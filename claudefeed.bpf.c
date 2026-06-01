/* The bpftool-generated vmlinux.h emits forward declarations the kernel
 * BTF dump can't fully resolve (e.g. `struct aes_enckey;`), which clang
 * flags under -Wall. Harmless — silence them for this header alone,
 * leaving -Wall live for the program code below.
 */
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wmissing-declarations"
#include "vmlinux.h"
#pragma clang diagnostic pop
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>

/* claudefeed — the kernel-side audit stream for a matched session.
 *
 * Where claudetree paints a live *tree* of who is running, claudefeed
 * is the scrolling *log* of what they did: every command exec'd, every
 * file opened, every TCP port reached or bound — for the matched
 * session and everything beneath it, and nothing else.
 *
 * The trick to "and nothing else" is a kernel-side membership set. A
 * `tracked` hash map holds the tgid of every process that belongs to a
 * session; the file/network probes are no-ops for any pid not in it, so
 * the firehose of system-wide opens never reaches userspace. The set
 * stays current from three directions:
 *
 *   - JS seeds it at startup: one sysgraph query finds the live session
 *     processes and all their descendants, written in via the map API.
 *   - exec self-propagates it: when a tracked process exec's a child,
 *     the child inherits membership; a *fresh* session is caught by
 *     matching the program's basename against the configured `needle`.
 *   - exit prunes it: the thread-group leader leaving drops its tgid.
 *
 * Probes:
 *   syscalls/sys_enter_execve → full argv → EXEC (and join the set)
 *   sched/sched_process_exit  → lifetime + status → EXIT (and leave)
 *   syscalls/sys_enter_openat → opened path + flags → OPEN
 *   kprobe/tcp_connect        → outbound peer addr:port → CONNECT
 *   kprobe/inet_listen        → bound addr:port → LISTEN
 *
 * A `start` hash map keyed by tgid bridges exec→exit so EXIT can report
 * how long the process lived; processes already alive at attach simply
 * have no stamp and report an unknown (0) lifetime. */

char LICENSE[] SEC("license") = "GPL";

#define EVT_EXEC    0
#define EVT_EXIT    1
#define EVT_OPEN    2
#define EVT_CONNECT 3
#define EVT_LISTEN  4

#ifndef BPF_ANY
#define BPF_ANY 0
#endif

#ifndef AF_INET
#define AF_INET  2
#endif
#ifndef AF_INET6
#define AF_INET6 10
#endif

/* argv packing. CMDLINE_LEN is the joined-command budget; ARGSIZE caps a
 * single argument. ARGS_CEIL leaves room for one more full ARGSIZE read,
 * which is the bound the verifier needs to prove the copy stays in the
 * buffer (see read_cmdline). */
#define ARGSIZE     256
#define CMDLINE_LEN 512
#define ARGS_CEIL   (CMDLINE_LEN - ARGSIZE)
#define MAX_ARGS    40

/* Basename match window for catching a fresh session at exec. */
#define BASE_LEN    64
#define NEEDLE_LEN  16

struct event {
    __u32 kind;          /* EVT_* */
    __u32 pid;           /* tgid — the user-visible PID */
    __u32 ppid;          /* parent's tgid */
    __u32 exit_code;     /* EXIT: exit(2) status */
    __u32 sig;           /* EXIT: terminating signal, 0 if none */
    __u64 duration_ns;   /* EXIT: 0 when the exec stamp wasn't seen */
    __u32 flags;         /* OPEN: open(2) flags */
    __u32 family;        /* CONNECT/LISTEN: AF_INET | AF_INET6 */
    __u32 port;          /* CONNECT: dest port; LISTEN: bound port (host) */
    __u8  addr[16];      /* CONNECT: dest addr; LISTEN: bound addr (raw) */
    char  comm[16];
    char  filename[256]; /* EXEC: program path; OPEN: opened path */
    char  cmdline[CMDLINE_LEN]; /* EXEC: space-joined argv */
};

/* clang can drop BTF for a struct only reached through the local pointer
 * that `bpf_ringbuf_reserve` hands back. Anchor it in a __used global so
 * the type survives — yeet's ringbuf bind resolves it via `btf_struct`. */
__attribute__((used)) static const struct event __event_anchor;

/* The match needle, lowercased, patched in by JS from `match=`. Kept in
 * .data (mutable globals, not `const`) so the data-section service can
 * write it at runtime. */
char needle[NEEDLE_LEN] = "claude";
__u32 needle_len = 6;

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16384);
    __type(key, __u32);   /* tgid */
    __type(value, __u8);  /* membership marker */
} tracked SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16384);
    __type(key, __u32);   /* tgid */
    __type(value, __u64); /* exec timestamp (ns) */
} start SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 18);
} events SEC(".maps");

static __always_inline int is_tracked(__u32 tgid)
{
    return bpf_map_lookup_elem(&tracked, &tgid) != NULL;
}

static __always_inline void track(__u32 tgid)
{
    __u8 one = 1;
    bpf_map_update_elem(&tracked, &tgid, &one, BPF_ANY);
}

static __always_inline char to_lower(char c)
{
    return (c >= 'A' && c <= 'Z') ? c + 32 : c;
}

/* Does the basename of the just-exec'd program path begin with the needle?
 * This is the only way a brand-new session (one whose parent isn't already
 * tracked) joins the set, so it runs on every exec — and so it has to stay
 * cheap: a full substring search over the path blows the verifier's state
 * budget. Reading the basename and prefix-comparing it case-insensitively
 * is one bounded pass, and catches the program-name match we actually want
 * (`claude`, `node`, …) rather than an incidental hit deep in a path. */
static __always_inline int name_matches(const char *path)
{
    char base[BASE_LEN];
    long n = bpf_probe_read_user_str(&base, sizeof(base), path);
    if (n <= 0)
        return 0;

    int start = 0;
    for (int i = 0; i < BASE_LEN; i++) {
        if (i >= n)
            break;
        if (base[i] == '/')
            start = i + 1;
    }

    __u32 nl = needle_len;
    if (nl == 0 || nl > NEEDLE_LEN)
        return 0;

    for (int j = 0; j < NEEDLE_LEN; j++) {
        if ((__u32)j >= nl)
            break;
        char want = needle[j & (NEEDLE_LEN - 1)];
        if (to_lower(base[(start + j) & (BASE_LEN - 1)]) != want)
            return 0;
    }
    return 1;
}

/* Walk argv, copying each argument into e->cmdline and turning the NUL
 * that bpf_probe_read_user_str writes after each one into a space, so
 * the result is a single readable command line (a `char[]` field is
 * lifted to a JS string that stops at the first NUL — embedded NULs
 * would otherwise hide everything past argv[0]). The `sz > ARGS_CEIL`
 * guard is what proves to the verifier that `&e->cmdline[sz]` plus a
 * full ARGSIZE read stays inside the buffer. */
static __always_inline void read_cmdline(struct event *e, const char *const *argv)
{
    unsigned int sz = 0;
#pragma unroll
    for (int i = 0; i < MAX_ARGS; i++) {
        const char *argp = NULL;
        bpf_probe_read_user(&argp, sizeof(argp), &argv[i]);
        if (!argp)
            break;
        if (sz > ARGS_CEIL)
            break;
        long ret = bpf_probe_read_user_str(&e->cmdline[sz], ARGSIZE, argp);
        if (ret <= 0)
            break;
        sz += (unsigned int)ret;
        e->cmdline[(sz - 1) & (CMDLINE_LEN - 1)] = ' ';
    }
    e->cmdline[(sz ? sz - 1 : 0) & (CMDLINE_LEN - 1)] = '\0';
}

static __always_inline __u32 parent_tgid(void)
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    return BPF_CORE_READ(task, real_parent, tgid);
}

SEC("tp/syscalls/sys_enter_execve")
int handle_execve(struct trace_event_raw_sys_enter *ctx)
{
    __u32 tgid = bpf_get_current_pid_tgid() >> 32;
    const char *filename = (const char *)ctx->args[0];
    const char *const *argv = (const char *const *)ctx->args[1];
    __u32 ppid = parent_tgid();

    /* Membership: descend from a tracked process, re-exec of one already
     * tracked, or a fresh session whose program name matches the needle. */
    if (!is_tracked(ppid) && !is_tracked(tgid) && !name_matches(filename))
        return 0;

    __u64 ts = bpf_ktime_get_ns();
    bpf_map_update_elem(&start, &tgid, &ts, BPF_ANY);
    track(tgid);

    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    e->kind = EVT_EXEC;
    e->pid = tgid;
    e->ppid = ppid;
    e->exit_code = 0;
    e->sig = 0;
    e->duration_ns = 0;
    e->flags = 0;
    e->family = 0;
    e->port = 0;
    __builtin_memset(e->addr, 0, sizeof(e->addr));

    /* comm here is still the caller's program — the new image's name is
     * the basename of `filename`, which JS derives. */
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    bpf_probe_read_user_str(&e->filename, sizeof(e->filename), filename);
    read_cmdline(e, argv);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tp/sched/sched_process_exit")
int handle_exit(struct trace_event_raw_sched_process_template *ctx)
{
    __u64 id = bpf_get_current_pid_tgid();
    __u32 tgid = id >> 32;
    __u32 pid = (__u32)id;

    /* Threads exit too; only the group leader is a real process exit. */
    if (pid != tgid)
        return 0;
    if (!is_tracked(tgid))
        return 0;

    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        goto cleanup;

    e->kind = EVT_EXIT;
    e->pid = tgid;
    e->ppid = parent_tgid();
    e->flags = 0;
    e->family = 0;
    e->port = 0;
    e->filename[0] = '\0';
    e->cmdline[0] = '\0';
    __builtin_memset(e->addr, 0, sizeof(e->addr));

    /* task->exit_code packs the wait(2) status: high byte is the exit()
     * code, low 7 bits are the signal that killed it (0 for a clean exit). */
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    int code = BPF_CORE_READ(task, exit_code);
    e->exit_code = (code >> 8) & 0xff;
    e->sig = code & 0x7f;

    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    __u64 *tsp = bpf_map_lookup_elem(&start, &tgid);
    e->duration_ns = tsp ? bpf_ktime_get_ns() - *tsp : 0;

    bpf_ringbuf_submit(e, 0);

cleanup:
    bpf_map_delete_elem(&start, &tgid);
    bpf_map_delete_elem(&tracked, &tgid);
    return 0;
}

SEC("tp/syscalls/sys_enter_openat")
int handle_openat(struct trace_event_raw_sys_enter *ctx)
{
    __u32 tgid = bpf_get_current_pid_tgid() >> 32;
    if (!is_tracked(tgid))
        return 0;

    const char *filename = (const char *)ctx->args[1];

    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    e->kind = EVT_OPEN;
    e->pid = tgid;
    e->ppid = 0;
    e->exit_code = 0;
    e->sig = 0;
    e->duration_ns = 0;
    e->flags = (__u32)ctx->args[2];
    e->family = 0;
    e->port = 0;
    e->cmdline[0] = '\0';
    __builtin_memset(e->addr, 0, sizeof(e->addr));

    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    bpf_probe_read_user_str(&e->filename, sizeof(e->filename), filename);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* Fill the common scalar fields for a network event, leaving addr/port/
 * family to the caller. */
static __always_inline struct event *net_event(__u32 kind, __u32 tgid)
{
    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return NULL;
    e->kind = kind;
    e->pid = tgid;
    e->ppid = 0;
    e->exit_code = 0;
    e->sig = 0;
    e->duration_ns = 0;
    e->flags = 0;
    e->filename[0] = '\0';
    e->cmdline[0] = '\0';
    __builtin_memset(e->addr, 0, sizeof(e->addr));
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    return e;
}

SEC("kprobe/tcp_connect")
int BPF_KPROBE(handle_tcp_connect, struct sock *sk)
{
    __u32 tgid = bpf_get_current_pid_tgid() >> 32;
    if (!is_tracked(tgid))
        return 0;

    struct event *e = net_event(EVT_CONNECT, tgid);
    if (!e)
        return 0;

    __u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);
    e->family = family;
    e->port = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));

    if (family == AF_INET) {
        __u32 d = BPF_CORE_READ(sk, __sk_common.skc_daddr);
        __builtin_memcpy(e->addr, &d, sizeof(d));
    } else if (family == AF_INET6) {
        BPF_CORE_READ_INTO(&e->addr, sk,
                           __sk_common.skc_v6_daddr.in6_u.u6_addr8);
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("kprobe/inet_listen")
int BPF_KPROBE(handle_inet_listen, struct socket *sock, int backlog)
{
    __u32 tgid = bpf_get_current_pid_tgid() >> 32;
    if (!is_tracked(tgid))
        return 0;

    struct sock *sk = BPF_CORE_READ(sock, sk);

    struct event *e = net_event(EVT_LISTEN, tgid);
    if (!e)
        return 0;

    __u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);
    e->family = family;
    /* skc_num is the bound local port, already in host byte order. */
    e->port = BPF_CORE_READ(sk, __sk_common.skc_num);

    if (family == AF_INET) {
        __u32 a = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
        __builtin_memcpy(e->addr, &a, sizeof(a));
    } else if (family == AF_INET6) {
        BPF_CORE_READ_INTO(&e->addr, sk,
                           __sk_common.skc_v6_rcv_saddr.in6_u.u6_addr8);
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}
