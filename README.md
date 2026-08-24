<!-- yeet:user-friendly-title: Inspect all agent actions -->

# `claudefeed`

> **`tail -f` for a coding agent.** What it ran, what it opened, what it dialed. From the kernel, not from its own log.

<p align="center">
  <a href="#requirements"><img src="https://img.shields.io/badge/platform-Linux-1793D1" alt="Linux: kernel with BTF, tracepoints and kprobes"></a>
  <a href="https://yeet.cx/docs/?utm_source=github&utm_medium=readme&utm_campaign=claudefeed&utm_content=badge"><img src="https://img.shields.io/badge/built%20with-yeet%20%2B%20eBPF-8A2BE2" alt="Built with yeet, a JS runtime for eBPF"></a>
  <a href="#what-you-cant-see"><img src="https://img.shields.io/badge/audit-observe%20only-D97706" alt="Observes and records; does not block"></a>
  <a href="#license"><img src="https://img.shields.io/badge/license-GPL--2.0-3DA639" alt="GPL-2.0"></a>
  <a href="https://discord.gg/JxVseaAVAU"><img src="https://img.shields.io/badge/chat-Discord-5865F2" alt="Discord"></a>
</p>

<p align="center">
  <img src="assets/claudefeed.gif" width="820" alt="claudefeed streaming exec, open, conn and listen events from a live Claude Code session">
</p>

**`claudefeed` is an eBPF agent audit feed for Linux: it streams every command, file open and TCP connection a coding-agent session makes, scoped to that session's process subtree.**

## Quick start

```sh
curl -fsSL https://yeet.cx | sh          # install yeet, once
yeet run github:yeet-src/claudefeed      # clone, build and run in one step
```

With an agent session running anywhere on the box, that is all of it. `claudefeed` finds the live `claude` processes, seeds its tracked set, and starts streaming.

The incumbents each solve a slice and miss the rest. `strace -f` needs a PID you name up front, and a session is a moving tree: the agent spawns a shell, the shell spawns `git`, `git` spawns `ssh`. Auditd catches the tree but hands you a system-wide log to filter afterwards. The agent's own transcript tells you what it believed it did, which is the one account you cannot check the others against. `claudefeed` filters in the kernel and scopes to the subtree, so what reaches your terminal is that session and nothing else.

> [!TIP]
> The filtering happens before userspace exists. A `tracked` hash map of session tgids gates the file and network probes, so a system-wide firehose of `openat` never crosses the kernel boundary. The set self-propagates across `exec`, which is how a `git` three levels deep in the tree stays in scope without being named.

## Contents

**Run it** — [Get started](#get-started) · [Have an agent set it up](#have-an-agent-set-it-up) · [Reading it without a TTY](#reading-it-without-a-tty)

**Understand it** — [A 60-second primer](#a-60-second-primer-on-the-tracked-set) · [Questions this tool answers](#questions-this-tool-answers) · [What you're looking at](#what-youre-looking-at) · [How it works](#how-it-works) · [Alerting](#alerting) · [What you can't see](#what-you-cant-see)

**Reference** — [Requirements](#requirements) · [FAQ](#faq) · [License](#license)

**Contribute** — [Building from source](#building-from-source) · [Testing across kernels](#testing-across-kernels)

## Get started

```sh
curl -fsSL https://yeet.cx | sh
make                                     # dumps vmlinux.h via bpftool, builds claudefeed.bpf.o
yeet run .                               # stream every class from every live `claude` session
```
[Manual install guide](https://yeet.cx/docs/install/manual-installation?utm_source=github&utm_medium=readme&utm_campaign=claudefeed) | Linux only

With no flags, `claudefeed` matches sessions whose program basename starts with `claude`, seeds the tracked set from the live process tree, and streams all five event classes until `Ctrl-C`. Flags go after `--` so the runtime routes them to the script rather than consuming them itself; getting that wrong is the most common first-run mistake.

| flag | default | meaning |
| --- | --- | --- |
| `--match=<name>` | `claude` | Session program-name needle, tested against the exec'd basename as a case-insensitive prefix. Never matched against the full command line, so a process that merely mentions `claude` in an argument cannot masquerade as a session. Truncated to 15 characters before it reaches the kernel. |
| `--secs=<n>` | `0` | Run for N seconds then exit. `0` runs until `Ctrl-C`. A bounded run is what makes this scriptable from CI or an agent. |
| `--only=<classes>` | all | Show only these classes from `exec,exit,open,conn,listen`. Filtering happens in JS, so the events are still captured and the kernel cost is unchanged. |
| `--except=<classes>` | none | Drop these classes. `--except=open` is the one worth knowing: file opens are by far the noisiest class, and dropping them leaves a readable command-and-network narrative. |

```sh
yeet run . -- --except=open --secs=30    # commands and network only, bounded 30s run
yeet run . -- --only=exec,conn           # just what ran and what it dialed
yeet run . -- --match=node               # audit node sessions instead
```

The feed is append-only, one line per event, newest at the bottom. There is no full-screen repaint, so unlike most terminal tools it is safe to pipe or redirect: colors come from yeet's `style` global and no-op to plain text off a TTY, which makes a piped run a clean grep-able log.

## Have an agent set it up

Paste this to a coding agent on the target Linux box.

```
Set up and verify github:yeet-src/claudefeed on this machine.

1. Clone it, or `git pull` if it is already present.
2. Install yeet if it is missing: `curl -fsSL https://yeet.cx | sh`
3. Run `make`. It shells out to `bpftool` to dump the running kernel's BTF into
   include/vmlinux.h, then compiles claudefeed.bpf.o with clang. The bpftool step
   needs privileges; the Makefile already prefixes it with sudo.
4. Start a traffic source so the feed has something to show. In a second terminal:
   `bash -c 'while true; do uname -a; curl -s -m 3 http://example.com >/dev/null; sleep 2; done'`
   Then run claudefeed matched against that shell rather than a real agent:
   `yeet run . -- --match=bash --secs=20`
5. Confirm exec, conn and exit lines appear for the loop. If the feed prints its
   header and then stays empty, the tracked set seeded zero processes: check that
   the --match needle matches a live program's basename.

"It compiled" is not the same as "it works". The header line prints before any
event is captured, so an empty feed and a broken feed look identical. Do not
report success until you have seen event lines scroll.

Report the header line, the first few event lines, and the kernel version
(`uname -r`).
```

Prefer to drive it yourself? [Get started](#get-started) is three lines.

## A 60-second primer on the `tracked` set

The hard part of auditing a session is not capturing events. It is capturing *only* that session's events while its process tree grows and shrinks underneath you.

`claudefeed` keeps a `tracked` hash map of session tgids in the kernel. The file and network probes look up the current tgid and return immediately if it is absent, so a non-session `openat` costs one hash lookup and never becomes a ring-buffer write. The set stays current from three directions.

**JS seeds it.** One `yeet.graph` query at startup walks the live process table, finds every process whose command name matches the needle, then BFS's down the child links to collect all descendants. The whole set lands in the kernel in a single `updateBatch` syscall, with a per-key fallback for kernels lacking `BPF_MAP_*_BATCH`. This is what captures activity from processes that were already running when you attached.

**`exec` self-propagates it.** When a tracked process exec's a child, the child inherits membership. A *fresh* session, one whose parent is not tracked, is caught by comparing the exec'd program's basename against a needle that JS patches into the program's `.data` section at runtime. The same needle drives both the JS seed and the kernel-side catch, so the two halves always agree on what counts as a session.

**`exit` prunes it.** The thread-group leader leaving drops its tgid from both maps. A separate `start` map keyed by tgid bridges `exec` to `exit`, which is how the exit line reports a lifetime.

That last mechanism is also the primer's honest ending: a process that was already alive when you attached has no `start` stamp, so its exit line reports an unknown lifetime rather than a wrong one.

## Questions this tool answers

**I am rolling out coding agents to a team and someone is going to ask me what they can actually do on a dev box. How do I answer that with evidence instead of a policy document?**
Run `claudefeed` against a real session and read the feed. You get every `execve` with full argv, every `openat` with its access mode, and every outbound TCP peer, for the agent and every process it spawns. That is a ground-truth inventory of the reach an agent actually exercises, which is a much better input to a policy conversation than an assumption about it. When you want the boundary enforced rather than recorded, [`agent-lock`](https://github.com/yeet-src/agent-lock) is the sibling that returns `-EPERM`.

**How do I check what an agent did on a server where I cannot install a monitoring stack or run Docker?**
One `curl` to install yeet, then `yeet run github:yeet-src/claudefeed`. There is no image to pull, no sidecar, no collector to point somewhere, and no daemon to leave behind if you do not want one. This is the case the terminal form is for: you are already SSH'd into the box and you want to know what happened on it in the next thirty seconds.

**An unattended agent run finished and I want to know what commands it actually executed, in order. Where does that come from?**
The `exec` class, which carries the resolved program path plus the space-joined argv, timestamped to the millisecond. Because membership propagates across `exec`, the shell the agent spawned and the `git` that shell spawned are all in the same feed, in the order the kernel saw them. See [What you're looking at](#what-youre-looking-at).

**Can I get a tripwire for an agent touching something it should not, without building a whole detection pipeline?**
Yes, and it is a branch in one callback. `ring.subscribe` in [`main.js`](main.js) already holds every decoded record, so a predicate on `EVT_CONNECT` matching an unexpected peer, or on `EVT_OPEN` touching `~/.ssh/id_*`, plus a `yeet.alert` call, is the whole implementation. See [Alerting](#alerting).

**Does this work for agents other than Claude Code?**
Any of them. `--match` is a program-name needle and nothing in the kernel side knows what an agent is. `--match=node`, `--match=python`, `--match=codex`, `--match=bash`: anything that exec's under a recognizable name is audited the same way. The name is a runtime knob patched into `.data`, not a compiled-in assumption.

**How do I get this into a log file or a shipper rather than watching it scroll?**
Pipe it. The feed is append-only rather than a repainting TUI, and the color helpers no-op off a TTY, so `yeet run . -- --secs=60 > session.log` is a plain-text audit record. For structured output, see [Reading it without a TTY](#reading-it-without-a-tty), which is also the honest boundary: there is no `--json` mode today.

**Is this a replacement for auditd, Falco, or an EDR agent?**
No. `claudefeed` is a single-host, single-session, run-it-when-you-want-it audit feed. It has no retention, no query language, no rule engine, no fleet aggregation and no persistence: close the terminal and the record is whatever you piped to a file. auditd and Falco are the right answer when you need durable, system-wide, policy-driven capture that survives reboots and feeds a SIEM. Reach for `claudefeed` when you want to see one agent session's behavior right now, on one box, with nothing installed in advance.

**When should I use this instead of `strace`, auditd, or reading the agent's own transcript?**
Use **`strace -f`** when you want syscall arguments and return values for a process you can name up front and you do not mind the ptrace slowdown. Use **auditd** when you need durable system-wide capture with retention. Read **the transcript** when you want to know what the agent intended. Reach for `claudefeed` when the question is what an agent's whole moving process tree actually did, right now, with no PID to name and no filtering pass afterwards. And when you want the live shape of the tree rather than a log of its actions, [`claudetree`](https://github.com/yeet-src/claudetree) renders that as a process tree.

## What you're looking at

```
claudefeed — auditing "claude" sessions · seeded 9 processes from 288 live · streaming exec/exit/open/conn/listen …
16:11:22.023  3003897  exit    sleep exit 0
16:11:22.023  3003924  exec    uname · /usr/bin/uname -a
16:11:22.024  3003924  exit    uname exit 0 after 1ms
16:11:22.024  3003925  exec    curl · curl -s -m 3 http://example.com
16:11:22.031  3003925  open    curl (r) /etc/ssl/certs/ca-certificates.crt
16:11:22.033  3003925  conn    curl → 104.20.23.154:80
16:11:22.053  3003925  exit    curl exit 0 after 29ms
```

The header line prints once at startup and tells you whether the seed worked: how many processes matched, out of how many live on the box, and which classes are streaming. A seed of zero is the signal that your `--match` needle found nothing.

Every line after it is one event, `time · pid · class · detail`. The pid and that process's program name share a stable color derived from a hash of the pid, so a burst of activity reads as one actor and re-exec of the same pid keeps its hue. Inside a command line, flags are muted and path-ish tokens are tinted, so a `bash -c '…'` pipeline stays legible.

| class | source | detail |
| --- | --- | --- |
| `exec` | `tp/syscalls/sys_enter_execve` | The new program's basename, then the full space-joined argv. Captured at syscall entry, so it is what was *requested*, whether or not the exec succeeded. |
| `exit` | `tp/sched/sched_process_exit` | `exit N`, or `killed sig N` when a signal ended it, plus how long the process lived. The lifetime is absent for processes that were already running when you attached. |
| `open` | `tp/syscalls/sys_enter_openat` | Access mode in parentheses (`r`, `w`, `rw`, with `+` when the open could create the file), then the path. The noisiest class by a wide margin. |
| `conn` | `kprobe/tcp_connect` | `→ addr:port` for an outbound TCP connection, IPv4 or IPv6. Fires on connect initiation, not on a completed handshake. |
| `listen` | `kprobe/inet_listen` | The bound `addr:port`. This is how an MCP server or a dev server the session started shows up. |

Colors come from yeet's `style` global (the standard 16-color palette, no truecolor), which no-ops to plain text when stdout is not a TTY.

## Reading it without a TTY

The feed is already the non-TTY path, which is unusual for a terminal tool and is a consequence of it being append-only rather than a repainting TUI. Two things follow.

**Piping works and produces plain text.** `yeet run . -- --secs=60 > session.log` gives you a timestamped, grep-able audit record with no escape codes in it. This is also what an agent should run to verify the tool works: a bounded `--secs` run exits on its own rather than needing a signal.

**There is no structured output mode today.** No `--json`, no NDJSON, no export sink. If you need one, `ring.subscribe` in [`main.js`](main.js) is the single place to add it: the callback already receives every field decoded, so emitting `JSON.stringify` per record instead of a formatted line is a few lines in the same shape as the [Alerting](#alerting) example. For a managed export pipeline into a SIEM or an object store, [contact us](https://yeet.cx/?utm_source=github&utm_medium=readme&utm_campaign=claudefeed&utm_content=without-tty).

## How it works

The kernel side is one BPF object, [`claudefeed.bpf.c`](claudefeed.bpf.c). The JS side is four modules with a deliberate split: only [`main.js`](main.js) touches the BPF API, [`model.js`](model.js) is pure decoding and seeding, and [`feed.js`](feed.js) is pure presentation.

```
claudefeed.bpf.c   five programs, three maps, the tracked-set logic
main.js            bind and start, patch the needle, seed tracked, stream the ring
config.js          yeet.args → constants (match, secs, only/except, event kinds)
model.js           sysgraph seed via BFS, plus record decoding (cstr, fmtAddr, fmtOpenMode)
feed.js            one decoded record → one colored audit line
```

### The BPF side

One object attaches three tracepoints and two kprobes, auto-attached on `start()` by their `SEC()` names.

| program | hook | what it captures |
| --- | --- | --- |
| `handle_execve` | `tp/syscalls/sys_enter_execve` | Program path and full argv. Also the membership gate: joins the set on a needle match, propagates it to children. |
| `handle_exit` | `tp/sched/sched_process_exit` | Exit code and terminating signal, unpacked from `task->exit_code`, plus lifetime. Prunes the tgid. |
| `handle_openat` | `tp/syscalls/sys_enter_openat` | The opened path and the raw `open(2)` flag word. |
| `handle_tcp_connect` | `kprobe/tcp_connect` | Destination address and port, read from `sk->__sk_common` via CO-RE. |
| `handle_inet_listen` | `kprobe/inet_listen` | Bound address and port. `skc_num` is already host byte order; `skc_dport` on the connect side is not, hence the `bpf_ntohs`. |

Three maps connect the two sides:

- **`tracked`** — `BPF_MAP_TYPE_HASH`, tgid to a one-byte marker, 16384 entries. Seeded from JS, maintained by the kernel thereafter. This is the gate every file and network probe checks first.
- **`start`** — `BPF_MAP_TYPE_HASH`, tgid to an exec timestamp. Bridges `exec` to `exit` so the exit line can report a lifetime.
- **`events`** — `BPF_MAP_TYPE_RINGBUF`, 256 KB, bound by its `btf_struct` name (`event`) rather than by field offsets.

Two `.data` globals, `needle` and `needle_len`, are patched from JS at startup through yeet's `DataSec` binding. They are deliberately non-`const` so the data section stays writable at runtime.

<details>
<summary>Three constraints the verifier imposed, and what they cost</summary>

**The basename match is a prefix compare, not a substring search.** `name_matches()` runs on *every* `execve` system-wide, since that is the only way a session whose parent is not yet tracked can join the set. A full substring search over a 256-byte path blows the verifier's state budget. Reading the basename into a 64-byte buffer and prefix-comparing case-insensitively is one bounded pass. It is also the better semantic: it matches the program name rather than an incidental hit deep in a path, which is what stops `/home/claude/project/bin/tool` from registering as a session.

**Every index into a fixed buffer is masked.** `base[(start + j) & (BASE_LEN - 1)]` and `needle[j & (NEEDLE_LEN - 1)]` are not defensive style, they are what proves in-bounds access to the verifier when the index is computed rather than constant. Both buffer sizes are powers of two so the mask is exact.

**argv packing needs a headroom bound.** `read_cmdline()` copies up to 40 arguments into one 512-byte buffer, capping each at 256 bytes. The `sz > ARGS_CEIL` guard, where `ARGS_CEIL` is `CMDLINE_LEN - ARGSIZE`, is what proves that the next full-size read still lands inside the buffer. It also means the joined command line is truncated past roughly 512 bytes: a very long argv is cut off rather than dropped.

The NUL handling in that loop is worth knowing, because it is why argv is joined kernel-side rather than in JS. `bpf_probe_read_user_str` writes a terminating NUL after each argument. A `char[]` field is lifted to a JS string that stops at the first NUL, so leaving them in place would hide everything past `argv[0]`. Each NUL is overwritten with a space as the copy proceeds, and the last one is restored.

One more, not verifier-related: `struct event` is anchored in a `__used` global. clang can drop BTF for a struct only ever reached through the pointer `bpf_ringbuf_reserve` returns, and yeet's ringbuf binding resolves the type by name, so without the anchor the bind fails on a type that appears to not exist.

</details>

### The JS side

| file | responsibility |
| --- | --- |
| [`main.js`](main.js) | Bind the three maps, patch the needle into `.data`, seed `tracked`, subscribe to the ring, handle the `--secs` bound. |
| [`config.js`](config.js) | Parse `yeet.args` into constants. Folds bare `k=v` positionals back into the named set, so both `--match=x` and `match=x` work. |
| [`model.js`](model.js) | The sysgraph BFS that computes initial membership, plus the decoders: NUL-trimming `char[]`, collapsing IPv6 zero-runs, unpacking `open(2)` flags into an access mode. |
| [`feed.js`](feed.js) | Formatting only. The per-pid color hash, the fixed-width class badge, the shell-style command-line tinting. |

The division is the point: the kernel does membership and capture, JS does seeding, decoding and presentation. Nothing in `feed.js` knows a BPF map exists.

### Why tracepoints and kprobes, not a syscall wrapper

The membership trick has to run *inside* `exec` to propagate to children and *inside* `exit` to prune, at the moment the kernel performs them, for the whole tree at once, with no PID named on the command line. A wrapper or an `LD_PRELOAD` shim only sees processes it launched and is trivially escaped by a statically linked binary or a direct syscall. `ptrace` sees a tree but imposes a stop on every syscall for every traced process, which is the cost that makes `strace -f` unusable on a busy session.

Tracepoints and kprobes have neither problem. They fire on the kernel's own path with no process cooperation and no possibility of a process opting out, and the `tracked` lookup that gates them means the uninteresting 99% of system-wide `openat` traffic costs one hash lookup and stops there.

## Alerting

The same ring-buffer callback that prints each line can page you. yeet posts to Slack: log in at [yeet.cx/settings](https://yeet.cx/settings?utm_source=github&utm_medium=readme&utm_campaign=claudefeed), connect your workspace once, and `yeet.alert` can send to any channel it can reach.

The subscribe callback in [`main.js`](main.js) already holds every decoded record, so an alert is a branch inside it.

```js
// pull in the same decoders feed.js uses
import { cstr, fmtAddr } from "./model.js";

const WATCH = "yeet.cx"; // an IP, a port, or a command needle work too

const sub = await ring.subscribe(async (rec) => {
  const e = rec.event ?? rec;
  stats.events++;
  if (!SHOW.has(KIND_KEY[e.kind])) return;
  console.log(line(e, Date.now()));

  if (e.kind === EVT_CONNECT) {
    const peer = fmtAddr(e.family, e.addr, e.port);
    if (peer.includes(WATCH)) {
      await yeet.alert({
        method: "slack",
        channel: "#alerts",
        text: `claude (pid ${e.pid}) connected to ${peer}`,
        blocks: [
          { type: "header", text: { type: "plain_text", text: "Claude phoned home" } },
          {
            type: "section",
            fields: [
              { type: "mrkdwn", text: `*Process:*\n${cstr(e.comm)} (${e.pid})` },
              { type: "mrkdwn", text: `*Peer:*\n${peer}` },
            ],
          },
        ],
      });
    }
  }
});
```

The same shape fits any class: alert on an `EVT_EXEC` whose `cstr(e.cmdline)` matches `rm -rf` or `curl … | sh`, or an `EVT_OPEN` that touches `~/.ssh/id_*`. The callback already has the decoded record, so you add the predicate and the `yeet.alert` and nothing else.

## Requirements

> [!IMPORTANT]
> A Linux kernel with **BTF** (`CONFIG_DEBUG_INFO_BTF=y`). It is what supplies the tracepoint context structs, `task_struct` for the parent tgid and exit status, and the `sock`/`socket` layouts the two network kprobes read through CO-RE. Default on current Arch, Fedora, Ubuntu and Debian.
>
> Ring buffer support, which means **kernel 5.8 or newer**. The batched map seed uses `BPF_MAP_*_BATCH` (5.6+) and falls back to per-key writes without it.
>
> The yeet daemon handles the privileged BPF load, so `yeet run` is never prefixed with `sudo`. `curl -fsSL https://yeet.cx | sh` installs it.
>
> CO-RE means the object is compiled once and relocated against whatever kernel it lands on. No per-kernel recompile.

## What you can't see

> [!NOTE]
> `claudefeed` observes. It tells you what a session did; it does not stop, hold, or modify anything. For a boundary that actually refuses, [`agent-lock`](https://github.com/yeet-src/agent-lock) enforces one with a BPF LSM hook and returns `-EPERM`.

- **That a file was opened, not what was in it.** `open` events carry the path and the access mode. The bytes read or written are never captured, by design: recording payloads would mean copying file contents through a ring buffer, which is a different tool with a very different cost profile.
- **`openat` only.** The older `open(2)` syscall, `openat2`, and anything reaching a file through `mmap` or an already-open descriptor passed across a socket do not appear. Most modern userspace uses `openat`, so this bites rarely, but it is a real gap and a determined process can step around it.
- **Requested execs, not successful ones.** `exec` fires at syscall entry, so a command that fails to launch still produces a line. The following `exit` line is what disambiguates.
- **TCP only, and connect initiation rather than completion.** `kprobe/tcp_connect` fires when a connection is initiated; a peer that refuses or times out still shows a `conn` line. UDP and raw sockets are not hooked at all, so DNS over UDP is invisible. For general packet-level visibility, `tcpdump` and Wireshark remain the right tools, and [`container-traffic`](https://github.com/yeet-src/container-traffic) covers per-container flow accounting.
- **A tree, matched by name, that can be left.** A session that exec's a program which then double-forks and is reparented to init keeps its tgid and stays tracked, but a process that was never a descendant and does not match the needle is invisible. This is a scoping tool, not an escape-proof monitor.
- **Nothing durable.** No retention, no persistence, no aggregation across hosts. The record is what you piped to a file. For durable system-wide capture, auditd and Falco are built for it.
- **A bounded command line.** argv is truncated past roughly 512 bytes and 40 arguments. A very long command shows its head, not its tail.

## FAQ

**Why not just read the agent's own logs?**
Those tell you what the agent believed it did, which is the one account you cannot check the others against. `claudefeed` reads the kernel, so it records what actually crossed `execve`, `openat` and the TCP stack, including everything the shells and subprocesses did on their own initiative.

**Does it slow the session down?**
Not meaningfully. The probes are passive observers with no stop imposed on the traced process, unlike `ptrace`. The in-kernel `tracked` gate drops non-session events after one hash lookup, so the cost scales with the matched session's activity rather than with the box's total syscall volume.

**Will it catch a session I start *after* attaching?**
Yes. That is the kernel-side half of the membership trick: a fresh session is caught the moment it exec's a program whose basename matches the needle, whether or not its parent was ever tracked.

**Why did the feed print a header and then nothing?**
Almost always a needle that matched nothing. The header reports how many processes it seeded; if that number is zero and no fresh session exec's during the run, there is nothing to show. Check the program basename with `ps -eo comm` and pass `--match=` accordingly.

**Why does an `exit` line sometimes have no lifetime?**
Because that process was already running when you attached, so there is no `exec` timestamp in the `start` map to subtract from. Reporting nothing is deliberate; the alternative would be reporting a duration measured from the wrong origin.

## Building from source

```sh
make          # dump vmlinux.h via bpftool, compile claudefeed.bpf.o
make clean    # remove the object and the generated header
```

`make` does two things. It shells out to `bpftool btf dump file /sys/kernel/btf/vmlinux format c` to generate `include/vmlinux.h` from the running kernel, which is why that step needs privileges and why the Makefile prefixes `bpftool` with `sudo`. Then clang compiles the program for the BPF target with the architecture macro set from `uname -m`.

Both outputs are gitignored build artifacts: `include/vmlinux.h` is large and host-specific, and `*.o` is regenerated on every build. `yeet run` imports the compiled object directly from [`main.js`](main.js), so a stale object is a stale run; re-`make` after editing the C.

## Testing across kernels

A BPF program that loads on your laptop can be rejected by an older kernel's verifier. The instruction and state budgets have changed across releases, and the bounded loops in `name_matches()` and `read_cmdline()` are exactly the shape that a stricter verifier evaluates differently.

`veristat` is the tool for this: it loads the object and reports the verifier's instruction count and state count without running it, so a regression shows up as a number rather than as a bug report from someone on an older distro. Run it against a built object directly. It needs privileges to load, which is correct here and is not an exception to the no-`sudo`-on-`yeet-run` rule.

```sh
make
sudo veristat claudefeed.bpf.o
```

## License

GPL-2.0.

---

Built with [yeet](https://yeet.cx/docs/?utm_source=github&utm_medium=readme&utm_campaign=claudefeed&utm_content=footer), a JS runtime for writing eBPF programs on Linux machines. Join us on [discord](https://discord.gg/JxVseaAVAU).
