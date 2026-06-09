# `claudefeed`

> **`tail -f` for Claude Code.** Every command a session runs, every file it opens, every TCP port it reaches or binds — decoded and streamed live to your terminal. Scoped to that session's process subtree. No other PIDs, no noise.

<p align="center">
  <img src="https://img.shields.io/badge/platform-Linux-1793D1" alt="Linux">
  <img src="https://img.shields.io/badge/built%20with-yeet%20%2B%20eBPF-8A2BE2" alt="yeet + eBPF">
  <img src="https://img.shields.io/badge/license-GPL--2.0-3DA639" alt="GPL-2.0">
  <a href="https://discord.gg/dYZu9PjKB"><img src="https://img.shields.io/badge/chat-Discord-5865F2" alt="Discord"></a>
</p>

![claudefeed demo](assets/claudefeed.gif)

**`claudefeed` turns a Claude Code session into a live, decoded audit log: every `exec` (with full argv), every `openat`, and every outbound or bound TCP port — for the matched session and its entire subtree.**

Where its sibling [`claudetree`](https://github.com/yeet-src/claudetree) paints *who is running* as a live process tree, `claudefeed` is the companion that tree promised: the `tail -f` of *what they did*.

> [!TIP]
> **You can't just `strace` this.** A session is a moving tree of processes — Claude spawns a shell, the shell spawns `git`, `git` spawns `ssh`. A system-wide feed of every `openat` would be a firehose, and a per-PID trace misses every child. `claudefeed` filters **in the kernel**: a `tracked` set of session tgids gates the probes, the set self-propagates across `exec`, and the noise never crosses into userspace.

## Quick start

```sh
curl -fsSL https://yeet.cx | sh
yeet run github:yeet-src/claudefeed
```
<sub>[Manual install guide](https://yeet.cx/docs/installation) | Linux only</sub>

With a Claude Code session running anywhere on the box, that's it — `claudefeed` finds the live `claude` processes, seeds its tracked set, and starts streaming. Everything after `--` is passed to claudefeed:

| flag               | default  | meaning                                                          |
| ------------------ | -------- | ---------------------------------------------------------------- |
| `--match=<name>`   | `claude` | session program-name needle; matched against the exec'd basename (case-insensitive prefix) |
| `--secs=<n>`       | `0`      | run for N seconds, `0` = until Ctrl-C                            |
| `--only=<classes>`   | all      | show only these classes, e.g. `--only=exec,conn,listen`        |
| `--except=<classes>` | none     | drop these classes, e.g. `--except=open` (the noisiest)        |

```sh
yeet run github:yeet-src/claudefeed -- --except=open --secs=30   # commands + network only, 30s
yeet run github:yeet-src/claudefeed -- --only=exec,conn      # just "what ran" and "what it dialed"
yeet run github:yeet-src/claudefeed -- --match=node          # audit node sessions instead
```

## A 60-second primer on the `tracked` set

The hard part of auditing a session isn't capturing events — it's capturing *only* the session's events, as its process tree grows and shrinks. `claudefeed` keeps a `tracked` hash map of session tgids in the kernel; the file and network probes are no-ops for any pid not in it. The set stays current from three directions:

**1. JS seeds it.** One `yeet.graph` query at startup finds the live session processes and all their descendants and writes the tgids into `tracked` in a single `updateBatch` syscall — so activity from processes already running when you attach is captured too.

**2. `exec` self-propagates it.** When a tracked process exec's a child, the child inherits membership. A *fresh* session — one whose parent isn't tracked — is caught by matching the exec'd program's basename against a needle the JS side patches into the program's `.data` section at runtime. The same needle drives both the seed and the kernel-side catch, so the two always agree on what counts.

**3. `exit` prunes it.** The thread-group leader leaving drops its tgid. A separate `start` map keyed by tgid bridges `exec`→`exit`, so the `exit` line can report how long the process lived (processes already alive at attach have no stamp and report an unknown lifetime).

Because `match` is tested against the program **basename** only — never the whole command line — a process that merely mentions `claude` in a path or argument doesn't masquerade as a session.

## Common use cases

`claudefeed` is for anyone running Claude Code (or any agent) with real autonomy and wanting a ground-truth record of what it actually did — not what it said it did.

- An autonomous agent run finished. What commands did it actually execute, and in what order?
- A session reached out to a host or opened a file it had no business touching. Catch it on the wire.
- A long unattended run needs a tripwire — get paged the moment it does something notable (see [Alerting](#alerting)).
- You want a clean, grep-able, archivable log of a session for forensics or review.

## What you're looking at

```
claudefeed — auditing "claude" sessions · seeded 9 processes from 288 live · streaming exec/exit/open/conn/listen …
16:11:22.023  3003897  exit    sleep exit 0
16:11:22.023  3003924  exec    uname · /usr/bin/uname -a
16:11:22.024  3003924  exit    uname exit 0 after 1ms
16:11:22.024  3003925  exec    curl · curl -s -m 3 http://example.com
16:11:22.033  3003925  conn    curl → 104.20.23.154:80
16:11:22.053  3003925  exit    curl exit 0 after 29ms
```

Each line is `time · pid · class · detail`. The **pid and that process's program name** share a stable per-process color, so a burst of activity reads as one actor; re-exec of the same pid keeps its color. Within a command line and an opened path, **flags are muted and paths are cyan**, so a `bash -c '…'` pipeline is legible at a glance. The class is a color-keyed badge:

| class    | source                     | detail                                |
| -------- | -------------------------- | ------------------------------------- |
| `exec`   | `sys_enter_execve`         | program name + full command line      |
| `exit`   | `sched/sched_process_exit` | `exit N` / `killed sig N`, + lifetime |
| `open`   | `sys_enter_openat`         | `(mode)` + path                       |
| `conn`   | `kprobe/tcp_connect`       | `→ addr:port` (outbound)              |
| `listen` | `kprobe/inet_listen`       | bound `addr:port`                     |

Colors come from yeet's `style` global (standard 16-color palette, no truecolor), which no-ops to plain text when stdout isn't a TTY — so a piped run is a clean plain-text log you can grep or archive.

## How it works

The core is in [`claudefeed.bpf.c`](claudefeed.bpf.c) and [`main.js`](main.js).

### The BPF side

One BPF object attaches three tracepoints and two kprobes, auto-attached on `start()` by their `SEC()` names:

| Program | Hook | What it does |
|---|---|---|
| `exec`   | `tp/syscalls/sys_enter_execve` | Emit the program + full argv; catch fresh sessions by basename, propagate membership to children. |
| `exit`   | `tp/sched/sched_process_exit`  | Emit exit status + lifetime; prune the leaving tgid from `tracked`. |
| `open`   | `tp/syscalls/sys_enter_openat` | Emit `(mode)` + path — only for tracked pids. |
| `conn`   | `kprobe/tcp_connect`           | Emit the outbound `addr:port`. |
| `listen` | `kprobe/inet_listen`           | Emit the bound `addr:port`. |

Three maps connect kernel to userspace:

- `tracked` — `HASH` of session tgids. Seeded from JS, maintained by the kernel thereafter; gates every file/network probe.
- `start` — `HASH` keyed by tgid, bridging `exec`→`exit` so the exit line can report a lifetime.
- `events` — `RINGBUF` bound by its `btf_struct` (`event`), one decoded record per event.

### The JS side

| file | responsibility |
|---|---|
| `main.js`   | wiring: bind/start, patch the needle, seed `tracked`, stream the ring |
| `config.js` | `yeet.args` → constants (`match`, `secs`, `only`/`except`, event kinds) |
| `model.js`  | seed the session subtree from the sysgraph; decode record fields |
| `feed.js`   | format one record into a colored audit line |

`RingBuf.subscribe` streams each record back as a decoded object: a `char[]` field arrives as a JS string and an `__u8[N]` field (the raw address) as a byte object, so argv is space-joined kernel-side into one `char[]` while addresses stay binary-clean.

### Why tracepoints and kprobes, not a syscall wrapper

The membership trick needs to fire *inside* `exec` (to propagate to children) and *inside* `exit` (to prune), at the moment the kernel does them — for the whole tree at once, with no PID named on the command line. Tracepoints and kprobes give exactly that, and the in-kernel `tracked` gate means the firehose never reaches userspace.

## Alerting

The feed is local — but the same ring-buffer callback that prints each line can also *page you*. yeet posts to Slack: log in at [yeet.cx/settings](https://yeet.cx/settings), connect your workspace once, and `yeet.alert` can then send to any channel it can reach.

The subscribe callback in `main.js` already holds every decoded record, so an alert is just a branch inside it. To know the moment a Claude session dials out to a host it has no business touching:

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

The same shape fits any class: alert on an `EVT_EXEC` whose `cstr(e.cmdline)` matches `rm -rf` or `curl … | sh`, or an `EVT_OPEN` that touches `~/.ssh/id_*`. The callback already has the decoded record in hand — you only add the predicate and the `yeet.alert`.

## Requirements

> [!IMPORTANT]
> A Linux kernel with **BTF** — needed for the tracepoint context structs, `task_struct`, and the `sock`/`socket` structs the network kprobes read. Default on current Arch, Fedora, Ubuntu, and Debian.
>
> The yeet daemon, which handles the privileged BPF load. `curl -fsSL https://yeet.cx | sh` installs it.

## Community questions

**Why not just read Claude's own logs?**
Those tell you what Claude *thinks* it did. `claudefeed` reads the kernel, so it records what actually crossed `execve`, `openat`, and the TCP stack — including everything the spawned shells, `git`, and subprocesses did on their own.

**Does it slow the session down?**
No meaningful overhead. The probes are passive observers and the in-kernel `tracked` gate drops non-session events before they ever cost a ring-buffer write.

**Will it catch a session I start *after* attaching?**
Yes. A fresh session is caught the moment it exec's a program whose basename matches the needle — that's the kernel-side half of the membership trick.

**Does it only work for Claude?**
No. `--match` is just a program-name needle. `--match=node`, `--match=python`, `--match=bash` — anything that exec's under a recognizable name works the same way.

## Building from source

```sh
make          # dumps vmlinux.h via bpftool, builds claudefeed.bpf.o
```

Needs `clang` (BPF target) and `bpftool`, plus a kernel with BTF. The generated `include/vmlinux.h` and `*.bpf.o` are build artifacts.

> If your kernel's BTF is newer than the bundled libbpf headers, clang may flag a conflicting `bpf_stream_vprintk` declaration. Build against the system libbpf instead: `make LIBBPF_INCLUDE=/usr/include`.

## License

GPL-2.0. The BPF program declares `char LICENSE[] SEC("license") = "GPL"` in [`claudefeed.bpf.c`](claudefeed.bpf.c), required for the kernel helpers it uses.

---

Built with [yeet](https://yeet.cx/docs/?utm_source=github&utm_medium=readme&utm_campaign=claudefeed), a JS runtime for writing eBPF programs on Linux machines. Join us on [discord](https://discord.gg/dYZu9PjKB?utm_source=github&utm_medium=readme&utm_campaign=claudefeed).
