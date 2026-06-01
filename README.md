# claudefeed

<p align="center">
  <img src="https://img.shields.io/badge/platform-Linux-1793D1" alt="Linux">
  <img src="https://img.shields.io/badge/built%20with-yeet%20%2B%20eBPF-8A2BE2" alt="yeet + eBPF">
  <img src="https://img.shields.io/badge/license-GPL--2.0-3DA639" alt="GPL-2.0">
  <a href="https://discord.gg/dYZu9PjKB"><img src="https://img.shields.io/badge/chat-Discord-5865F2" alt="Discord"></a>
</p>

![claudefeed demo](assets/claudefeed.gif)

A scrolling **audit log** of everything a **Claude Code** session does:
every command it `exec`s (with the full argv), every file it opens, and
every TCP port it reaches out to or binds — for the matched session and
everything beneath it, and nothing else.

Where its sibling [`claudetree`](../claudetree) paints *who is running* as
a live process tree, `claudefeed` is the companion the claudetree README
promised: the `tail -f` of *what they did*.

```
claudefeed — auditing "claude" sessions · seeded 9 processes from 288 live · streaming exec/exit/open/conn/listen …
16:11:22.023  3003897  exit    sleep exit 0
16:11:22.023  3003924  exec    uname · /usr/bin/uname -a
16:11:22.024  3003924  exit    uname exit 0 after 1ms
16:11:22.024  3003925  exec    curl · curl -s -m 3 http://example.com
16:11:22.033  3003925  conn    curl → 104.20.23.154:80
16:11:22.053  3003925  exit    curl exit 0 after 29ms
```

Each line is `time · pid · class · detail`. The **pid and that process's
program name** share a stable per-process color, so a burst of activity
reads as one actor; re-exec of the same pid keeps its color. Within a
command line and an opened path, **flags are muted and paths are cyan**, so
a `bash -c '…'` pipeline is legible at a glance. The class is a color-keyed
badge:

| class    | source                                | detail                                |
| -------- | ------------------------------------- | ------------------------------------- |
| `exec`   | `sys_enter_execve`                    | program name + full command line      |
| `exit`   | `sched/sched_process_exit`            | `exit N` / `killed sig N`, + lifetime |
| `open`   | `sys_enter_openat`                    | `(mode)` + path                       |
| `conn`   | `kprobe/tcp_connect`                  | `→ addr:port` (outbound)              |
| `listen` | `kprobe/inet_listen`                  | bound `addr:port`                     |

## The "and nothing else" trick

A system-wide feed of every `openat` would be a firehose. The filtering
happens **in the kernel**: a `tracked` hash map holds the tgid of every
process that belongs to a session, and the file/network probes are no-ops
for any pid not in it — so the noise never crosses into userspace. The set
stays current from three directions:

- **JS seeds it.** One `yeet.graph` query at startup finds the live
  session processes and all their descendants and writes the tgids into
  `tracked` via the map API (`updateBatch`).
- **`exec` self-propagates it.** When a tracked process exec's a child,
  the child inherits membership. A *fresh* session — one whose parent
  isn't tracked — is caught by matching the exec'd program's basename
  against a needle the JS side patches into the program's config.
- **`exit` prunes it.** The thread-group leader leaving drops its tgid.

A `start` hash map keyed by tgid bridges `exec`→`exit` so the `exit` line
can report how long the process lived (processes already alive at attach
have no stamp and report an unknown lifetime).

## Build

```sh
make
```

Dumps the running kernel's BTF to `include/vmlinux.h` (needed for the
tracepoint context structs, `task_struct`, and the `sock`/`socket`
structs the network kprobes read), then compiles `claudefeed.bpf.c`.
Requires `clang`, `bpftool`, and a kernel with BTF.

> If your kernel's BTF is newer than the bundled libbpf headers, clang
> may flag a conflicting `bpf_stream_vprintk` declaration. Build against
> the system libbpf instead: `make LIBBPF_INCLUDE=/usr/include`.

## Run

```sh
yeet run .
```

Args (both `--match=x` and the bare `match=x` form work):

| arg              | default      | meaning                                            |
| ---------------- | ------------ | -------------------------------------------------- |
| `match=<name>`   | `claude`     | session program-name needle (see below)            |
| `secs=<n>`       | `0`          | run for N seconds, `0` = until Ctrl-C              |
| `only=<classes>` | all          | show only these, e.g. `only=exec,conn,listen`      |
| `no=<classes>`   | none         | drop these, e.g. `no=open` (the noisiest class)    |

```sh
yeet run . no=open secs=30          # commands + network only, for 30s
yeet run . only=exec,conn           # just "what ran" and "what it dialed"
yeet run . match=node               # audit node sessions instead
```

`match` is tested against each exec'd program's **basename** (a prefix
match, case-insensitive) and, for the startup seed, against `comm` or
`argv[0]`'s basename — never the whole command line, so a process that
merely mentions the name in a path or argument doesn't masquerade as a
session. The same needle drives both the JS seed and the kernel-side
catch of fresh sessions, so the two agree on what counts.

Colors come from yeet's `style` global (standard 16-color palette, no
truecolor), which no-ops to plain text when stdout isn't a TTY — so a
piped run is a clean plain-text log you can grep or archive.

## Alerting

The feed is local — but the same ring-buffer callback that prints each
line can also *page you*. yeet posts to Slack: log in at
[yeet.cx/settings](https://yeet.cx/settings), connect your workspace once,
and `yeet.alert` can then send to any channel it can reach.

The subscribe callback in `main.js` already holds every decoded record, so
an alert is just a branch inside it. To know the moment a Claude session
dials out to a host it has no business touching:

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

The same shape fits any class: alert on an `EVT_EXEC` whose
`cstr(e.cmdline)` matches `rm -rf` or `curl … | sh`, or an `EVT_OPEN`
that touches `~/.ssh/id_*`. The callback already has the decoded record
in hand — you only add the predicate and the `yeet.alert`.

## Layout

| file          | responsibility                                                       |
| ------------- | -------------------------------------------------------------------- |
| `main.js`     | wiring: bind/start, push the needle, seed `tracked`, stream the ring |
| `config.js`   | `yeet.args` → constants (`match`, `secs`, `only`/`no`, event kinds)  |
| `model.js`    | seed the session subtree from the sysgraph; decode record fields     |
| `feed.js`     | format one record into a colored audit line                          |

## How it maps to the daemon

- `yeet.graph.query(gql)` resolves a GraphQL query against the sysgraph;
  here `procs { pid stat { ppid comm } cmdline }` seeds the membership set.
- Programs are auto-attached on `start()` by their `SEC()` name: three
  tracepoints (`tp/syscalls/*`, `tp/sched/*`) and two kprobes
  (`kprobe/tcp_connect`, `kprobe/inet_listen`).
- `HashMap("tracked")` is written from JS to seed membership; the kernel
  maintains it thereafter. `DataSec` patches the match needle into the
  program's `.data` section at runtime.
- `events` is a ring buffer bound by its `btf_struct` (`event`);
  `RingBuf.subscribe` streams each record back as a decoded object. A
  `char[]` field arrives as a JS string and an `__u8[N]` field (the raw
  address) as a byte object, so argv is space-joined kernel-side into one
  `char[]` while addresses stay binary-clean.
