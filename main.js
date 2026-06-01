import { DataSec, HashMap, RingBuf } from "yeet:bpf";
import bpf from "./claudefeed.bpf.o";

import {
  DATA_SEC,
  EVT_CONNECT,
  EVT_EXEC,
  EVT_EXIT,
  EVT_LISTEN,
  EVT_OPEN,
  MATCH,
  SECS,
  SHOW,
} from "./config.js";
import { line } from "./feed.js";
import { sessionTgids, stats } from "./model.js";

/* claudefeed — a scrolling audit log of everything a matched session does:
 * commands exec'd, files opened, TCP ports reached or bound.
 *
 * The kernel side (claudefeed.bpf.c) owns a `tracked` set of session tgids
 * and only emits file/network events for members, so the feed never drowns
 * in system-wide noise. This file wires the two ends together:
 *
 *   1. push the match needle into the kernel's config so a *fresh* session
 *      started after we attach is caught the moment it exec's;
 *   2. seed `tracked` from one sysgraph snapshot — the live session
 *      processes and all their descendants — so activity from processes
 *      that were already running is captured too;
 *   3. stream the ring buffer, formatting each record as one audit line. */

const KIND_KEY = {
  [EVT_EXEC]: "exec",
  [EVT_EXIT]: "exit",
  [EVT_OPEN]: "open",
  [EVT_CONNECT]: "conn",
  [EVT_LISTEN]: "listen",
};

try {
  const control = await bpf
    .bind("events", { kind: "ringbuf", btf_struct: "event" })
    .bind("tracked", { kind: "hash_map" })
    .bind(DATA_SEC, { kind: "data" })
    .start();

  const ring = new RingBuf(control, "events");
  const tracked = new HashMap(control, "tracked");
  const config = new DataSec(control, DATA_SEC);

  /* Tell the kernel what a session looks like (lowercased, NUL-safe). The
   * basename of every exec'd program is tested against this needle. */
  const needle = MATCH.slice(0, 15);
  await config.patch({ needle, needle_len: needle.length });

  /* Seed membership from the current process tree. updateBatch lands the
   * whole set in one syscall; fall back to per-key writes on older kernels
   * that lack BPF_MAP_*_BATCH. */
  const { tracked: seed, total } = await sessionTgids();
  if (seed.size) {
    const pairs = [...seed].map((pid) => [pid, 1]);
    await tracked.updateBatch(pairs).catch(async () => {
      for (const [k, v] of pairs) await tracked.update(k, v).catch(() => {});
    });
  }
  console.log(
    `claudefeed — auditing "${MATCH}" sessions · seeded ${seed.size} ` +
      `process${seed.size === 1 ? "" : "es"} from ${total} live · ` +
      `streaming ${[...SHOW].join("/")} …`,
  );

  const sub = await ring.subscribe(
    (rec) => {
      const e = rec.event ?? rec;
      stats.events++;
      if (!SHOW.has(KIND_KEY[e.kind])) return;
      console.log(line(e, Date.now()));
    },
    (err) => console.error("ringbuf error:", err),
  );

  if (SECS > 0) await new Promise((r) => setTimeout(r, SECS * 1000));
  else await new Promise(() => {}); /* run until Ctrl-C */

  await sub.unsubscribe();
  await control.stop();
} catch (err) {
  console.error(err);
}
