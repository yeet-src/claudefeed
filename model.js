/* The seeding + decoding model.
 *
 * claudefeed keeps no live process table of its own — the kernel owns the
 * `tracked` membership set and maintains it across exec/exit. This module
 * does the two things that have to happen in JS: compute the *initial*
 * membership (the live session processes plus every descendant) from one
 * sysgraph snapshot, and decode the raw ring-buffer records into the
 * fields the feed renders. */

import { MATCH } from "./config.js";

export const stats = {
  events: 0,
  t0: Date.now(),
};

/* char[] fields arrive char-flagged, so the runtime hands us a pre-decoded
 * JS string; trim at the first NUL. Fall back to a byte decode in case a
 * build surfaces the raw array instead. */
export function cstr(v) {
  if (v == null) return "";
  if (typeof v === "string") {
    const nul = v.indexOf("\0");
    return nul >= 0 ? v.slice(0, nul) : v;
  }
  let s = "";
  for (const b of Object.values(v)) {
    if (b === 0) break;
    s += String.fromCharCode(b);
  }
  return s;
}

export function basename(path) {
  if (!path) return "";
  const i = path.lastIndexOf("/");
  return i >= 0 ? path.slice(i + 1) : path;
}

export function fmtDur(ns) {
  if (!ns) return "";
  const ms = Number(ns) / 1e6;
  if (ms < 1000) return `${ms.toFixed(0)}ms`;
  const s = ms / 1000;
  if (s < 60) return `${s.toFixed(1)}s`;
  return `${Math.floor(s / 60)}m${Math.round(s % 60)}s`;
}

/* A `__u8 addr[16]` field comes through as a byte-keyed object (the same
 * shape airtop sees for MAC fields), so collect the bytes in order. */
function addrBytes(addr) {
  return Object.values(addr ?? {}).map((b) => Number(b) & 0xff);
}

export function fmtAddr(family, addr, port) {
  const b = addrBytes(addr);
  if (family === 10) {
    /* Group the 16 bytes into eight hextets, then collapse the longest
     * run of zero groups to `::` — enough to read, not a full RFC 5952. */
    const groups = [];
    for (let i = 0; i < 16; i += 2) groups.push(((b[i] << 8) | b[i + 1]) >>> 0);
    let host = groups.map((g) => g.toString(16)).join(":");
    host = host.replace(/(^|:)0(:0)+(:|$)/, "::").replace(/:::/, "::");
    return `[${host}]:${port}`;
  }
  return `${b[0]}.${b[1]}.${b[2]}.${b[3]}:${port}`;
}

/* Decode the open(2) flag word into the access intent that matters for an
 * audit line: read / write / read-write, plus a `+` when the open could
 * create the file. The low two bits are the access mode (O_RDONLY=0,
 * O_WRONLY=1, O_RDWR=2); O_CREAT is 0o100 on every arch yeet targets. */
export function fmtOpenMode(flags) {
  const acc = flags & 0o3;
  const mode = acc === 1 ? "w" : acc === 2 ? "rw" : "r";
  return (flags & 0o100) ? `${mode}+` : mode;
}

/* Match on the command *name* — comm or argv[0]'s basename — not the whole
 * cmdline, mirroring the kernel-side needle test so the JS seed and the
 * kernel agree on what counts as a session. */
function isMatch(comm, cmdline) {
  if ((comm || "").toLowerCase().includes(MATCH)) return true;
  const argv0 = basename((cmdline || "").split(" ")[0]).toLowerCase();
  return argv0.length > 0 && argv0.includes(MATCH);
}

/* One sysgraph query → the set of tgids that belong to a live session:
 * every process whose command name matches, plus all of their descendants
 * (a matched root's children may not match by name themselves). The
 * returned set is what JS writes into the kernel's `tracked` map. */
export async function sessionTgids() {
  const query = `{ procs { pid stat { ppid comm } cmdline } }`;
  const res = await yeet.graph.query(query);
  const list = (res && res.data && res.data.procs) || [];

  const byPid = new Map();
  const children = new Map();
  for (const p of list) {
    const st = p.stat;
    if (!st) continue;
    const node = { pid: p.pid, ppid: st.ppid, comm: st.comm, cmdline: (p.cmdline || []).join(" ") };
    byPid.set(p.pid, node);
    if (!children.has(st.ppid)) children.set(st.ppid, []);
    children.get(st.ppid).push(p.pid);
  }

  /* Seed from matched roots, then BFS down the child links. The `seen`
   * guard keeps a pid-reuse cycle from looping forever. */
  const tracked = new Set();
  const queue = [];
  for (const node of byPid.values()) {
    if (isMatch(node.comm, node.cmdline)) queue.push(node.pid);
  }
  while (queue.length) {
    const pid = queue.shift();
    if (tracked.has(pid)) continue;
    tracked.add(pid);
    for (const kid of children.get(pid) || []) queue.push(kid);
  }

  return { tracked, total: list.length };
}
