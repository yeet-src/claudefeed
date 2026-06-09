/* Runtime configuration, parsed once from `yeet.args`. Imported by the
 * model (the match needle pushed into the kernel) and by main (run
 * duration, what to show), so the arg surface lives in one place. */

/* yeet parses `--match=x` as a named arg but leaves a bare `match=x` as a
 * positional (in `_`). Fold positional `k=v` tokens back into the named
 * set so both styles work — the bare form is what the examples document. */
const raw = (typeof yeet !== "undefined" && yeet.args) || {};
const args = { ...raw };
for (const tok of raw._ || []) {
  const eq = String(tok).indexOf("=");
  if (eq > 0) args[String(tok).slice(0, eq)] = String(tok).slice(eq + 1);
}

export const MATCH = String(args.match ?? args.m ?? "claude").toLowerCase();
export const SECS = Number(args.secs ?? args.s ?? 0); /* 0 = run until Ctrl-C */

/* Event-class filters. Default shows everything; pass e.g. `only=exec,conn`
 * to narrow the feed, or `except=open` to drop the noisiest class. */
const ALL = ["exec", "exit", "open", "conn", "listen"];
const csv = (v) => String(v).split(",").map((s) => s.trim().toLowerCase()).filter(Boolean);
const only = args.only ? csv(args.only) : null;
const except = args.except ? csv(args.except) : [];
export const SHOW = new Set(ALL.filter((k) => (only ? only.includes(k) : true) && !except.includes(k)));

/* Event kinds emitted by claudefeed.bpf.c on the `events` ring buffer. */
export const EVT_EXEC = 0;
export const EVT_EXIT = 1;
export const EVT_OPEN = 2;
export const EVT_CONNECT = 3;
export const EVT_LISTEN = 4;

/* libbpf names internal data-section maps `<first 8 of obj_name>.data`
 * (obj_name = filename up to the first `.`, so `claudefeed.bpf.o` →
 * `claudefeed` → first 8 = `claudefe`). Bind against that truncated
 * name, not the raw `.data` ELF section name. */
export const DATA_SEC = "claudefe.data";
