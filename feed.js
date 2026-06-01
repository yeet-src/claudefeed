/* Rendering: turn one decoded ring-buffer record into a single colored
 * audit line. The feed is append-only — each event is one line, newest at
 * the bottom, like `tail -f` — so there's no full-screen repaint and a
 * piped run is a clean plain-text log. Colors use the `style` global
 * (standard 16-color palette, no truecolor), which no-ops off a TTY. */

import { EVT_CONNECT, EVT_EXEC, EVT_EXIT, EVT_LISTEN, EVT_OPEN } from "./config.js";
import { basename, cstr, fmtAddr, fmtDur, fmtOpenMode } from "./model.js";

/* A stable per-PID color so every line from one process shares a hue and the
 * eye can group a burst of activity by who caused it — used to tint both the
 * pid and that process's program name. Drawn from the `style` global's
 * standard palette (no truecolor), so it renders in a TTY and no-ops when
 * piped. */
const PID_COLORS = [style.red, style.green, style.yellow, style.blue, style.magenta, style.cyan];

function pidColor(pid) {
  return PID_COLORS[((pid * 2654435761) >>> 0) % PID_COLORS.length];
}

function pidTag(pid) {
  return pidColor(pid)(String(pid).padStart(7));
}

function clock(now) {
  const d = new Date(now);
  const p = (n, w = 2) => String(n).padStart(w, "0");
  return style.dim(`${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}.${p(d.getMilliseconds(), 3)}`);
}

/* Color a path cyan so it stands out from the surrounding text. */
function paintPath(p) {
  return style.cyan(p);
}

/* Light shell-style highlighting for a command line: flags muted, path-ish
 * tokens basename-popped, everything else left alone. argv was space-joined
 * kernel-side, so this tokenizes on spaces — cosmetic, and good enough that
 * a quoted arg split across tokens still colors sensibly. */
function paintCmd(cmd) {
  return cmd
    .split(" ")
    .map((tok) => {
      if (!tok) return tok;
      if (tok[0] === "-") return style.yellow(tok);
      if (tok.includes("/")) return paintPath(tok);
      return tok;
    })
    .join(" ");
}

/* Fixed-width, color-keyed event class so the column reads at a glance. */
function badge(kind) {
  switch (kind) {
    case EVT_EXEC: return style.green("exec  ");
    case EVT_EXIT: return style.dim("exit  ");
    case EVT_OPEN: return style.blue("open  ");
    case EVT_CONNECT: return style.magenta("conn  ");
    case EVT_LISTEN: return style.yellow("listen");
    default: return "?     ";
  }
}

function detail(e) {
  /* The program name carries this process's color on every line, so the
   * name and its pid read as one actor. */
  const col = pidColor(e.pid);
  const comm = col(cstr(e.comm));
  switch (e.kind) {
    case EVT_EXEC: {
      const cmd = cstr(e.cmdline).trimEnd();
      const prog = basename(cstr(e.filename));
      /* The freshly-exec'd program is the headline — bold it in its color. */
      return `${style.bold(col(prog))} ${style.dim("·")} ${paintCmd(cmd)}`;
    }
    case EVT_EXIT: {
      const how = e.sig
        ? style.red(`killed sig ${e.sig}`)
        : e.exit_code
          ? style.red(`exit ${e.exit_code}`)
          : style.dim("exit 0");
      const dur = e.duration_ns ? ` ${style.dim(`after ${fmtDur(e.duration_ns)}`)}` : "";
      return `${comm} ${how}${dur}`;
    }
    case EVT_OPEN: {
      const path = cstr(e.filename);
      return `${comm} ${style.dim(`(${fmtOpenMode(e.flags)})`)} ${paintPath(path)}`;
    }
    case EVT_CONNECT:
      return `${comm} ${style.dim("→")} ${style.bold(fmtAddr(e.family, e.addr, e.port))}`;
    case EVT_LISTEN:
      return `${comm} ${style.dim("listening on")} ${style.bold(fmtAddr(e.family, e.addr, e.port))}`;
    default:
      return comm;
  }
}

export function line(e, now) {
  return `${clock(now)}  ${pidTag(e.pid)}  ${badge(e.kind)}  ${detail(e)}`;
}
