// Agents' background work, read the way Salt's web Background panel reads it.
//
// A work report is an ordinary end-to-end encrypted message in a lane (a sidechain under a chat) whose plaintext
// starts with `[[SALT-WORK id=… status=… …]]`, then a title line and optional detail lines.
//
// Ports (keep in step with them; tests/me-work.test.mjs holds cases copied from the web's own tests):
//   parseWorkReport      salt-fe src/utilities/work.js  parseWorkReport   (the writers are salt-agent-sdk src/work.ts and
//                                                                          Grains connectors/__init__.py format_work_report)
//   collectReports       salt-fe src/components/chats/tasks/tasks.js  collectReports (fold by lane + id, latest status wins,
//                                                                          title is the ask, startedAt is the first report)
//   backgroundSections   same file, backgroundSections (scheduled / running with the 10-minute stale rule / stuck / done)
//
// Left out on purpose, because Background draws them in their own panels rather than as jobs: the strategy, rules,
// my_state, advantage and waiting-table bodies. Their lines are dropped from a detail and a report of those kinds is not
// returned.

export const WORK_STATUSES = ["running", "waiting", "done", "failed", "scheduled", "cancelled", "stuck"];
export const WORK_NEEDS = ["card", "payment", "mandate", "human"];
export const STALE_AFTER_MS = 10 * 60 * 1000;
export const DONE_WINDOW_MS = 24 * 60 * 60 * 1000;

const MAX_STEPS = 40;
const STEP_MAX_CHARS = 120;
const LINE_MAX_CHARS = 200;
const DETAIL_LINE_RE = /^(where|needs|steps|strategy|advantage|waiting|rules|my_state):[ \t]*(.*)$/;
const DUE_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(:\d{2}(\.\d+)?)?(Z|[+-]\d{2}:?\d{2})$/;
const WORK_KINDS = ["delegation", "task", "strategy", "rules", "my_state"];
const STRATEGY_STATUSES = ["attempting", "blocked", "succeeded", "abandoned", "superseded"];
const STRATEGY_AS_WORK = { attempting: "running", blocked: "running", succeeded: "done", abandoned: "cancelled", superseded: "cancelled" };
const WORK_REPEATS = ["hourly", "daily", "weekdays", "weekly", "monthly"];
const ID_RE = /^[A-Za-z0-9_-]{1,64}$/;
const HANDLE_RE = /^[A-Za-z0-9_.-]{1,40}$/;
export const WORK_MARKER_RE = /^\[\[SALT-WORK ([^\]\n]*)\]\]\n?/;
const PROGRESS_FRACTION_RE = /^(0(\.\d+)?|1(\.0+)?)$/;
const PROGRESS_STEP_RE = /^(\d{1,3})\/(\d{1,3})$/;

const parseSteps = (value) => {
  let list;
  try {
    list = JSON.parse(value);
  } catch {
    return null;
  }
  if (!Array.isArray(list)) return null;
  const steps = list.filter((x) => typeof x === "string" && x.trim()).map((x) => x.trim().slice(0, STEP_MAX_CHARS));
  return steps.length ? steps.slice(-MAX_STEPS) : null;
};

/** The report in a plaintext, or null when it is not one (or is a kind Background draws elsewhere). */
export function parseWorkReport(plaintext) {
  const text = typeof plaintext === "string" ? plaintext : "";
  const match = WORK_MARKER_RE.exec(text);
  if (!match) return null;
  const attrs = {};
  match[1].split(/\s+/).forEach((pair) => {
    const eq = pair.indexOf("=");
    if (eq > 0) attrs[pair.slice(0, eq)] = pair.slice(eq + 1);
  });
  if (attrs.kind === "strategy" && STRATEGY_STATUSES.includes(attrs.status)) attrs.status = STRATEGY_AS_WORK[attrs.status];
  if (!ID_RE.test(attrs.id || "") || !WORK_STATUSES.includes(attrs.status)) return null;
  if (["strategy", "rules", "my_state"].includes(attrs.kind)) return null;
  const [title, ...rest] = text.slice(match[0].length).split("\n");
  const report = { id: attrs.id, status: attrs.status, title: (title || "").trim() };
  if (WORK_KINDS.includes(attrs.kind)) report.kind = attrs.kind;
  if (attrs.with && HANDLE_RE.test(attrs.with)) report.with = attrs.with;
  if (attrs.due && DUE_RE.test(attrs.due) && !Number.isNaN(Date.parse(attrs.due))) report.due = attrs.due;
  if (attrs.repeat && WORK_REPEATS.includes(attrs.repeat)) report.repeat = attrs.repeat;
  if (attrs.progress && PROGRESS_FRACTION_RE.test(attrs.progress)) {
    const fraction = parseFloat(attrs.progress);
    if (fraction >= 0 && fraction <= 1) report.progress = { ...(report.progress || {}), fraction };
  }
  if (attrs.step && PROGRESS_STEP_RE.test(attrs.step)) {
    const [, stepStr, ofStr] = PROGRESS_STEP_RE.exec(attrs.step);
    const step = parseInt(stepStr, 10);
    const of = parseInt(ofStr, 10);
    if (step >= 1 && of >= step) report.progress = { ...(report.progress || {}), step, of };
  }
  if (attrs.needs && WORK_NEEDS.includes(attrs.needs)) report.needsKind = attrs.needs;
  if (attrs.transfer && ID_RE.test(attrs.transfer)) report.transferId = attrs.transfer;
  const kept = [];
  rest.forEach((line) => {
    const m = DETAIL_LINE_RE.exec(line.trim());
    if (!m) {
      kept.push(line);
      return;
    }
    const value = m[2].trim();
    if (m[1] === "steps") {
      const steps = parseSteps(value);
      if (steps) report.steps = steps;
    } else if (m[1] === "where" || m[1] === "needs") {
      if (value) report[m[1]] = value.slice(0, LINE_MAX_CHARS);
    }
    // strategy / advantage / waiting / rules / my_state lines: dropped (drawn in their own panels on the web)
  });
  const detail = kept.join("\n").trim();
  if (detail) report.detail = detail;
  if (report.status === "stuck" || (report.status === "waiting" && (report.where || report.needs || report.needsKind))) report.stuck = true;
  return report;
}

/**
 * Items are `{id, laneId, at (ms), work (a parsed report), withName, isOwn}`. One entry per piece of work (lane + id):
 * the latest status wins, the first report is when it started, the title is the ask, `stream` is every report in order.
 */
export function collectReports(items = []) {
  const byWork = new Map();
  [...items]
    .filter((item) => item && item.work && !item.isOwn)
    .sort((a, b) => (a.at || 0) - (b.at || 0))
    .forEach((item) => {
      const key = `${item.laneId}:${item.work.id}`;
      const prev = byWork.get(key);
      const step = { status: item.work.status, title: item.work.title || "", detail: item.work.detail || null, at: item.at || 0, messageId: item.id, steps: item.work.steps || null };
      const stream = prev ? [...prev.stream, step] : [step];
      const finished = ["done", "failed", "cancelled"].includes(item.work.status);
      byWork.set(key, {
        key,
        id: item.work.id,
        laneId: item.laneId,
        agentName: item.withName,
        status: item.work.status,
        kind: item.work.kind || (prev && prev.kind) || "task",
        with: item.work.with || (prev && prev.with) || null,
        title: (prev && prev.title) || item.work.title || "",
        latest: item.work.title || (prev && prev.latest) || "",
        outcome: finished ? item.work.title : prev ? prev.outcome : null,
        detail: (prev && prev.detail) || item.work.detail || null,
        due: item.work.due || null,
        repeat: item.work.repeat || (prev && prev.repeat) || null,
        progress: item.work.progress || null,
        stuck: !!item.work.stuck,
        where: item.work.where || null,
        needs: item.work.needs || null,
        needsKind: item.work.needsKind || null,
        steps: item.work.steps || (prev && prev.steps) || null,
        transferId: item.work.transferId || (prev && prev.transferId) || null,
        messageId: item.id,
        startedAt: prev ? prev.startedAt : item.at || 0,
        updatedAt: item.at || 0,
        stream,
      });
    });
  return [...byWork.values()];
}

/** Scheduled / running (stale after 10 min) / waiting / done, newest first. `waiting` includes plain questions, flagged by `stuck`. */
export function backgroundSections({ items = [], now = Date.now(), includeDone = true }) {
  const reports = collectReports(items);
  const scheduled = reports
    .filter((r) => r.status === "scheduled")
    .sort((a, b) => (a.due ? Date.parse(a.due) : Infinity) - (b.due ? Date.parse(b.due) : Infinity));
  const running = reports
    .filter((r) => r.status === "running")
    .map((r) => ({ ...r, stale: now - r.updatedAt > STALE_AFTER_MS }))
    .sort((a, b) => b.updatedAt - a.updatedAt);
  const waiting = reports.filter((r) => r.stuck || r.status === "stuck" || r.status === "waiting").sort((a, b) => b.updatedAt - a.updatedAt);
  const done = includeDone
    ? reports.filter((r) => ["done", "failed", "cancelled"].includes(r.status) && now - r.updatedAt <= DONE_WINDOW_MS).sort((a, b) => b.updatedAt - a.updatedAt)
    : [];
  return { scheduled, running, waiting, done };
}
