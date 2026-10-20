// pipeline.js: runs a detection file (Sigma base rules plus Sigma correlation rules) over enriched records.
//
// Base rules are parsed, compiled and matched by sigma.js. Correlation rules (event_count, value_count,
// temporal_ordered) are written in the Sigma correlation format; sigma.js reports correlations as
// unsupported, so correlate() below evaluates them. Records arrive already enriched: each one carries
// an `enrichment` object produced by the lookup stage (baselines, tickets, change windows).
"use strict";
const Sigma = require("./sigma.js");
const yaml = require("./js-yaml.min.js");

const MIN = 60000, HOUR = 3600000;

// Field mapping for rules written against Windows process_creation, applied to OCSF Process Activity records.
const FIELD_MAP = {
  "windows/process_creation": {
    Image: "process.file.path", CommandLine: "process.cmd_line", ParentImage: "process.parent_process.file.path",
    ParentCommandLine: "process.parent_process.cmd_line", User: "actor.user.name", OriginalFileName: "process.file.name",
  },
};
const APPSRC = { payments: "payments", "customer-portal": "portal", "edi-gateway": "edi", "customs-filing": "customs" };

function srcOf(ls) {
  ls = ls || {};
  const p = String(ls.product || "").toLowerCase();
  if (p === "okta") return "okta";
  if (p === "aws") return "cloudtrail";
  if (p === "kubernetes") return "k8s";
  if (p === "windows") return "edr";
  if (p === "m365") return "m365";
  if (p === "harbourline") return APPSRC[ls.service] || null;
  return null;
}
function mapKey(map, k) { const parts = k.split("|"); if (map[parts[0]]) parts[0] = map[parts[0]]; return parts.join("|"); }
function mapRule(rule) {
  const ls = rule.logsource || {}, map = FIELD_MAP[(ls.product || "") + "/" + (ls.category || "")];
  if (!map) return rule;
  const r = JSON.parse(JSON.stringify(rule)), det = r.detection;
  const mapOne = (o) => {
    if (!o || typeof o !== "object" || Array.isArray(o)) return o;
    const n = {}; Object.keys(o).forEach((k) => { n[mapKey(map, k)] = o[k]; }); return n;
  };
  Object.keys(det).forEach((id) => { if (id !== "condition") det[id] = Array.isArray(det[id]) ? det[id].map(mapOne) : mapOne(det[id]); });
  return r;
}
function splitDocs(text) {
  return String(text).split(/^---[ \t]*$/m).map((t) => t.replace(/^\s*\n/, "")).filter((t) => t.replace(/^\s*#.*$/gm, "").trim());
}
function spanMs(s) {
  const m = /^(\d+)\s*([smhd])$/.exec(String(s || "").trim());
  return m ? +m[1] * { s: 1000, m: MIN, h: HOUR, d: 24 * HOUR }[m[2]] : null;
}

function compile(text) {
  const out = { bases: [], corrs: [], errors: [], byName: {} };
  splitDocs(text).forEach((part, i) => {
    let obj;
    try { obj = yaml.load(part); } catch (e) { out.errors.push(`Document ${i + 1}: YAML error: ${e.reason || e.message}`); return; }
    if (!obj || typeof obj !== "object") { out.errors.push(`Document ${i + 1} is empty`); return; }
    if (obj.correlation) {
      const c = obj.correlation, cond = c.condition || {};
      const cr = { kind: "correlation", title: obj.title, id: obj.id, name: obj.name || null, level: obj.level, type: c.type,
        rules: [].concat(c.rules || []), groupBy: [].concat(c["group-by"] || []), timespan: c.timespan, span: spanMs(c.timespan), cond, generate: !!c.generate };
      if (!["event_count", "value_count", "temporal_ordered", "temporal"].includes(cr.type)) out.errors.push(`${obj.title}: correlation type ${cr.type} is not supported`);
      if (!cr.span) out.errors.push(`${obj.title}: timespan ${c.timespan} is not a duration such as 10m or 4h`);
      if (cr.type === "value_count" && !cond.field) out.errors.push(`${obj.title}: value_count needs condition.field`);
      out.corrs.push(cr); if (cr.name) out.byName[cr.name] = cr;
      return;
    }
    try {
      const rule = Sigma.parse(part), comp = Sigma.compile(mapRule(rule));
      comp.errors.forEach((er) => out.errors.push(`${rule.title}: ${er}`));
      const b = { kind: "base", rule, title: rule.title, id: rule.id, name: rule.name || null, compiled: comp, src: srcOf(rule.logsource) };
      if (!b.src) out.errors.push(`${rule.title}: no event source for logsource ${JSON.stringify(rule.logsource)}`);
      out.bases.push(b); if (b.name) out.byName[b.name] = b;
    } catch (e) { out.errors.push(`Document ${i + 1}: ${e.message}`); }
  });
  out.corrs.forEach((c) => c.rules.forEach((n) => { if (!out.byName[n]) out.errors.push(`${c.title}: refers to rule ${n}, which is not in this file`); }));
  const referenced = {}; out.corrs.forEach((c) => c.rules.forEach((n) => { referenced[n] = 1; }));
  out.terminal = out.corrs.length ? out.corrs.filter((c) => !c.name || !referenced[c.name] || c.generate) : out.bases;
  return out;
}

const first = (v) => (v && v.length ? v[0] : null);
function groupVal(item, f) {
  if (item.group && Object.prototype.hasOwnProperty.call(item.group, f)) return item.group[f];
  return item.ev ? first(Sigma.getValues(item.ev.record, f)) : null;
}
function baseItems(b, events) {
  return events.filter((e) => e.source === b.src && Sigma.match(b.compiled, e.record).match)
    .map((e) => ({ ts: e.t, first: e.t, ids: [e.id], ev: e }));
}
function itemsFor(cd, name, events, memo) {
  if (memo[name]) return memo[name];
  const node = cd.byName[name];
  if (!node) return (memo[name] = []);
  memo[name] = node.kind === "base" ? baseItems(node, events) : correlate(cd, node, events, memo);
  return memo[name];
}
function correlate(cd, c, events, memo) {
  const all = [].concat(...c.rules.map((n, ri) => itemsFor(cd, n, events, memo).map((it) => ({ ri, ...it })))).sort((a, b) => a.ts - b.ts);
  const groups = {}, order = [];
  all.forEach((it) => {
    const g = {}; c.groupBy.forEach((f) => { g[f] = groupVal(it, f); });
    if (c.groupBy.some((f) => g[f] === null || g[f] === undefined)) return;
    const k = JSON.stringify(g);
    if (!groups[k]) { groups[k] = { g, list: [] }; order.push(k); }
    groups[k].list.push(it);
  });
  const out = [], cond = c.cond || {};
  const ok = (n) => (cond.gte !== undefined ? n >= cond.gte : cond.gt !== undefined ? n > cond.gt : cond.eq !== undefined ? n === cond.eq : n >= 1);
  const emit = (g, items, last) => {
    const ids = [...new Set(items.flatMap((x) => x.ids))];
    out.push({ ts: last.ts, first: Math.min(...items.map((x) => x.first)), ids, group: g, corr: c });
  };
  order.forEach((k) => {
    const { g, list: L } = groups[k];
    if (c.type === "event_count" || c.type === "value_count") {
      let i = 0;
      for (let j = 0; j < L.length; j++) {
        while (L[j].ts - L[i].ts > c.span) i++;
        const win = L.slice(i, j + 1);
        const n = c.type === "event_count" ? win.length
          : new Set(win.map((x) => (x.ev ? first(Sigma.getValues(x.ev.record, cond.field)) : null)).filter((v) => v !== null)).size;
        if (ok(n)) { emit(g, win, L[j]); i = j + 1; }
      }
    } else { // temporal_ordered; temporal is treated as ordered
      let from = 0;
      for (let s = 0; s < L.length; s++) {
        if (L[s].ri !== 0 || L[s].ts < from) continue;
        let seq = [L[s]], cur = L[s];
        for (let r = 1; r < c.rules.length; r++) {
          const nx = L.find((it) => it.ri === r && it.ts >= cur.ts && it.ts - L[s].ts <= c.span);
          if (!nx) { seq = null; break; }
          seq.push(nx); cur = nx;
        }
        if (seq) { emit(g, seq, cur); from = cur.ts + 1; }
      }
    }
  });
  return out;
}

// hits(compiled, events): every alert-producing match. events: [{ id, ts (ISO), source, record }]
function hits(cd, events) {
  if (cd.errors.length) return [];
  const evs = events.map((e) => ({ ...e, t: Date.parse(e.ts) })).sort((a, b) => a.t - b.t), memo = {}, out = [];
  if (cd.corrs.length) cd.terminal.forEach((c) => (c.name ? itemsFor(cd, c.name, evs, memo) : correlate(cd, c, evs, memo)).forEach((h) => out.push(h)));
  else cd.bases.forEach((b) => baseItems(b, evs).forEach((h) => out.push(h)));
  return out;
}

module.exports = { compile, hits, splitDocs, srcOf };
