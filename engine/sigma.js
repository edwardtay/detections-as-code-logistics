/* sigma.js: a Sigma rule engine for the browser (and node, for tests).
 *
 * parse()    YAML text -> rule object (needs js-yaml, vendored next to this file)
 * compile()  rule -> AST with every search identifier inlined into the condition
 * match()    AST + event -> { match, ids } where ids are the identifiers that were true
 * lint()     rule -> errors and warnings, including the mistakes AI drafts tend to make
 * convert()  AST -> Splunk SPL, Microsoft Sentinel KQL, Elastic Lucene, Athena / CloudTrail Lake SQL
 *
 * Covers the Sigma 2.0 detection spec: field maps and lists, keyword lists, wildcards with
 * backslash escapes, null and empty values, and the modifiers contains, startswith, endswith,
 * all, re (i, m, s), cased, exists, cidr, gt, gte, lt, lte, fieldref, windash, base64,
 * base64offset, wide / utf16le, utf16be, utf16. Conditions support and, or, not, brackets,
 * "1 of x*", "all of x*" and "them". Correlation rules and the old "| count()" pipes are
 * reported as unsupported rather than guessed at.
 */
(function (root) {
  "use strict";

  var KNOWN_MODS = ["contains", "startswith", "endswith", "all", "re", "i", "m", "s", "cased", "exists", "cidr", "gt", "gte", "lt", "lte",
    "fieldref", "windash", "base64", "base64offset", "wide", "utf16le", "utf16be", "utf16", "expand"];
  // Modifiers AI drafts and old rule packs invent. Each maps to what was meant.
  var WRONG_MODS = { contain: "contains", icontains: "contains", regex: "re", regexp: "re", startwith: "startswith", beginswith: "startswith",
    endwith: "endswith", equals: "(no modifier)", eq: "(no modifier)", in: "(a YAML list)", any: "(a YAML list)", like: "contains", wildcard: "(plain value with *)",
    gte_: "gte", lowercase: "(nothing: matching is case-insensitive by default)", nocase: "(nothing: matching is case-insensitive by default)" };
  var LEVELS = ["informational", "low", "medium", "high", "critical"];
  var STATUSES = ["stable", "test", "experimental", "deprecated", "unsupported"];
  var TACTICS = ["reconnaissance", "resource-development", "initial-access", "execution", "persistence", "privilege-escalation", "defense-evasion",
    "credential-access", "discovery", "lateral-movement", "collection", "command-and-control", "exfiltration", "impact"];
  var DASHES = ["-", "/", "\u2013", "\u2014", "\u2015"];

  function SigmaError(msg) { this.message = msg; }
  SigmaError.prototype = Object.create(Error.prototype);

  /* ---------------- parsing ---------------- */

  function yaml() {
    var y = root.jsyaml || (typeof require === "function" ? require("./js-yaml.min.js") : null);
    if (!y) throw new SigmaError("YAML parser not loaded");
    return y;
  }
  function parse(text) {
    var docs;
    try { docs = yaml().loadAll(String(text || "")); } catch (e) { throw new SigmaError("YAML error: " + (e.reason || e.message) + (e.mark ? " (line " + (e.mark.line + 1) + ")" : "")); }
    docs = docs.filter(function (d) { return d && typeof d === "object"; });
    if (!docs.length) throw new SigmaError("No rule found. A Sigma rule is a YAML document with a detection block.");
    var rule = null, extra = [];
    docs.forEach(function (d) { if (!rule && d.detection) rule = d; else extra.push(d); });
    if (!rule) {
      if (docs[0].correlation) throw new SigmaError("This is a correlation rule. Correlation rules aggregate other rules over time and are not supported here.");
      throw new SigmaError("No detection block found.");
    }
    rule.__extraDocs = extra.length;
    return rule;
  }

  /* ---------------- values and patterns ---------------- */

  // Sigma escapes: \* \? \\ are literals; any other backslash is itself.
  // Returns tokens: {t:"lit", v} | {t:"star"} | {t:"q"}
  function tokens(str) {
    var out = [], buf = "";
    for (var i = 0; i < str.length; i++) {
      var c = str[i];
      if (c === "\\" && i + 1 < str.length && (str[i + 1] === "*" || str[i + 1] === "?" || str[i + 1] === "\\")) { buf += str[i + 1]; i++; continue; }
      if (c === "*" || c === "?") { if (buf) out.push({ t: "lit", v: buf }); buf = ""; out.push({ t: c === "*" ? "star" : "q" }); continue; }
      buf += c;
    }
    if (buf) out.push({ t: "lit", v: buf });
    // merge runs of stars
    return out.filter(function (tk, i) { return !(tk.t === "star" && out[i - 1] && out[i - 1].t === "star"); });
  }
  function litTokens(str) { return str === "" ? [] : [{ t: "lit", v: str }]; }
  function reEsc(s) { return s.replace(/[.*+?^${}()|[\]\\\/]/g, "\\$&"); }

  // Classify a token list for converters: eq / contains / startswith / endswith / wildcard
  function shape(tk) {
    var lits = tk.filter(function (x) { return x.t === "lit"; });
    var hasQ = tk.some(function (x) { return x.t === "q"; });
    if (!hasQ) {
      if (tk.length === 0) return { op: "eq", v: "" };
      if (tk.length === 1 && tk[0].t === "star") return { op: "any" };
      if (tk.length === 1 && lits.length === 1) return { op: "eq", v: lits[0].v };
      if (tk.length === 3 && tk[0].t === "star" && tk[1].t === "lit" && tk[2].t === "star") return { op: "contains", v: tk[1].v };
      if (tk.length === 2 && tk[0].t === "lit" && tk[1].t === "star") return { op: "startswith", v: tk[0].v };
      if (tk.length === 2 && tk[0].t === "star" && tk[1].t === "lit") return { op: "endswith", v: tk[1].v };
    }
    return { op: "wildcard" };
  }

  function utf16(s, be) {
    var out = "";
    for (var i = 0; i < s.length; i++) {
      var c = s.charCodeAt(i), lo = String.fromCharCode(c & 255), hi = String.fromCharCode(c >> 8);
      out += be ? hi + lo : lo + hi;
    }
    return out;
  }
  function utf8bytes(s) { return unescape(encodeURIComponent(s)); }
  function b64(bin) { return typeof btoa === "function" ? btoa(bin) : Buffer.from(bin, "binary").toString("base64"); }
  function base64offset(bin) {
    var starts = [0, 2, 3], ends = [null, -3, -2], out = [];
    for (var i = 0; i < 3; i++) {
      var enc = b64(new Array(i + 1).join(" ") + bin), end = ends[(bin.length + i) % 3];
      out.push(end === null ? enc.slice(starts[i]) : enc.slice(starts[i], end));
    }
    return out;
  }

  /* ---------------- compile ---------------- */

  function splitKey(key) {
    var parts = String(key).split("|");
    return { field: parts[0], mods: parts.slice(1).map(function (m) { return m.trim().toLowerCase(); }) };
  }

  // One field (or keyword) item -> leaf node
  function leaf(field, mods, rawValues, ctx, idName) {
    var unknown = mods.filter(function (m) { return KNOWN_MODS.indexOf(m) < 0; });
    if (unknown.length) {
      unknown.forEach(function (m) {
        ctx.errors.push("Unknown modifier |" + m + (WRONG_MODS[m] ? ", did you mean " + WRONG_MODS[m] + "?" : "") + " in " + idName + ".");
      });
    }
    var has = function (m) { return mods.indexOf(m) >= 0; };
    if (has("expand")) ctx.unsupported.push("|expand placeholders (" + (field || "keyword") + ") need a pipeline that fills %placeholders%; that value never matches here.");
    var values = Array.isArray(rawValues) ? rawValues : [rawValues];
    if (!values.length) ctx.errors.push("Empty value list for " + (field || "keywords") + " in " + idName + ".");
    var node = { type: "leaf", field: field || null, mods: mods, all: has("all"), id: idName, specs: [] };
    var cased = has("cased");

    values.forEach(function (v) {
      if (has("exists")) { node.specs.push({ op: "exists", v: v === true || String(v).toLowerCase() === "true" }); return; }
      if (v === null) { node.specs.push({ op: "null" }); return; }
      if (has("gt") || has("gte") || has("lt") || has("lte")) {
        var num = Number(v); if (isNaN(num)) ctx.errors.push("Non-numeric value for |gt/|lt on " + field + ".");
        node.specs.push({ op: has("gt") ? "gt" : has("gte") ? "gte" : has("lt") ? "lt" : "lte", v: num }); return;
      }
      if (has("cidr")) { var c = parseCidr(String(v)); if (!c) ctx.errors.push("Bad CIDR " + v + " on " + field + "."); node.specs.push({ op: "cidr", v: String(v), cidr: c }); return; }
      if (has("fieldref")) {
        node.specs.push({ op: "fieldref", v: String(v), sub: has("contains") ? "contains" : has("startswith") ? "startswith" : has("endswith") ? "endswith" : "eq", cased: cased }); return;
      }
      if (has("re")) {
        var flags = (has("i") ? "i" : "") + (has("m") ? "m" : "") + (has("s") ? "s" : "");
        var src = String(v), rx = null;
        try { rx = new RegExp(src.replace(/^\(\?([ims]+)\)/, function (_, f) { flags += f.replace(/[^ims]/g, ""); return ""; }), Array.from(new Set(flags.split(""))).join("")); }
        catch (e) { ctx.errors.push("Regex does not compile in " + idName + ": " + e.message); }
        node.specs.push({ op: "re", v: src, flags: flags, rx: rx }); return;
      }
      // plain string path
      var s = typeof v === "boolean" || typeof v === "number" ? String(v) : String(v);
      var variants = [s];
      if (has("windash")) variants = windash(s);
      var transformed = has("base64") || has("base64offset") || has("wide") || has("utf16le") || has("utf16be") || has("utf16");
      variants.forEach(function (sv) {
        var tk;
        if (transformed) {
          var bin = has("wide") || has("utf16le") ? utf16(sv, false) : has("utf16be") ? utf16(sv, true) : has("utf16") ? "\xff\xfe" + utf16(sv, false) : utf8bytes(sv);
          var encs = has("base64offset") ? base64offset(bin) : has("base64") ? [b64(bin)] : [bin];
          encs.forEach(function (enc) { pushPlain(node, litTokens(enc), mods, true); });
          return;
        }
        tk = tokens(sv);
        pushPlain(node, tk, mods, cased);
      });
    });
    return node;
  }
  function pushPlain(node, tk, mods, cased) {
    var has = function (m) { return mods.indexOf(m) >= 0; };
    if (has("contains")) tk = [{ t: "star" }].concat(tk, [{ t: "star" }]);
    else if (has("startswith")) tk = tk.concat([{ t: "star" }]);
    else if (has("endswith")) tk = [{ t: "star" }].concat(tk);
    tk = tk.filter(function (x, i) { return !(x.t === "star" && tk[i - 1] && tk[i - 1].t === "star"); });
    var body = tk.map(function (x) { return x.t === "lit" ? reEsc(x.v) : x.t === "star" ? "[\\s\\S]*" : "[\\s\\S]"; }).join("");
    var sh = shape(tk);
    node.specs.push({ op: "pattern", tk: tk, shape: sh, cased: !!cased, rx: new RegExp("^" + body + "$", cased ? "" : "i"), keywordRx: new RegExp(body.replace(/^(\[\\s\\S\]\*)?/, "").replace(/(\[\\s\\S\]\*)?$/, ""), cased ? "" : "i") });
  }
  function windash(s) {
    var out = {};
    DASHES.forEach(function (d) { out[s.replace(/(^|\s)[-\/\u2013\u2014\u2015]/g, "$1" + d)] = 1; });
    return Object.keys(out);
  }

  function compileIdentifier(name, def, ctx) {
    if (def === null || def === undefined) { ctx.errors.push("Search identifier " + name + " is empty."); return { type: "or", children: [] }; }
    if (Array.isArray(def)) {
      if (def.every(function (x) { return x === null || typeof x !== "object"; })) {
        // keyword list
        return { type: "or", children: [leaf(null, [], def, ctx, name)], keyword: true };
      }
      return { type: "or", children: def.map(function (item) { return typeof item === "object" && item !== null ? compileMap(name, item, ctx) : leaf(null, [], [item], ctx, name); }) };
    }
    if (typeof def === "object") return compileMap(name, def, ctx);
    return leaf(null, [], [def], ctx, name);
  }
  function compileMap(name, map, ctx) {
    var keys = Object.keys(map);
    if (!keys.length) ctx.errors.push("Search identifier " + name + " has no fields.");
    return {
      type: "and", children: keys.map(function (k) {
        var sk = splitKey(k);
        ctx.fields[sk.field] = 1;
        var n = leaf(sk.field, sk.mods, map[k], ctx, name);
        if (sk.mods.indexOf("fieldref") >= 0) [].concat(map[k]).forEach(function (f) { ctx.fields[String(f)] = 1; });
        return n;
      })
    };
  }

  /* condition parser */
  function lexCond(s) {
    var out = [], re = /\s*(\(|\)|[A-Za-z0-9_*\-.]+|\|.*$)/g, m, pos = 0;
    s = String(s);
    while (pos < s.length) {
      re.lastIndex = pos;
      m = re.exec(s);
      if (!m || m.index !== pos) {
        if (/^\s+$/.test(s.slice(pos))) break;
        throw new SigmaError("Cannot read the condition near: " + s.slice(pos, pos + 20));
      }
      out.push(m[1]); pos = re.lastIndex;
    }
    return out;
  }
  function parseCondition(cond, ids, ctx) {
    var pipe = cond.indexOf("|");
    if (pipe >= 0) {
      ctx.unsupported.push("The aggregation \"" + cond.slice(pipe).trim() + "\" is deprecated Sigma syntax; only the part before | is evaluated. Rewrite it as a correlation rule.");
      cond = cond.slice(0, pipe);
    }
    var tk = lexCond(cond), i = 0;
    function peek() { return tk[i] && tk[i].toLowerCase(); }
    function expr() { var n = and(); var kids = [n]; while (peek() === "or") { i++; kids.push(and()); } return kids.length > 1 ? { type: "or", children: kids } : n; }
    function and() { var n = not(); var kids = [n]; while (peek() === "and") { i++; kids.push(not()); } return kids.length > 1 ? { type: "and", children: kids } : n; }
    function not() { if (peek() === "not") { i++; return { type: "not", children: [not()] }; } return prim(); }
    function prim() {
      var t = tk[i];
      if (t === undefined) throw new SigmaError("The condition ends too early.");
      if (t === "(") { i++; var n = expr(); if (tk[i] !== ")") throw new SigmaError("A bracket in the condition is not closed."); i++; return n; }
      if (/^(\d+|all|any)$/i.test(t) && tk[i + 1] && tk[i + 1].toLowerCase() === "of") {
        var q = t.toLowerCase(); i += 2;
        var pat = tk[i++];
        if (!pat) throw new SigmaError("\"" + q + " of\" needs a pattern or them.");
        var names = pat.toLowerCase() === "them" ? ids.filter(function (x) { return x[0] !== "_"; }) : ids.filter(globMatch(pat));
        if (!names.length) ctx.errors.push("\"" + q + " of " + pat + "\" matches no search identifier.");
        names.forEach(function (x) { ctx.used[x] = 1; });
        var kids = names.map(function (x) { return { type: "id", name: x }; });
        if (q === "all") return { type: "and", children: kids, of: q + " of " + pat };
        var nq = q === "any" ? 1 : parseInt(q, 10);
        if (nq === 1) return { type: "or", children: kids, of: q + " of " + pat };
        return { type: "nof", n: nq, children: kids, of: q + " of " + pat };
      }
      if (/^(and|or|not|\))$/i.test(t)) throw new SigmaError("Unexpected \"" + t + "\" in the condition.");
      i++;
      if (ids.indexOf(t) < 0) { ctx.errors.push("The condition uses " + t + ", which is not defined in detection."); return { type: "id", name: t, missing: true }; }
      ctx.used[t] = 1;
      return { type: "id", name: t };
    }
    var n = expr();
    if (i < tk.length) throw new SigmaError("Unexpected \"" + tk[i] + "\" in the condition.");
    return n;
  }
  function globMatch(pat) {
    var rx = new RegExp("^" + pat.split("*").map(reEsc).join(".*") + "$");
    return function (x) { return rx.test(x); };
  }

  function compile(rule) {
    var ctx = { errors: [], unsupported: [], used: {}, fields: {} };
    var det = rule.detection || {};
    var ids = Object.keys(det).filter(function (k) { return k !== "condition" && k !== "timeframe"; });
    var defs = {};
    ids.forEach(function (k) { defs[k] = compileIdentifier(k, det[k], ctx); });
    if (det.timeframe) ctx.unsupported.push("timeframe: " + det.timeframe + " belongs to the deprecated aggregation syntax and is ignored.");
    var conds = det.condition;
    if (conds === undefined || conds === null || conds === "") { ctx.errors.push("detection has no condition."); conds = []; }
    conds = Array.isArray(conds) ? conds : [conds];
    var trees = [];
    conds.forEach(function (c) {
      try { trees.push(parseCondition(String(c), ids, ctx)); } catch (e) { ctx.errors.push(e.message); }
    });
    var tree = trees.length === 1 ? trees[0] : { type: "or", children: trees };
    // inline identifiers
    function inline(n) {
      if (n.type === "id") return { type: "id", name: n.name, missing: n.missing, child: defs[n.name] || { type: "or", children: [] } };
      if (n.children) return Object.assign({}, n, { children: n.children.map(inline) });
      return n;
    }
    var ast = inline(tree);
    var unused = ids.filter(function (k) { return !ctx.used[k]; });
    return { rule: rule, ast: ast, defs: defs, ids: ids, unused: unused, errors: ctx.errors, unsupported: ctx.unsupported, fields: Object.keys(ctx.fields).filter(Boolean) };
  }

  /* ---------------- matching ---------------- */

  // All values at a dotted path. Exact flat key first, then nested walk; arrays fan out.
  function getValues(ev, path) {
    if (ev == null || typeof ev !== "object") return [];
    if (Object.prototype.hasOwnProperty.call(ev, path)) return flat(ev[path]);
    var lower = path.toLowerCase();
    for (var k in ev) if (k.toLowerCase() === lower) return flat(ev[k]);
    var parts = path.split("."), cur = [ev];
    for (var p = 0; p < parts.length; p++) {
      // try joining the remaining parts as one flat key at this level
      var rest = parts.slice(p).join("."), next = [];
      cur.forEach(function (o) {
        if (o == null || typeof o !== "object") return;
        if (Array.isArray(o)) { o.forEach(function (x) { next.push(x); }); return; }
        var key = findKey(o, parts[p]);
        if (key !== null) next.push(o[key]);
      });
      cur = [];
      next.forEach(function (x) { if (Array.isArray(x)) x.forEach(function (y) { cur.push(y); }); else cur.push(x); });
      if (!cur.length) return [];
    }
    return cur.filter(function (x) { return x !== undefined; });
  }
  function findKey(o, k) {
    if (Object.prototype.hasOwnProperty.call(o, k)) return k;
    var l = k.toLowerCase();
    for (var x in o) if (x.toLowerCase() === l) return x;
    return null;
  }
  function flat(v) { return Array.isArray(v) ? v : [v]; }
  function str(v) { return v === null || v === undefined ? null : typeof v === "object" ? JSON.stringify(v) : String(v); }
  function allStrings(ev, out) {
    out = out || [];
    if (ev === null || ev === undefined) return out;
    if (typeof ev === "object") { for (var k in ev) if (k !== "_expect") allStrings(ev[k], out); }
    else out.push(String(ev));
    return out;
  }

  function specMatch(spec, vals, ev, keyword) {
    switch (spec.op) {
      case "null": return !vals.length || vals.every(function (v) { return v === null || v === undefined; });
      case "exists": var ex = vals.some(function (v) { return v !== null && v !== undefined; }); return spec.v ? ex : !ex;
      case "gt": case "gte": case "lt": case "lte":
        return vals.some(function (v) { var n = Number(v); if (v === null || v === "" || isNaN(n)) return false; return spec.op === "gt" ? n > spec.v : spec.op === "gte" ? n >= spec.v : spec.op === "lt" ? n < spec.v : n <= spec.v; });
      case "cidr": return !!spec.cidr && vals.some(function (v) { return inCidr(str(v), spec.cidr); });
      case "re": return !!spec.rx && vals.some(function (v) { var s = str(v); return s !== null && spec.rx.test(s); });
      case "fieldref":
        var refs = getValues(ev, spec.v).map(str).filter(function (x) { return x !== null; });
        return vals.some(function (v) {
          var s = str(v); if (s === null) return false;
          return refs.some(function (r) {
            var a = spec.cased ? s : s.toLowerCase(), b = spec.cased ? r : r.toLowerCase();
            return spec.sub === "contains" ? a.indexOf(b) >= 0 : spec.sub === "startswith" ? a.indexOf(b) === 0 : spec.sub === "endswith" ? a.slice(-b.length) === b : a === b;
          });
        });
      case "pattern":
        var rx = keyword ? spec.keywordRx : spec.rx;
        return vals.some(function (v) { var s = str(v); return s !== null && rx.test(s); });
    }
    return false;
  }
  function leafMatch(n, ev) {
    var vals = n.field === null ? allStrings(ev) : getValues(ev, n.field);
    var keyword = n.field === null;
    if (n.all) return n.specs.every(function (sp) { return specMatch(sp, vals, ev, keyword); });
    return n.specs.some(function (sp) { return specMatch(sp, vals, ev, keyword); });
  }
  function evalNode(n, ev, hits) {
    switch (n.type) {
      case "leaf": return leafMatch(n, ev);
      case "and": return n.children.every(function (c) { return evalNode(c, ev, hits); });
      case "or": return n.children.some(function (c) { return evalNode(c, ev, hits); });
      case "not": return !evalNode(n.children[0], ev, null);
      case "nof": var k = 0; n.children.forEach(function (c) { if (evalNode(c, ev, hits)) k++; }); return k >= n.n;
      case "id": var r = evalNode(n.child, ev, null); if (hits && r) hits[n.name] = 1; return r;
    }
    return false;
  }
  function match(compiled, ev) {
    var hits = {};
    var ok = evalNode(compiled.ast, ev, hits);
    // which identifiers are true at all, for the evidence view (negated filters included)
    var truth = {};
    compiled.ids.forEach(function (k) { truth[k] = evalNode(compiled.defs[k], ev, null); });
    return { match: ok, ids: Object.keys(hits), truth: truth };
  }

  /* ---------------- CIDR ---------------- */
  function parseIp(s) {
    s = String(s || "").trim();
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(s)) {
      var p = s.split(".").map(Number); if (p.some(function (x) { return x > 255; })) return null;
      return { v: 4, b: p };
    }
    if (s.indexOf(":") >= 0) {
      var m = s.match(/^(.*):(\d{1,3}(?:\.\d{1,3}){3})$/), tail = [];
      if (m) { var v4 = parseIp(m[2]); if (!v4) return null; s = m[1] + ":0:0"; tail = v4.b; }
      var halves = s.split("::"); if (halves.length > 2) return null;
      var head = halves[0] ? halves[0].split(":") : [], back = halves.length > 1 && halves[1] ? halves[1].split(":") : [];
      var fill = 8 - head.length - back.length; if (halves.length === 1 && fill !== 0) return null;
      var words = head.concat(new Array(Math.max(fill, 0) + 1).join("0,").split(",").slice(0, Math.max(fill, 0)), back).map(function (h) { return parseInt(h || "0", 16); });
      if (words.length !== 8 || words.some(isNaN)) return null;
      var bytes = []; words.forEach(function (w) { bytes.push(w >> 8, w & 255); });
      if (tail.length) { bytes[12] = tail[0]; bytes[13] = tail[1]; bytes[14] = tail[2]; bytes[15] = tail[3]; }
      return { v: 6, b: bytes };
    }
    return null;
  }
  function parseCidr(s) {
    var parts = s.split("/"), ip = parseIp(parts[0]); if (!ip) return null;
    var bits = parts.length > 1 ? parseInt(parts[1], 10) : ip.b.length * 8;
    if (isNaN(bits) || bits < 0 || bits > ip.b.length * 8) return null;
    return { ip: ip, bits: bits };
  }
  function inCidr(s, c) {
    var ip = parseIp(s); if (!ip || ip.v !== c.ip.v) return false;
    for (var i = 0; i < c.bits; i++) {
      var byte = i >> 3, mask = 128 >> (i & 7);
      if ((ip.b[byte] & mask) !== (c.ip.b[byte] & mask)) return false;
    }
    return true;
  }

  /* ---------------- lint ---------------- */

  // Field dictionaries for log sources where a wrong field name silently never matches.
  var SCHEMAS = {
    "aws/cloudtrail": { label: "AWS CloudTrail record", prefix: ["userIdentity.", "requestParameters.", "responseElements.", "additionalEventData.", "tlsDetails.", "resources.", "serviceEventDetails.", "insightDetails."],
      fields: ["eventVersion", "userIdentity", "eventTime", "eventSource", "eventName", "awsRegion", "sourceIPAddress", "userAgent", "errorCode", "errorMessage", "requestParameters", "responseElements", "additionalEventData", "requestID", "eventID", "readOnly", "resources", "eventType", "apiVersion", "managementEvent", "recipientAccountId", "serviceEventDetails", "sharedEventID", "vpcEndpointId", "vpcEndpointAccountId", "eventCategory", "tlsDetails", "sessionCredentialFromConsole", "edgeDeviceDetails", "insightDetails"] },
    "okta/okta": { label: "Okta System Log event", prefix: ["actor.", "client.", "outcome.", "target.", "transaction.", "debugContext.", "authenticationContext.", "securityContext.", "request."],
      fields: ["uuid", "published", "eventType", "version", "severity", "legacyEventType", "displayMessage", "actor", "client", "outcome", "target", "transaction", "debugContext", "authenticationContext", "securityContext", "request"] },
    "windows/process_creation": { label: "Windows process creation event", prefix: [],
      fields: ["Image", "CommandLine", "ParentImage", "ParentCommandLine", "OriginalFileName", "User", "IntegrityLevel", "CurrentDirectory", "Hashes", "Product", "Company", "Description", "FileVersion", "ProcessId", "ParentProcessId", "ProcessGuid", "ParentProcessGuid", "LogonId", "LogonGuid", "ParentUser", "TerminalSessionId", "UtcTime", "RuleName", "md5", "sha1", "sha256", "Imphash", "Provider_Name", "EventID"] },
    "github/audit": { label: "GitHub audit log event", prefix: ["config.", "actor_location.", "data."],
      fields: ["action", "actor", "actor_id", "actor_location", "org", "org_id", "repo", "repository", "repository_public", "user", "user_id", "created_at", "@timestamp", "_document_id", "business", "business_id", "operation_type", "public_repo", "visibility", "name", "hook_id", "config", "events", "team", "permission", "transport_protocol_name", "transport_protocol", "external_identity_nameid", "external_identity_username", "hashed_token", "programmatic_access_type", "token_scopes", "token_id", "reason", "user_agent", "request_id", "data"] }
  };
  function schemaFor(ls) {
    if (!ls) return null;
    var p = String(ls.product || "").toLowerCase(), s = String(ls.service || "").toLowerCase(), c = String(ls.category || "").toLowerCase();
    if (p === "aws" && s === "cloudtrail") return SCHEMAS["aws/cloudtrail"];
    if (p === "okta") return SCHEMAS["okta/okta"];
    if (p === "windows" && c === "process_creation") return SCHEMAS["windows/process_creation"];
    if (p === "github" && s === "audit") return SCHEMAS["github/audit"];
    return null;
  }
  function fieldKnown(sc, f) {
    if (sc.fields.some(function (x) { return x.toLowerCase() === f.toLowerCase(); })) return true;
    return sc.prefix.some(function (p) { return f.toLowerCase().indexOf(p.toLowerCase()) === 0; });
  }

  function lint(text) {
    var out = { errors: [], warnings: [], info: [], rule: null, compiled: null };
    var rule;
    try { rule = parse(text); } catch (e) { out.errors.push(e.message); return out; }
    out.rule = rule;
    var c = compile(rule); out.compiled = c;
    c.errors.forEach(function (e) { out.errors.push(e); });
    c.unsupported.forEach(function (e) { out.warnings.push(e); });
    if (rule.__extraDocs) out.info.push("Only the first rule in this file is used; " + rule.__extraDocs + " more YAML document(s) were skipped.");
    if (!rule.title) out.warnings.push("title is missing.");
    else if (String(rule.title).length > 110) out.warnings.push("title is longer than 110 characters, the SigmaHQ limit.");
    if (!rule.id) out.warnings.push("id is missing. Every rule needs a UUID so it can be versioned and referenced.");
    else if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(String(rule.id))) out.warnings.push("id is not a UUID.");
    if (!rule.status) out.warnings.push("status is missing (experimental, test or stable).");
    else if (STATUSES.indexOf(String(rule.status)) < 0) out.warnings.push("status \"" + rule.status + "\" is not one of " + STATUSES.join(", ") + ".");
    if (!rule.level) out.warnings.push("level is missing.");
    else if (LEVELS.indexOf(String(rule.level)) < 0) out.warnings.push("level \"" + rule.level + "\" is not one of " + LEVELS.join(", ") + ".");
    if (!rule.description) out.warnings.push("description is missing. Analysts read it first when the alert fires.");
    if (!rule.logsource || typeof rule.logsource !== "object") out.errors.push("logsource is missing, so no backend knows where to run the rule.");
    else if (!rule.logsource.product && !rule.logsource.category && !rule.logsource.service) out.errors.push("logsource needs at least one of product, category or service.");
    if (!rule.falsepositives) out.warnings.push("falsepositives is missing. Name the benign activity that looks like this, or write Unknown.");
    if (rule.date && !/^\d{4}-\d{2}-\d{2}$/.test(String(rule.date instanceof Date ? rule.date.toISOString().slice(0, 10) : rule.date))) out.warnings.push("date should be YYYY-MM-DD.");
    if (rule.modified && !/^\d{4}-\d{2}-\d{2}$/.test(String(rule.modified instanceof Date ? rule.modified.toISOString().slice(0, 10) : rule.modified))) out.warnings.push("modified should be YYYY-MM-DD.");
    var tags = Array.isArray(rule.tags) ? rule.tags : rule.tags ? [rule.tags] : [];
    var attack = tags.filter(function (t) { return /^attack\./i.test(t); });
    if (!attack.length) out.warnings.push("No attack.* tags, so the rule counts for nothing in ATT&CK coverage.");
    tags.forEach(function (t) {
      t = String(t);
      if (/^attack\./i.test(t)) {
        var rest = t.slice(7);
        if (t !== t.toLowerCase()) out.warnings.push("Tag " + t + " should be lowercase.");
        else if (!/^(t\d{4}(\.\d{3})?|g\d{4}|s\d{4}|ta\d{4})$/.test(rest) && TACTICS.indexOf(rest) < 0) out.warnings.push("Tag " + t + " is neither a technique id nor an ATT&CK tactic name.");
      }
    });
    if (attack.length && !attack.some(function (t) { return /^attack\.t\d{4}/i.test(t); })) out.warnings.push("The ATT&CK tags name a tactic but no technique id.");
    c.unused.forEach(function (k) { out.warnings.push("Search identifier " + k + " is defined but the condition never uses it."); });
    // filters swallowed by "them"
    (function walk(n) {
      if (!n) return;
      if (n.of && /them$/.test(n.of) && n.children.some(function (k) { return /^filter/i.test(k.name); })) out.errors.push("\"" + n.of + "\" includes the filter identifiers, so the filters select events instead of excluding them.");
      (n.children || []).forEach(walk);
    })(c.ast);
    // value smells
    Object.keys(c.defs).forEach(function (k) {
      (function walk(n) {
        if (n.type === "leaf") {
          if (n.mods.indexOf("contains") >= 0 && n.specs.some(function (s) { return s.tk && s.tk.length >= 3 && s.tk[1].t === "star"; })) out.warnings.push(k + ": " + n.field + "|contains already wraps the value in wildcards; the extra * is redundant.");
          if (n.specs.some(function (s) { return s.shape && s.shape.op === "any"; })) out.warnings.push(k + ": " + (n.field || "keyword") + " is \"*\", which matches any value. Use |exists: true to say the field must be present.");
          if (n.all && n.specs.length < 2) out.warnings.push(k + ": |all with a single value does nothing.");
          if (n.field && /\s$/.test(n.field)) out.errors.push(k + ": field name \"" + n.field + "\" ends in a space.");
          if (n.mods.indexOf("re") >= 0 && n.specs.some(function (s) { return /^\.\*|\.\*$/.test(s.v); })) out.info.push(k + ": a leading or trailing .* in a regex is unnecessary; |re matches anywhere in the value.");
        }
        (n.children || []).forEach(walk);
      })(c.defs[k]);
    });
    var sc = schemaFor(rule.logsource);
    if (sc) {
      var bad = c.fields.filter(function (f) { return !fieldKnown(sc, f); });
      bad.forEach(function (f) { out.warnings.push("Field " + f + " is not in the " + sc.label + " schema, so it will never match raw logs. Check the spelling or the field mapping."); });
      if (!bad.length) out.info.push("Every field exists in the " + sc.label + " schema.");
    } else if (rule.logsource) out.info.push("No field dictionary for this log source, so field names were not checked.");
    return out;
  }

  /* ---------------- entities and structured alerts ---------------- */

  var ENTITY_FIELDS = {
    user: ["userIdentity.arn", "userIdentity.userName", "actor.alternateId", "userPrincipalName", "UserPrincipalName", "User", "user", "actor", "protoPayload.authenticationInfo.principalEmail", "data.protoPayload.authenticationInfo.principalEmail", "Initiated By", "InitiatedBy.user.userPrincipalName"],
    ip: ["sourceIPAddress", "client.ipAddress", "ipAddress", "IPAddress", "src_ip", "SourceIp", "actor_ip", "protoPayload.requestMetadata.callerIp", "data.protoPayload.requestMetadata.callerIp"],
    host: ["Computer", "Hostname", "host.name", "hostname", "ComputerName"],
    process: ["Image", "process.executable"],
    commandLine: ["CommandLine", "process.command_line"],
    cloudAccount: ["recipientAccountId", "userIdentity.accountId", "org"],
    region: ["awsRegion"],
    time: ["eventTime", "published", "createdDateTime", "TimeGenerated", "UtcTime", "@timestamp", "created_at", "timestamp"]
  };
  function entities(ev) {
    var out = {};
    Object.keys(ENTITY_FIELDS).forEach(function (k) {
      for (var i = 0; i < ENTITY_FIELDS[k].length; i++) {
        var v = getValues(ev, ENTITY_FIELDS[k][i]).filter(function (x) { return x !== null && x !== undefined && typeof x !== "object"; });
        if (v.length) { out[k] = k === "time" && typeof v[0] === "number" ? new Date(v[0] * (v[0] < 1e12 ? 1000 : 1)).toISOString() : String(v[0]); break; }
      }
    });
    return out;
  }
  function fieldsOfId(def) {
    var out = [];
    (function walk(n) { if (n.type === "leaf" && n.field) out.push(n.field); (n.children || []).forEach(walk); })(def);
    return out;
  }
  function alert(compiled, ev, res, index) {
    var r = compiled.rule, tags = [].concat(r.tags || []);
    var ev2 = {};
    res.ids.forEach(function (k) { fieldsOfId(compiled.defs[k]).forEach(function (f) { var v = getValues(ev, f); if (v.length) ev2[f] = v.length === 1 ? v[0] : v; }); });
    return {
      rule: { id: r.id || null, title: r.title || null, level: r.level || null, status: r.status || null },
      attack: tags.filter(function (t) { return /^attack\.t\d{4}/i.test(t); }).map(function (t) { return t.slice(7).toUpperCase(); }),
      tactics: tags.filter(function (t) { return TACTICS.indexOf(String(t).slice(7)) >= 0; }).map(function (t) { return t.slice(7); }),
      event_index: index,
      entities: entities(ev),
      matched: res.ids,
      evidence: ev2,
      falsepositives: [].concat(r.falsepositives || []),
      references: [].concat(r.references || [])
    };
  }

  /* ---------------- conversion ---------------- */

  var SENTINEL = {
    "aws/cloudtrail": { table: "AWSCloudTrail", map: { eventName: "EventName", eventSource: "EventSource", sourceIPAddress: "SourceIpAddress", userAgent: "UserAgent", errorCode: "ErrorCode", errorMessage: "ErrorMessage", awsRegion: "AWSRegion", recipientAccountId: "RecipientAccountId", eventType: "EventTypeName", readOnly: "ReadOnly", "userIdentity.type": "UserIdentityType", "userIdentity.arn": "UserIdentityArn", "userIdentity.userName": "UserIdentityUserName", "userIdentity.accountId": "UserIdentityAccountId", "userIdentity.principalId": "UserIdentityPrincipalid", "userIdentity.accessKeyId": "UserIdentityAccessKeyId", "userIdentity.invokedBy": "UserIdentityInvokedBy", "userIdentity.sessionContext.sessionIssuer.userName": "SessionIssuerUserName", "userIdentity.sessionContext.attributes.mfaAuthenticated": "SessionMfaAuthenticated", requestParameters: "RequestParameters", responseElements: "ResponseElements", additionalEventData: "AdditionalEventData" }, json: { requestParameters: "RequestParameters", responseElements: "ResponseElements", additionalEventData: "AdditionalEventData" } },
    "windows/process_creation": { table: "DeviceProcessEvents", map: { Image: "FolderPath", CommandLine: "ProcessCommandLine", ParentImage: "InitiatingProcessFolderPath", ParentCommandLine: "InitiatingProcessCommandLine", OriginalFileName: "ProcessVersionInfoOriginalFileName", User: "AccountName", IntegrityLevel: "ProcessIntegrityLevel", Company: "ProcessVersionInfoCompanyName", Product: "ProcessVersionInfoProductName", Description: "ProcessVersionInfoFileDescription", ProcessId: "ProcessId", ParentProcessId: "InitiatingProcessId", md5: "MD5", sha1: "SHA1", sha256: "SHA256" } },
    "azure/signinlogs": { table: "SigninLogs", map: {} },
    "azure/auditlogs": { table: "AuditLogs", map: {} },
    "azure/activitylogs": { table: "AzureActivity", map: {} },
    "m365/threat_management": { table: "OfficeActivity", map: {} },
    "okta/okta": { table: "OktaV2_CL", map: {} }
  };
  function sentinelFor(ls) {
    ls = ls || {};
    var p = String(ls.product || "").toLowerCase(), s = String(ls.service || "").toLowerCase(), c = String(ls.category || "").toLowerCase();
    return SENTINEL[p + "/" + s] || SENTINEL[p + "/" + c] || null;
  }

  function q(s) { return '"' + String(s).replace(/\\/g, "\\\\").replace(/"/g, '\\"') + '"'; }
  function rq(s) { return '"' + String(s).replace(/"/g, '\\"') + '"'; }
  function kv(s) { return '@"' + String(s).replace(/"/g, '""') + '"'; }
  function sq(s) { return "'" + String(s).replace(/'/g, "''") + "'"; }

  function convert(compiled, target, opts) {
    opts = opts || {};
    var warn = [], notes = [];
    var ls = compiled.rule.logsource || {};
    var sentinel = target === "kql" && opts.mapFields !== false ? sentinelFor(ls) : null;
    function fname(f) {
      if (target === "kql" && sentinel) {
        if (sentinel.map[f]) return sentinel.map[f];
        var top = f.split(".")[0];
        if (sentinel.json && sentinel.json[top]) return "parse_json(" + sentinel.json[top] + ")" + f.slice(top.length).split(".").map(function (x) { return x ? "." + x : ""; }).join("");
        if (Object.keys(sentinel.map).length) warn.push("No " + sentinel.table + " column for " + f + "; it is used as written.");
      }
      if (target === "sql") return f.split(".").map(function (p) { return /^[A-Za-z_][A-Za-z0-9_]*$/.test(p) ? p : '"' + p.replace(/"/g, '""') + '"'; }).join(".");
      if (target === "kql" && !/^[A-Za-z_][A-Za-z0-9_.]*$/.test(f)) return "['" + f.replace(/'/g, "\\'") + "']";
      if (target === "lucene") return f.replace(/([\s+\-=&|><!(){}\[\]^"~*?:\\\/])/g, "\\$1");
      if (target === "spl" && /[\s"=]/.test(f)) return "'" + f + "'";
      return f;
    }
    var pipes = []; // SPL: top-level regex / fieldref go after the search

    function patText(tk, kind) {
      return tk.map(function (x) {
        if (x.t === "star") return kind === "sql" ? "%" : "*";
        if (x.t === "q") { if (kind === "spl") { warn.push("SPL has no single-character wildcard; ? became *."); return "*"; } return kind === "sql" ? "_" : "?"; }
        if (kind === "lucene") return x.v.replace(/([\s+\-=&|><!(){}\[\]^"~*?:\\\/])/g, "\\$1");
        if (kind === "sql") return x.v.replace(/([\\%_])/g, "\\$1");
        if (kind === "spl" && /\*/.test(x.v)) warn.push("SPL cannot match a literal * inside a value.");
        return x.v;
      }).join("");
    }
    function tkRegex(tk) { return tk.map(function (x) { return x.t === "lit" ? reEsc(x.v) : x.t === "star" ? ".*" : "."; }).join(""); }

    function specExpr(field, sp, keyword, top) {
      var f = field === null ? null : fname(field);
      var o = sp.op;
      if (keyword) {
        if (o !== "pattern") { warn.push("Keyword searches only support plain values here."); return null; }
        var core = sp.tk.filter(function (x, i) { return !(x.t === "star" && (i === 0 || i === sp.tk.length - 1)); });
        if (target === "spl") return q("*" + patText(core, "spl") + "*");
        if (target === "kql") { notes.push("KQL * has \"term\" matches whole terms, which differs from Sigma's substring keywords."); return "* has " + q(patText(core, "kql")); }
        if (target === "lucene") return "*" + patText(core, "lucene") + "*";
        warn.push("Keyword (full-text) search has no SQL equivalent; name the field instead."); return null;
      }
      if (o === "null") return target === "spl" ? "NOT " + f + "=*" : target === "kql" ? "isempty(" + f + ")" : target === "lucene" ? "NOT _exists_:" + f : f + " IS NULL";
      if (o === "exists") {
        var e = target === "spl" ? f + "=*" : target === "kql" ? "isnotempty(" + f + ")" : target === "lucene" ? "_exists_:" + f : f + " IS NOT NULL";
        if (sp.v) return e;
        return target === "kql" ? "isempty(" + f + ")" : target === "sql" ? f + " IS NULL" : "NOT " + e;
      }
      if (/^(gt|gte|lt|lte)$/.test(o)) {
        var sym = { gt: ">", gte: ">=", lt: "<", lte: "<=" }[o];
        return target === "lucene" ? f + ":" + sym + sp.v : f + sym + sp.v;
      }
      if (o === "cidr") {
        if (target === "spl") return f + "=" + q(sp.v);
        if (target === "kql") return (sp.cidr && sp.cidr.ip.v === 6 ? "ipv6_is_in_range(" : "ipv4_is_in_range(") + f + ", " + q(sp.v) + ")";
        if (target === "lucene") return f + ":" + q(sp.v);
        return "contains(" + sq(sp.v) + ", CAST(" + f + " AS IPADDRESS))";
      }
      if (o === "re") {
        var flagsPrefix = sp.flags.indexOf("i") >= 0 ? "(?i)" : "";
        if (target === "spl") {
          if (!top) { warn.push("A regex inside OR or NOT cannot be written as one SPL search. Split the rule or rewrite with | where match()."); return null; }
          pipes.push("| regex " + f + "=" + rq(flagsPrefix + sp.v)); return "";
        }
        if (target === "kql") return f + " matches regex " + kv(flagsPrefix + sp.v);
        if (target === "lucene") {
          if (/\\[dwsDWSb]|\(\?[=!<]|\^|\$/.test(sp.v)) warn.push("Lucene regex has no \\d, \\w, \\s, anchors or lookarounds; check the converted pattern.");
          if (flagsPrefix) warn.push("Lucene regex has no case-insensitive flag.");
          var body = sp.v.replace(/^\^/, "").replace(/\$$/, "");
          if (!/^\^/.test(sp.v)) body = ".*" + body;
          if (!/\$$/.test(sp.v)) body = body + ".*";
          return f + ":/" + body.replace(/\//g, "\\/") + "/";
        }
        return "regexp_like(" + f + ", " + sq(flagsPrefix + sp.v) + ")";
      }
      if (o === "fieldref") {
        var g = fname(sp.v);
        if (target === "spl") {
          if (!top) { warn.push("A field comparison inside OR or NOT cannot be written as one SPL search."); return null; }
          var ef = "'" + field.replace(/'/g, "\\'") + "'", eg = "'" + sp.v.replace(/'/g, "\\'") + "'";
          pipes.push("| where " + (sp.sub === "eq" ? "lower(" + ef + ")=lower(" + eg + ")" : "like(lower(" + ef + "), \"" + (sp.sub === "startswith" ? "" : "%") + "\".lower(" + eg + ").\"" + (sp.sub === "endswith" ? "" : "%") + "\")")); return "";
        }
        if (target === "kql") return sp.sub === "eq" ? f + " =~ " + g : sp.sub === "contains" ? "indexof(tolower(" + f + "), tolower(" + g + ")) >= 0" : sp.sub === "startswith" ? "indexof(tolower(" + f + "), tolower(" + g + ")) == 0" : "tolower(" + f + ") endswith tolower(" + g + ")";
        if (target === "lucene") { warn.push("Lucene cannot compare one field with another."); return null; }
        return sp.sub === "eq" ? "lower(" + f + ") = lower(" + g + ")" : sp.sub === "contains" ? "strpos(lower(" + f + "), lower(" + g + ")) > 0" : sp.sub === "startswith" ? "starts_with(lower(" + f + "), lower(" + g + "))" : "lower(" + f + ") LIKE ('%' || lower(" + g + "))";
      }
      // pattern
      var sh = sp.shape, cs = sp.cased;
      if (target === "spl") {
        if (cs) warn.push("SPL search is case-insensitive; |cased is not preserved.");
        if (sh.op === "any") return f + "=*";
        return f + "=" + q(patText(sp.tk, "spl"));
      }
      if (target === "kql") {
        if (sh.op === "any") return "isnotempty(" + f + ")";
        if (sh.op === "eq") return f + (cs ? " == " : " =~ ") + q(sh.v);
        if (sh.op === "contains") return f + (cs ? " contains_cs " : " contains ") + q(sh.v);
        if (sh.op === "startswith") return f + (cs ? " startswith_cs " : " startswith ") + q(sh.v);
        if (sh.op === "endswith") return f + (cs ? " endswith_cs " : " endswith ") + q(sh.v);
        return f + " matches regex " + kv((cs ? "" : "(?i)") + "^" + tkRegex(sp.tk) + "$");
      }
      if (target === "lucene") {
        if (sh.op === "any") return "_exists_:" + f;
        if (cs === false) notes.push("Elastic keyword fields match case-sensitively unless the mapping normalises them.");
        if (sh.op === "eq") return f + ":" + q(sh.v);
        return f + ":" + patText(sp.tk, "lucene");
      }
      // sql
      if (sh.op === "any") return f + " IS NOT NULL";
      var lf = cs ? f : "lower(" + f + ")";
      var low = function (s) { return cs ? s : s.toLowerCase(); };
      if (sh.op === "eq") return lf + " = " + sq(low(sh.v));
      return lf + " LIKE " + sq(low(patText(sp.tk, "sql"))) + " ESCAPE '\\'";
    }

    function leafExpr(n, top) {
      var keyword = n.field === null;
      var exprs = [];
      // SPL / KQL lists of plain equals fold into IN
      var plainEq = n.specs.filter(function (s) { return s.op === "pattern" && !s.cased && (target === "spl" ? true : s.shape.op === "eq"); });
      if (!keyword && !n.all && n.specs.length > 1 && plainEq.length === n.specs.length && (target === "spl" || target === "kql")) {
        var f = fname(n.field);
        if (target === "spl") return f + " IN (" + plainEq.map(function (s) { return q(patText(s.tk, "spl")); }).join(", ") + ")";
        return f + " in~ (" + plainEq.map(function (s) { return q(s.shape.v); }).join(", ") + ")";
      }
      var single = n.specs.length === 1 || n.all;
      n.specs.forEach(function (s) { var e = specExpr(n.field, s, keyword, top && single); if (e === null) exprs.push(null); else if (e !== "") exprs.push(e); });
      if (exprs.some(function (e) { return e === null; })) return null;
      if (!exprs.length) return "";
      return exprs.length === 1 ? exprs[0] : "(" + exprs.join(n.all ? " AND " : " OR ").replace(/ AND /g, target === "kql" ? " and " : " AND ").replace(/ OR /g, target === "kql" ? " or " : " OR ") + ")";
    }
    var AND = target === "kql" ? " and " : " AND ", OR = target === "kql" ? " or " : " OR ", NOT = target === "kql" ? "not" : "NOT";
    function nodeExpr(n, top) {
      switch (n.type) {
        case "leaf": return leafExpr(n, top);
        case "id": return nodeExpr(n.child, top);
        case "and":
          var a = n.children.map(function (c) {
            // SPL: "selection and not filter" where the filter is one regex or field comparison becomes a pipe
            if (target === "spl" && top && c.type === "not") {
              var lf = singleLeaf(c.children[0]);
              if (lf && (lf.specs[0].op === "re" || lf.specs[0].op === "fieldref")) {
                var sp = lf.specs[0], f = fname(lf.field);
                if (sp.op === "re") pipes.push("| regex " + f + "!=" + rq((sp.flags.indexOf("i") >= 0 ? "(?i)" : "") + sp.v));
                else { var keep = pipes.length; specExpr(lf.field, sp, false, true); var w = pipes.splice(keep, 1)[0]; pipes.push("| where NOT (" + w.slice(8) + ")"); }
                return "";
              }
            }
            return nodeExpr(c, top);
          });
          if (a.some(function (x) { return x === null; })) return null;
          a = a.filter(function (x) { return x !== ""; });
          return a.length ? (a.length === 1 ? a[0] : "(" + a.join(AND) + ")") : "";
        case "or":
          var o = n.children.map(function (c) { return nodeExpr(c, false); });
          if (o.some(function (x) { return x === null || x === ""; })) return o.some(function (x) { return x === null; }) ? null : "";
          return o.length ? (o.length === 1 ? o[0] : "(" + o.join(OR) + ")") : (target === "sql" ? "FALSE" : target === "kql" ? "false" : "NOT *");
        case "not":
          var inner = nodeExpr(n.children[0], false);
          if (inner === null || inner === "") return null;
          return target === "kql" ? "not(" + inner + ")" : NOT + " " + inner;
        case "nof":
          warn.push("\"" + n.of + "\" needs at least " + n.n + " identifiers to match; this backend gets an OR, which is broader.");
          return nodeExpr({ type: "or", children: n.children }, false);
      }
      return null;
    }
    function singleLeaf(n) {
      while (n && n.type !== "leaf") {
        if (n.type === "id") n = n.child;
        else if ((n.type === "and" || n.type === "or") && n.children.length === 1) n = n.children[0];
        else return null;
      }
      return n && n.specs.length === 1 && n.field ? n : null;
    }
    var expr = nodeExpr(compiled.ast, true);
    if (expr === null) return { ok: false, query: "", warnings: uniq(warn), notes: uniq(notes) };
    expr = String(expr).replace(/^\((.*)\)$/, function (m, inner) { return balanced(inner) ? inner : m; });
    var query;
    if (target === "spl") query = (expr || "*") + (pipes.length ? "\n" + pipes.join("\n") : "");
    else if (target === "kql") {
      var table = sentinel ? sentinel.table : "<table>";
      if (!sentinel && opts.mapFields !== false) notes.push("No Microsoft Sentinel table is mapped for this log source; replace <table> and check field names.");
      query = table + "\n| where " + (expr || "true");
      if (sentinel && sentinel.table === "AWSCloudTrail") notes.push("Field names were mapped to the AWSCloudTrail table. Nested request and response fields are read with parse_json().");
      if (sentinel && !Object.keys(sentinel.map).length) notes.push("Table name only: field names are kept as the rule writes them, so check them against your " + sentinel.table + " schema.");
      if (sentinel && sentinel.table === "DeviceProcessEvents") notes.push("Field names were mapped to Defender XDR DeviceProcessEvents. FolderPath holds the full image path.");
    } else if (target === "lucene") query = expr || "*";
    else {
      var aws = String(ls.product || "").toLowerCase() === "aws";
      query = "SELECT *\nFROM " + (aws ? "$EDS_ID" : "<table>") + "\nWHERE " + (expr || "TRUE");
      if (aws) notes.push("Written for CloudTrail Lake (replace $EDS_ID with your event data store ID). The same WHERE clause runs in Athena over a CloudTrail table.");
      else notes.push("Trino / Athena SQL. Replace <table> with your table.");
    }
    return { ok: true, query: query, warnings: uniq(warn), notes: uniq(notes) };
  }
  function balanced(s) {
    var d = 0, inq = false;
    for (var i = 0; i < s.length; i++) {
      var c = s[i];
      if (c === '"' && s[i - 1] !== "\\") inq = !inq;
      if (inq) continue;
      if (c === "(") d++; else if (c === ")") { d--; if (d < 0) return false; }
    }
    return d === 0;
  }
  function uniq(a) { return a.filter(function (x, i) { return a.indexOf(x) === i; }); }

  /* ---------------- log input ---------------- */

  // JSON array, NDJSON, a single object, or a wrapper like {"Records":[...]} / {"value":[...]}.
  function parseLogs(text) {
    text = String(text || "").trim();
    if (!text) return { events: [], format: "empty" };
    try {
      var v = JSON.parse(text);
      if (Array.isArray(v)) return { events: v, format: "JSON array" };
      if (v && typeof v === "object") {
        var wrap = ["Records", "records", "value", "events", "Events", "data", "hits"];
        for (var i = 0; i < wrap.length; i++) if (Array.isArray(v[wrap[i]])) return { events: v[wrap[i]], format: "JSON " + wrap[i] + " array" };
        if (v.hits && Array.isArray(v.hits.hits)) return { events: v.hits.hits.map(function (h) { return h._source || h; }), format: "Elasticsearch hits" };
        return { events: [v], format: "single JSON object" };
      }
    } catch (e) { /* fall through to NDJSON */ }
    var lines = text.split(/\r?\n/).filter(function (l) { return l.trim(); }), events = [], bad = 0, firstBad = 0;
    lines.forEach(function (l, i) {
      try { var o = JSON.parse(l); if (o && typeof o === "object") events.push(o); else { bad++; firstBad = firstBad || i + 1; } }
      catch (e) { bad++; firstBad = firstBad || i + 1; }
    });
    if (!events.length) return { events: [], format: "unreadable", error: "Logs must be JSON: an array, one object per line, or a {\"Records\": [...]} export." };
    return { events: events, format: "NDJSON", skipped: bad, firstBad: firstBad };
  }

  /* ---------------- SigmaHQ live index ---------------- */

  var SIGMAHQ = { list: "https://data.jsdelivr.com/v1/packages/gh/SigmaHQ/sigma@master?structure=flat", raw: "https://cdn.jsdelivr.net/gh/SigmaHQ/sigma@master/", web: "https://github.com/SigmaHQ/sigma/blob/master/" };
  var _index = null;
  function sigmahqIndex() {
    if (_index) return _index;
    _index = fetch(SIGMAHQ.list).then(function (r) { if (!r.ok) throw new Error("SigmaHQ list HTTP " + r.status); return r.json(); }).then(function (d) {
      return d.files.map(function (f) { return f.name.replace(/^\//, ""); }).filter(function (p) { return /^rules[^/]*\/.*\.ya?ml$/.test(p); });
    }).catch(function (e) { _index = null; throw e; });
    return _index;
  }
  function sigmahqRule(path) {
    // jsDelivr's listing can run ahead of its file cache; GitHub raw is the fallback.
    return fetch(SIGMAHQ.raw + path).then(function (r) { if (!r.ok) throw new Error("HTTP " + r.status); return r.text(); })
      .catch(function () { return fetch("https://raw.githubusercontent.com/SigmaHQ/sigma/master/" + path).then(function (r) { if (!r.ok) throw new Error("HTTP " + r.status + " for " + path); return r.text(); }); });
  }


  /* ---------------- autofix ---------------- */

  // Text-level repairs for the lint findings that have one right answer. Edits keep the
  // author's layout and comments; anything that needs judgement is left alone.
  function uuid() {
    if (root.crypto && root.crypto.randomUUID) return root.crypto.randomUUID();
    return "xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx".replace(/[xy]/g, function (c) { var r = Math.random() * 16 | 0; return (c === "x" ? r : (r & 3 | 8)).toString(16); });
  }
  function fix(text, today) {
    var out = String(text), applied = [], rule;
    try { rule = parse(out); } catch (e) { return { text: out, applied: [] }; }
    // 1. misspelled modifiers inside keys
    Object.keys(WRONG_MODS).forEach(function (bad) {
      var good = WRONG_MODS[bad];
      if (/^[a-z]+$/.test(good)) {
        var rx = new RegExp("\\|" + bad + "(?=[|:])", "g");
        if (rx.test(out)) { out = out.replace(rx, "|" + good); applied.push("|" + bad + " became |" + good); }
      } else if (bad === "lowercase" || bad === "nocase" || bad === "equals" || bad === "eq") {
        var rx2 = new RegExp("\\|" + bad + "(?=[|:])", "g");
        if (rx2.test(out)) { out = out.replace(rx2, ""); applied.push("Removed |" + bad + ", which Sigma does not have"); }
      }
    });
    // 2. field name case against the known schema
    var sc = schemaFor(rule.logsource);
    if (sc) {
      var c0 = compile(rule);
      c0.fields.forEach(function (f) {
        if (fieldKnown(sc, f)) {
          var exact = sc.fields.filter(function (x) { return x.toLowerCase() === f.toLowerCase(); })[0];
          if (exact && exact !== f) {
            var rx3 = new RegExp("^(\\s+)" + reEsc(f) + "(?=[|:])", "gm");
            out = out.replace(rx3, "$1" + exact); applied.push(f + " became " + exact + ", the field's real spelling");
          }
        }
      });
    }
    // 3. "1 of them" that swallows filters
    var det = rule.detection || {}, cond = typeof det.condition === "string" ? det.condition : null;
    if (cond && /\b(1|any|all) of them\b/.test(cond)) {
      var ids = Object.keys(det).filter(function (k) { return k !== "condition" && k !== "timeframe"; });
      var filters = ids.filter(function (k) { return /^filter/i.test(k); }), sels = ids.filter(function (k) { return !/^filter/i.test(k); });
      if (filters.length && sels.length) {
        var q = cond.match(/\b(1|any|all) of them\b/)[1];
        var selPart = sels.length === 1 ? sels[0] : (q === "all" ? "all of " : "1 of ") + commonGlob(sels);
        var nc = cond.replace(/\b(1|any|all) of them\b/, selPart + " and not " + (filters.length === 1 ? filters[0] : "1 of " + commonGlob(filters)));
        out = out.replace(/^(\s*condition:\s*)(['"]?)(.*?)\2\s*$/m, function (m, pre) { return pre + nc; });
        applied.push("Condition rewritten to \"" + nc + "\" so the filters exclude");
      }
    }
    // 4. attack tags in upper case
    out = out.replace(/^(\s*-\s*)(attack\.[A-Za-z0-9.\-]+)\s*$/gm, function (m, pre, tag) {
      if (tag !== tag.toLowerCase()) { applied.push(tag + " became " + tag.toLowerCase()); return pre + tag.toLowerCase(); }
      return m;
    });
    // 5. missing metadata, inserted after the title line
    var add = [];
    if (!rule.id) { add.push("id: " + uuid()); applied.push("Added a new id"); }
    if (!rule.status) { add.push("status: experimental"); applied.push("Added status: experimental"); }
    if (!rule.description) { add.push("description: " + JSON.stringify("Detects " + String(rule.title || "this activity").replace(/^detects?\s+/i, ""))); applied.push("Added a placeholder description to edit"); }
    if (!rule.date) { add.push("date: " + (today || new Date().toISOString().slice(0, 10))); applied.push("Added today's date"); }
    if (add.length) {
      if (/^title:.*$/m.test(out)) out = out.replace(/^title:.*$/m, function (m) { return m + "\n" + add.join("\n"); });
      else out = add.join("\n") + "\n" + out;
    }
    if (!rule.level) { out = out.replace(/\s*$/, "\nlevel: medium\n"); applied.push("Added level: medium"); }
    if (!rule.falsepositives) { out = out.replace(/\s*$/, "\nfalsepositives:\n  - Unknown\n"); applied.push("Added falsepositives: Unknown"); }
    return { text: out, applied: applied };
  }
  function commonGlob(names) {
    var p = names[0];
    names.forEach(function (n) { while (n.indexOf(p) !== 0) p = p.slice(0, -1); });
    return p ? p + "*" : "them";
  }

  /* ---------------- draft a rule from an event ---------------- */

  function leaves(ev, prefix, out) {
    out = out || [];
    Object.keys(ev || {}).forEach(function (k) {
      if (k === "_expect") return;
      var v = ev[k], path = prefix ? prefix + "." + k : k;
      if (v !== null && typeof v === "object" && !Array.isArray(v)) leaves(v, path, out);
      else if (Array.isArray(v)) { if (v.length && typeof v[0] !== "object") out.push({ path: path, value: v[0] }); }
      else if (v !== null && v !== undefined && v !== "") out.push({ path: path, value: v });
    });
    return out;
  }
  function guessLogsource(ev) {
    if ("eventSource" in ev && "eventName" in ev) return { product: "aws", service: "cloudtrail" };
    if ("eventType" in ev && "actor" in ev) return { product: "okta", service: "okta" };
    if ("Image" in ev && "CommandLine" in ev) return { product: "windows", category: "process_creation" };
    if ("action" in ev && ("org" in ev || "actor" in ev)) return { product: "github", service: "audit" };
    if ("userPrincipalName" in ev || "UserPrincipalName" in ev) return { product: "azure", service: "signinlogs" };
    return { product: "your_product" };
  }
  function yq(v) {
    var s = String(v);
    return /^[A-Za-z0-9_.@\-\/]+$/.test(s) && !/^(true|false|null|yes|no|on|off|~|\d+(\.\d+)?)$/i.test(s) ? s : "'" + s.replace(/\\(?=[*?\\])/g, "\\\\").replace(/([*?])/g, "\\$1").replace(/'/g, "''") + "'";
  }
  // picks: [{path, value, mode: "eq"|"contains"|"startswith"|"endswith"}]
  function draft(ev, picks, meta) {
    meta = meta || {};
    var ls = guessLogsource(ev), lines = [];
    lines.push("title: " + (meta.title || "Draft rule"), "id: " + uuid(), "status: experimental",
      "description: " + JSON.stringify(meta.description || "Drafted from one event. Generalise the values before it ships."),
      "author: " + (meta.author || "you"), "date: " + new Date().toISOString().slice(0, 10), "logsource:");
    Object.keys(ls).forEach(function (k) { lines.push("  " + k + ": " + ls[k]); });
    lines.push("detection:", "  selection:");
    picks.forEach(function (p) {
      var v = p.mode === "eq" ? p.value : String(p.value);
      lines.push("    " + p.path + (p.mode && p.mode !== "eq" ? "|" + p.mode : "") + ": " + yq(v));
    });
    lines.push("  condition: selection", "falsepositives:", "  - Unknown", "level: medium");
    return lines.join("\n") + "\n";
  }

  var api = { fix: fix, draft: draft, leaves: leaves, guessLogsource: guessLogsource, parse: parse, compile: compile, match: match, lint: lint, convert: convert, parseLogs: parseLogs, entities: entities, alert: alert, getValues: getValues,
    sigmahqIndex: sigmahqIndex, sigmahqRule: sigmahqRule, SIGMAHQ: SIGMAHQ, schemaFor: schemaFor, sentinelFor: sentinelFor, SigmaError: SigmaError, _inCidr: function (ip, c) { return inCidr(ip, parseCidr(c)); } };
  if (typeof module === "object" && module.exports) module.exports = api;
  else root.Sigma = api;
})(typeof window !== "undefined" ? window : globalThis);
