// test.js: lint every rule file, then run its positive and negative test cases through the pipeline.
// Usage: node scripts/test.js [FD-004 ...]    Exit code 1 on any failure.
"use strict";
const fs = require("fs");
const path = require("path");
const Sigma = require("../engine/sigma.js");
const P = require("../engine/pipeline.js");

const ROOT = path.join(__dirname, "..");
const ATTACK = require("../engine/attack-ids.json");
const index = JSON.parse(fs.readFileSync(path.join(ROOT, "rules/index.json"), "utf8"));
const only = process.argv.slice(2);
let failed = 0, cases = 0;
const out = (s) => process.stdout.write(s + "\n");

out(`Sigma engine lint, ATT&CK v${ATTACK.version} tag check, embedded tests`);
for (const d of index) {
  if (only.length && !only.includes(d.id)) continue;
  const text = fs.readFileSync(path.join(ROOT, d.file), "utf8");
  const problems = [];
  const cd = P.compile(text);
  problems.push(...cd.errors);

  // Lint each base rule with the engine's linter. Fields under enrichment.* come from the lookup stage.
  for (const doc of P.splitDocs(text)) {
    if (/^correlation:/m.test(doc)) continue;
    const L = Sigma.lint(doc);
    problems.push(...L.errors);
    L.warnings.filter((w) => !/^Field enrichment\./.test(w) && !/is not in the .* field list/.test(w)).forEach((w) => out(`  warn  ${d.id}: ${w}`));
  }
  // Every ATT&CK tag must exist in the pinned release, and one base rule must carry the detection's technique.
  const tags = cd.bases.flatMap((b) => b.rule.tags || []);
  for (const t of tags) {
    const m = /^attack\.(t\d{4}(?:\.\d{3})?)$/i.exec(t);
    if (m && !ATTACK.techniques[m[1].toUpperCase()]) problems.push(`tag ${t} is not in ATT&CK v${ATTACK.version}`);
  }
  if (!tags.some((t) => t.toLowerCase() === "attack." + d.technique.toLowerCase())) problems.push(`no base rule is tagged attack.${d.technique.toLowerCase()}`);
  for (const b of cd.bases) if (!b.id) problems.push(`${b.title}: no id`);

  // Test cases: "alert" must produce at least one hit, "none" must produce zero.
  const suite = JSON.parse(fs.readFileSync(path.join(ROOT, "tests", d.id + ".json"), "utf8"));
  const pos = suite.cases.filter((c) => c.expect === "alert").length, neg = suite.cases.length - pos;
  if (!pos || !neg) problems.push(`needs at least one positive and one negative case (has ${pos} and ${neg})`);
  const results = suite.cases.map((c) => {
    const n = P.hits(cd, c.events).length;
    return { name: c.name, expect: c.expect, n, pass: c.expect === "alert" ? n > 0 : n === 0 };
  });
  cases += results.length;
  const bad = results.filter((r) => !r.pass);
  const ok = !problems.length && !bad.length;
  if (!ok) failed++;
  out(`${ok ? "PASS" : "FAIL"} ${d.id} ${d.title}  tests ${results.length - bad.length}/${results.length} (${pos} positive, ${neg} negative)`);
  problems.forEach((p) => out(`  error ${p}`));
  bad.forEach((r) => out(`  case "${r.name}": expected ${r.expect}, got ${r.n} hit(s)`));
}
const ran = only.length ? index.filter((d) => only.includes(d.id)).length : index.length;
out(`\n${ran - failed}/${ran} detections passed, ${cases} test cases`);
process.exit(failed ? 1 : 0);
