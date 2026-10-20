# detections-as-code-logistics

[![detections](https://github.com/edwardtay/detections-as-code-logistics/actions/workflows/ci.yml/badge.svg)](https://github.com/edwardtay/detections-as-code-logistics/actions/workflows/ci.yml)

Thirteen detections for a freight forwarder's estate, written as Sigma 2.0 rules and treated as software: each one carries positive and negative test cases, and CI runs every case on every push. The rules cover identity (Okta), cloud (AWS CloudTrail), Kubernetes audit, endpoint, Microsoft 365, and the forwarder's own applications: customs filing, partner EDI, customer portal and payments.

The company in the data, Harbourline Forwarding, is fictional. All test records are synthetic (see [Test data](#test-data)).

## Detections

| ID | Detection | ATT&CK v19.2 | Log source | Severity | Cases |
|---|---|---|---|---|---|
| [FD-001](rules/FD-001-mfa-factor-reset-then-a-sign-in-from-a-new.yml) | MFA factor reset, then a sign-in from a new device | `T1556.006` | Okta System Log | high | 4 |
| [FD-002](rules/FD-002-push-fatigue-repeated-rejected-pushes-then-an.yml) | Push fatigue: repeated rejected pushes, then an approval | `T1621` | Okta System Log | high | 4 |
| [FD-003](rules/FD-003-password-spray-one-source-many-users.yml) | Password spray: one source, many users | `T1110.003` | Okta System Log | medium | 3 |
| [FD-004](rules/FD-004-cloudtrail-stopped-deleted-or-narrowed-by-a-non.yml) | CloudTrail stopped, deleted or narrowed by a non-IaC principal | `T1685.002` | AWS CloudTrail | high | 4 |
| [FD-005](rules/FD-005-access-key-created-for-another-iam-user.yml) | Access key created for another IAM user | `T1098.001` | AWS CloudTrail | high | 3 |
| [FD-006](rules/FD-006-bulk-reads-from-the-customs-documents-bucket-by.yml) | Bulk reads from the customs documents bucket by a new principal | `T1530` | AWS CloudTrail (S3 data events) | high | 3 |
| [FD-007](rules/FD-007-exec-into-a-production-pod-outside-a-change.yml) | exec into a production pod outside a change window | `T1609` | Kubernetes audit log | high | 4 |
| [FD-008](rules/FD-008-remote-access-tool-installed-on-a-laptop.yml) | Remote access tool installed on a laptop | `T1219` | EDR process events (OCSF) | high | 3 |
| [FD-009](rules/FD-009-mailbox-rule-forwarding-mail-outside-the-company.yml) | Mailbox rule forwarding mail outside the company | `T1114.003` | Microsoft 365 audit | medium | 3 |
| [FD-010](rules/FD-010-oauth-consent-with-mail-or-file-scopes-to-an.yml) | OAuth consent with mail or file scopes to an unreviewed app | `T1528` | Microsoft 365 audit (Entra ID) | medium | 3 |
| [FD-011](rules/FD-011-payee-bank-details-changed-within-hours-of-a.yml) | Payee bank details changed within hours of a new-device sign-in | `T1657` | Payments service + Okta | critical | 4 |
| [FD-012](rules/FD-012-sign-in-from-a-new-network-then-load-re-tender.yml) | Sign-in from a new network, then load re-tender or remit-to change | `T1078` | Okta + customer portal + EDI gateway | high | 5 |
| [FD-013](rules/FD-013-backup-or-snapshot-deletion-in-bulk.yml) | Backup or snapshot deletion in bulk | `T1490` | AWS CloudTrail | high | 3 |

Multi-step detections (for example FD-001: an MFA factor reset, then a sign-in from a device new to that user within an hour) are written as Sigma correlation rules (`temporal_ordered`, `event_count`, `value_count`) over named base rules in the same file.

## How a detection runs

1. **Enrichment.** A lookup stage adds an `enrichment` object to each raw record: the user the event is about, whether the network or device is new for that user against a 30-day baseline, verified helpdesk tickets, change windows, on-call incidents. Rules filter on these fields, for example `enrichment.verified_ticket: true` to drop helpdesk-driven MFA resets. In the test fixtures the enrichment is already applied, so each case is self-contained.
2. **Base rules.** Parsed, compiled and matched by [`engine/sigma.js`](engine/sigma.js), a Sigma 2.0 engine (modifiers, `1 of` / `all of`, field references). Rules written against Windows `process_creation` fields are mapped onto OCSF Process Activity records, the way a pySigma processing pipeline maps fields for a backend.
3. **Correlation.** [`engine/pipeline.js`](engine/pipeline.js) evaluates the Sigma correlation rules over the base-rule matches, grouped by the `group-by` fields within the `timespan`.

## CI

[`.github/workflows/ci.yml`](.github/workflows/ci.yml) runs three jobs:

- **lint and test rules** (`node scripts/test.js`): lints every base rule, checks every ATT&CK tag against the pinned v19.2 release, requires at least one positive and one negative case per detection, and runs every case. A case marked `alert` must fire; a case marked `none` must stay silent.
- **secret scan**: gitleaks over the full git history, with an allowlist limited to AWS example-form identifiers ([`.gitleaks.toml`](.gitleaks.toml)).
- **validate with pySigma and convert** (`python scripts/convert.py`): parses every file with [pySigma](https://github.com/SigmaHQ/pySigma), the reference implementation, and writes Splunk SPL and Microsoft KQL to a build artifact. Where a backend cannot convert a correlation, the base rules are converted one by one and the correlation runs in the SIEM's own syntax.

Run locally:

```sh
node scripts/test.js            # all detections
node scripts/test.js FD-004     # one detection
python -m pip install --require-hashes --no-deps -r requirements.txt
python scripts/convert.py
```

Node 18 or later; no npm dependencies.

## Adding a detection

1. Add `rules/FD-0NN-<slug>.yml`, with an `id`, `name` and `attack.tNNNN` tag on each base rule, and an entry in [`rules/index.json`](rules/index.json).
2. Add `tests/FD-0NN.json` with at least one `alert` case and one `none` case. Each case lists records as `{ id, ts, source, record }`.
3. Run `node scripts/test.js FD-0NN`. Open a pull request; CI must pass before merge.

## Test data

All records are synthetic, generated in the vendors' record shapes (Okta System Log, CloudTrail, Kubernetes `audit.k8s.io/v1`, Microsoft 365 unified audit, OCSF Process and API Activity). They use documentation-only values: IP addresses from RFC 5737 ranges, AS numbers from the RFC 5398 documentation range, `.example` domains, the AWS documentation account `111122223333` and example access key IDs. No real person, company or credential appears in them.

## Limits

- `engine/sigma.js` does not evaluate Sigma correlations on its own; `engine/pipeline.js` does, for the three types above.
- FD-005 compares two fields with `fieldref`. pySigma's Splunk and Kusto backends do not convert it yet, so it has no generated SPL or KQL.
- Thresholds and allowlists are tuned to the fictional estate. Real tuning starts from a week of shadow-mode alert counts.

## License

MIT, see [LICENSE](LICENSE). Uses js-yaml (MIT) and MITRE ATT&CK technique names (ATT&CK terms of use).

Built by [Edward Tay](https://github.com/edwardtay). Related browser tools: [pwnsy Detection Workbench](https://pwnsy.com/tools/detect/).
