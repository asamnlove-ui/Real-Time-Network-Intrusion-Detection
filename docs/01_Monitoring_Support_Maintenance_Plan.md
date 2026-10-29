# Monitoring, Support & Maintenance Plan (Module 6, Task 3)
**System:** Group 5 NIDS decision-support prototype (HistGradientBoosting, NSL-KDD 5-class). Prototype only — this plan describes what *would* run if adopted beyond the course.

## 1. Performance monitoring (is the model still useful?)
| Signal | How | Threshold / cadence | Action |
|---|---|---|---|
| Prediction distribution | Log every prediction (class + top probability + latency, no payload bytes); daily histogram per class | Alert if share of any class shifts >10 pp vs. validation baseline for 3 consecutive days | Analyst review; trigger data-quality check |
| Confidence profile | Track mean max-probability, % low-confidence (<0.60) predictions | Alert if low-confidence share doubles vs. baseline | Lower auto-triage; route more to manual review |
| Ground-truth evaluation | Analysts label a weekly sample (~200 records); compute accuracy, macro-F1, per-class recall — emphasis on R2L/U2R | Macro-F1 drop >0.05 or R2L/U2R recall drop >0.10 vs. release | Open retraining ticket |
| Latency & availability | p50/p95 inference ms, error rate, uptime | p95 >50 ms/record or error rate >1% over 1 h | Roll back / scale; see §2 |
| Data drift | Population Stability Index / KS tests on key numerics (src_bytes, count, serror_rate) + new-category rate for service/flag | PSI >0.2 on any top-5 feature | Evaluate new data (§3) |

Dashboard minimum: class histogram, confidence histogram, latency p50/p95, error rate, drift flags. Weekly email summary to SOC lead + model owner. No continuous production-monitoring service is operated for this course — the workflow above is the handover spec.

## 2. Error handling (find → fix → prevent)
- **App/API:** Streamlit bounds + Pydantic ranges; missing columns, wrong types, and bad CSVs return a safe, specific error (never a silent prediction). Unknown service/flag values pass through OneHot(handle_unknown="ignore").
- **Runtime taxonomy:** (a) input validation, (b) model/load failure, (c) infra (OOM, timeout). Each logged with timestamp, version, input hash (not raw sensitive fields), and stack trace.
- **Response:** critical (app down / all predictions failing) → revert to last good `nids_pipeline.joblib` (versioned artifacts) + поверх manual triage within 4 h; major (class missing / latency breach) → fix within 2 business days; minor (cosmetic) → next release.
- **Prevention:** `test_system.py` (6 tests) runs in CI on every commit; Docker image pinned by `requirements.txt`; smoke test (predict `sample_inputs.csv`) gates every release.

## 3. Data & model updates (when to retrain)
1. Collect candidate data: newly labelled analyst-reviewed connections, with attack-type → 5-class mapping revalidated.
2. Quality gate: schema check (41 columns), missing/duplicates report, label distribution vs. train (flag U2R/R2L scarcity).
3. Offline experiment: re-run `train_evaluate.py` (or MLflow-tracked equivalent); compare challenger vs. champion on a *time-sliced* holdout (not just KDDTest+). Promote only if macro-F1 improves ≥0.02 with no per-class recall regression >0.05.
4. Canary: serve challenger to 10% of traffic for 1 week; roll back on any §1 alert.
5. Versioning: `models/nids_pipeline_vYYYYMMDD.joblib` + `metrics.json` + git tag; keep last 3 champions. Quarterly review even without alerts (NSL-KDD is stale — real traffic drifts fast).

## 4. Security & responsible AI
- **Privacy:** prototype uses a public benchmark — no personal data. In any pilot: minimise logged fields (no payloads/credentials), hash identifiers, encrypt at rest/in transit, role-based access, 90-day log retention.
- **Fairness:** audit error rates by service/protocol subgroup; R2L/U2R weakness must stay visible in the UI (current disclaimer) so rare attacks are not systematically deprioritised. Never use predictions for personnel decisions.
- **Safety:** advisory-only interlock — no autonomous blocking; every output carries "analyst review required." Adversarial note: evasion via traffic shaping is out of scope for the prototype but must be threat-modelled before any real deployment.
- **Supply chain:** pinned dependencies, `pip audit` in CI, no secrets in repo (verified — none included).

## 5. Support & maintenance (who does what)
| Item | Owner | Cadence |
|---|---|---|
| Dependency bumps + `pip audit` | Maintainer | Monthly |
| Re-run full test suite + smoke predict | CI / maintainer | Every commit + weekly schedule |
| Log review + issue triage (GitHub Issues with `bug/model-drift/docs` labels) | SOC liaison + model owner | Weekly |
| Model card / README refresh | Model owner | Each release |
| Backup of versioned artifacts + rollback drill | Maintainer | Quarterly |

Known tech debt carried into maintenance: file-based experiment logs → migrate to MLflow; no calibration (probabilities are ranking scores, not calibrated risks); R2L/U2R recall gap → cost-sensitive learning / targeted data collection first.
