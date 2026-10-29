# Testing, Deployment & Experiment Tracking (Module 6, Task 2)

## 1. Testing — what was run + evidence
`test_system.py` (run from portfolio root: `python test_system.py`), full log in `test_evidence.log`:

| # | Test | Result (this machine) |
|---|---|---|
| 1 | Model artifact loads (`nids_pipeline.joblib` has `predict`) | PASS |
| 2 | Single + batch prediction on `sample_inputs.csv` (41 cols, labels ⊆ {Normal,DoS,Probe,R2L,U2R}) | PASS — demo rows → Normal / DoS / Normal |
| 3 | `predict_proba` shape (n,5), rows sum to 1 | PASS |
| 4 | Invalid/unknown handling: unseen `service` tolerated (OneHot ignore); missing column raises safely | PASS |
| 5 | Latency budget <50 ms/record | PASS — ≈2.3 ms/record here (≈0.02 ms on training hardware) |
| 6 | Determinism: same input → same output | PASS |

**Overall: 6/6 passed.** Manual UI checks (reviewer-reproducible): Tab 1 defaults → Normal; Tab 2 upload `app/sample_inputs.csv` → 3 classified rows + bar chart + downloadable `nids_predictions.csv`; malformed CSV → safe error message.

## 2. Experiment tracking
- Prototype-scale logging (sufficient for course): `train_evaluate.py` prints per-model scores + classification reports, saves `outputs/metrics.json` (data quality, train/test distributions, CV means/std, best RF params, all test metrics, latency) and `outputs/model_comparison.csv`, plus `figures/` (train/test distributions, numeric correlations, protocol-vs-target, recall-normalised + count confusion matrices).
- Result that drove selection: HistGradientBoosting macro-F1 0.665 > Decision Tree 0.564 / LogReg 0.569 / tuned RF 0.524 → promoted as FINAL. Honest negative result: proposal macro-F1 ≥0.80 target not met (17 test-only attack types; 52 U2R train rows).
- Production recommendation: migrate to **MLflow** (`mlflow.sklearn.autolog()` + log params/metrics/artifacts per run, Model Registry champion/challenger) — specified in the monitoring plan; not operated as a live tracking server for this prototype.

## 3. How the app/API receives inputs and returns predictions
- **Streamlit (`app/app.py`):** Tab 1 form (41 widgets with bounds/defaults) → DataFrame with exact `FEATURES` column order → `pipe.predict` + `predict_proba` + ms/record → success banner (class + latency), probability bar chart + table, analyst-review warning. Tab 2: CSV upload → missing-column check → same pipeline → table (first 50) + class bar chart + `nids_predictions.csv` download. Template downloadable in-app.
- **FastAPI (`api.py`):** Pydantic `Connection` schema (rates constrained 0–1, counts ≥0) → `/predict` (single) and `/predict_batch` (list) return `{predicted_category, probabilities, caution}`; `/health` reports model + classes. Invalid bodies → HTTP 400 with safe message. Interactive docs at `/docs`.

## 4. Invalid-input & error handling
Streamlit widget bounds + Pydantic ranges catch out-of-range values at entry; pipeline-level `handle_unknown="ignore"` tolerates novel services/flags; missing columns / unreadable CSVs surface as explicit errors (see Test 4). No silent fallback predictions.

## 5. How to access / run
- **GitHub:** source of truth (push this folder); reviewer clones + `pip install -r requirements.txt`.
- **Streamlit Community Cloud:** deploy from repo (`app/app.py`, Python 3.11); share link in submission. If public hosting is unavailable, reviewers use local run (Section 8 of README) + screenshots/video.
- **Docker:** `Dockerfile` (python:3.11-slim, pinned requirements) serves Streamlit on 8501 by default or FastAPI on 8000 via override — the realistic SOC-integration path. `docker build -t g5-nids . && docker run -p 8501:8501 g5-nids`.
- No secrets/credentials anywhere; nothing to redact beyond normal review.
