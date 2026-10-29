# Group 5 — Real-Time Network Intrusion Detection (FUSE AI-201, Module 6)

Supervised **multi-class** classification of NSL-KDD connection records into **Normal / DoS / Probe / R2L / U2R**.
Module 6 scope: demonstrate the Module 5 prototype, explain testing + deployment, and plan monitoring, support, and maintenance. **Not a production security control — decision-support prototype only.**

## 1. What this portfolio contains (Deliverable A)

| Path | Purpose |
|---|---|
| `app/app.py` | Streamlit prototype (single-record form + batch CSV upload). Run from portfolio root: `streamlit run app/app.py` |
| `api.py` | FastAPI alternative (`/health`, `/predict`, `/predict_batch`). Run: `uvicorn api:app --reload` |
| `models/nids_pipeline.joblib` | Saved preprocessing + final HistGradientBoosting model (single artifact) |
| `models/feature_meta.joblib` | Feature lists, categorical/numeric split, label order |
| `train_evaluate.py` | Full reproducible training + evaluation (writes `figures/`, `outputs/`) |
| `test_system.py` + `test_evidence.log` | 6 whole-system tests + actual run output (**6/6 passed**) |
| `app/sample_inputs.csv` | 3 demo rows (Normal-like, DoS-like, FTP login) |
| `outputs/model_comparison.csv` | Held-out KDDTest+ results for all models |
| `Dockerfile`, `requirements.txt` | Reproducible run / container deployment |
| `docs/` | Monitoring plan, testing & deployment note, retrospective (C), simulated-data statement (D), video script (B), Module 4 + 5 PDFs |
| `Capstone_Presentation_Group5.pptx` | Slide deck for the ≤10-min video |

## 2. Quick start

```bash
pip install -r requirements.txt
python test_system.py            # verify: expect 6/6 passed
streamlit run app/app.py         # prototype (portfolio root)
# alternative API:
uvicorn api:app --reload
# Docker (prototype):
docker build -t g5-nids .
docker run -p 8501:8501 g5-nids
# Docker (API instead):
docker run -p 8000:8000 g5-nids uvicorn api:app --host 0.0.0.0 --port 8000
```

CSV template: in the app, Tab 2 → "Download CSV template" (41 NSL-KDD columns). Extra columns are ignored; missing columns are rejected with a safe error.

## 3. How the prototype works (dataset → model → app)

- **Input:** 41 NSL-KDD connection features (3 categorical: `protocol_type, service, flag`; 38 numeric: durations, byte counts, login/host stats, count/rate windows).
- **Preprocessing (saved inside pipeline):** OneHotEncoder(handle_unknown="ignore") for the 3 categoricals + numeric passthrough — identical at train and serve time, so unseen services/flags degrade gracefully instead of crashing.
- **Model:** HistGradientBoosting (class_weight="balanced"), selected evidence-first over Decision Tree / Logistic Regression / tuned Random Forest on held-out KDDTest+ (n=22,544).
- **Output:** predicted category + per-class probabilities + per-record latency, with an analyst-review warning. R2L/U2R recall is weak — Normal predictions on unusual logins must be treated with care.

## 4. Results (held-out KDDTest+, honest reporting)

| Model | Acc | Macro-F1 | Weighted-F1 |
|---|---|---|---|
| Majority | 0.431 | 0.120 | 0.259 |
| Decision Tree (baseline) | 0.764 | 0.564 | 0.726 |
| Logistic Regression (baseline) | 0.761 | 0.569 | 0.716 |
| Random Forest tuned | 0.745 | 0.524 | 0.707 |
| **HistGradientBoosting (FINAL)** | **0.801** | **0.665** | **0.784** |

Per-class (final): Normal 0.71/0.97/0.82 · DoS 0.96/0.79/0.87 · Probe 0.81/0.79/0.80 · R2L 0.96/0.28/0.44 · U2R 0.66/0.28/0.40 (P/R/F1). Latency ≈ 2 ms/record (this machine; ~0.02 ms/record on training hardware — either way well within "real-time" triage budget).
Proposal targets (macro-F1 ≥ 0.80) were **not met** — expected on this novelty-heavy test set (17 test-only attack types; only 52 U2R training rows). Documented in app disclaimer, report, and video.

## 5. Testing, experiment tracking, deployment (summary — see `docs/02_Testing_Deployment.md`)

- Tests: `test_system.py` covers artifact load, single+batch prediction, probability validity, unknown/invalid input handling, latency budget, determinism. Evidence: `test_evidence.log` (6/6).
- Tracking: `train_evaluate.py` logs CV means/std, `outputs/metrics.json`, `outputs/model_comparison.csv`, confusion matrices + EDA in `figures/`. MLflow is the recommended next step (see monitoring plan) — current logging is file-based and sufficient for a prototype.
- Validation: Pydantic schema in `api.py` (ranges for rates 0–1, non-negative counts) + Streamlit widgets with bounds; missing columns / bad CSVs produce safe error messages, never silent wrong predictions.
- Deployment paths: GitHub (source of truth) → Streamlit Community Cloud (demo link) for reviewers; FastAPI + Docker for SOC integration (shown, not hosted as a live security service for this course).

## 6. Data statement (summary — see `docs/04_Simulated_Data_Statement.md`)

**No simulated or synthetic data.** Real benchmark data: NSL-KDD `KDDTrain+.txt` / `KDDTest+.txt` (detailed labels, mapped to 5 classes). Historical data — does not represent modern encrypted/cloud traffic. Must not be presented as production performance.

## 7. Group 5 members (11) — all contributed to final presentation

Wogari Ararsa · Amanuel Ayalew Arega · Eyob Daniel Asefa · Surafiel Habib Asefa · Mulatie Yeshu Asegie · Asamn Admasu Asfaw · Petros Tariku Assefa · Semegn Mulugeta Assefa · Fuad Kedir Assen · Mohammed Yassin Awel · Tenaw Workie Awoke.
Responsibilities rotated across data prep, training/evaluation, app/API build, testing, docs, and video (see video script for per-member segments).

## 8. Reviewer instructions (if no public link)

1. `pip install -r requirements.txt; python test_system.py` → expect 6/6.
2. `streamlit run app/app.py` → Tab 1: accept defaults → "Classify traffic" → expect **Normal** with high probability; Tab 2: upload `app/sample_inputs.csv` → expect 3 rows classified (Normal / DoS / Normal) + bar chart + downloadable predictions.
3. Optional: `uvicorn api:app --reload` → open `http://127.0.0.1:8000/docs` → try `/predict`.
No credentials, keys, or confidential data are included or required.
