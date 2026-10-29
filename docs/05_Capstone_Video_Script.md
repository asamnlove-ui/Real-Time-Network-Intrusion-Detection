# Capstone Video Script — Group 5 (≤10 min, Deliverable B)
Target: ~9 min spoken (~1,150 words). Record screen + narration; compress to <250 MB (720p). All 11 members speak; per-member lines marked.

## Slide 1 — Title (0:00–0:40) — Wogari
"Hello, we are Group 5, FUSE AI-201. Our project is Real-Time Network Intrusion Detection: a decision-support prototype that classifies a network connection as Normal, Denial-of-Service, Probe, Remote-to-Local, or User-to-Root using the NSL-KDD benchmark. Eleven members built this from proposal through implementation to the demo you will see now — and everything we claim is evidenced in our portfolio."

## Slide 2 — Problem & users (0:40–1:50) — Amanuel + Eyob
Amanuel: "SOC analysts drown in alerts. Signature and rule-based tools miss novel attacks, need constant expert upkeep, and false-alarm — they don't scale."
Eyob: "Our users are security analysts and network admins doing triage — which alert to investigate first — plus SOC staff and IT managers. Output is advisory only, never an autonomous block."

## Slide 3 — Dataset → model → app (1:50–3:20) — Surafiel + Mulatie
Surafiel: "41 NSL-KDD features per connection — 3 categorical, 38 numeric — mapped from detailed attack names to our 5 classes. No synthetic data; details in our Simulated Data Statement."
Mulatie: "One saved pipeline — one-hot for protocol/service/flag, numeric passthrough — feeding HistGradientBoosting, chosen evidence-first over tree, logistic, and tuned forest baselines."

## Slide 4 — LIVE DEMO, single record (3:20–5:00) — Asamn + Petros [screen share]
Asamn: [open app, Tab 1, defaults] "One connection in — I press Classify." [show: Predicted Normal + latency + probability chart] "Prediction plus probabilities plus latency, with an analyst-review warning."
Petros: [change service to private, flag S0, high serror_rate] "Now a scan-like record —" [show: Predicted DoS with distribution] "Same pipeline as training, so no train-serve skew."

## Slide 5 — LIVE DEMO, batch + validation (5:00–6:00) — Semegn + Fuad [screen share]
Semegn: [Tab 2, upload sample_inputs.csv] "Three rows in, three predictions out — Normal, DoS, Normal — with a bar chart and downloadable predictions."
Fuad: [upload broken CSV / pick invalid value] "Missing columns or bad values fail safely with a specific error — never a silent wrong answer. The FastAPI version enforces the same rules with Pydantic."

## Slide 6 — Testing & results (6:00–7:20) — Mohammed + Tenaw
Mohammed: "Six whole-system tests — artifact load, batch prediction, probability validity, invalid-input handling, latency, determinism — 6 of 6 passed; log in test_evidence.log."
Tenaw: "Held-out KDDTest+: accuracy 0.80, macro-F1 0.66, weighted-F1 0.78. Strong on DoS and Probe, weak on R2L and U2R — recall 0.28 each — because only 52 U2R rows trained us and 17 test attacks were unseen. We missed our 0.80 macro-F1 target and we say so openly."

## Slide 7 — Deployment (7:20–8:10) — Wogari + Amanuel [show README/Dockerfile]
Wogari: "GitHub is the source of truth; Streamlit Cloud hosts the reviewer demo; Docker reproduces either the Streamlit app or the FastAPI service — the realistic SOC path with /health, /predict, /predict_batch and interactive docs."
Amanuel: "Reviewers without a public link: pip install, run test_system.py, streamlit run app/app.py — under two minutes, no secrets needed."

## Slide 8 — Monitoring, support & maintenance (8:10–9:00) — Eyob + Surafiel
Eyob: "Beyond prototype: daily prediction and confidence histograms, weekly labelled-sample scoring, latency and drift alerts, quarterly reviews — retrain only on a time-sliced holdout with no rare-class regression, canary at 10%."
Surafiel: "Advisory-only interlock, minimal logging, pinned dependencies, versioned artifacts with rollback — and probabilities stay uncalibrated ranking scores until we calibrate them."

## Slide 9 — Reflection & future (9:00–9:40) — all (Mulatie closes)
Mulatie: "We learned baselines-first, one-artifact reproducibility, and that UX is safety engineering. Limits: rare-class recall, stale benchmark, planned-not-running monitoring. Next: calibration with a review queue, targeted R2L/U2R data, MLflow registry, and a pilot on anonymised modern traffic. Thank you — portfolio, app, tests, and statements are in our submission."

## Recording checklist
- 720p, app text legible; compress (e.g., HandBrake H.264) to <250 MB; check audio per speaker.
- Show real app + `test_evidence.log` + `model_comparison.csv` on screen at the indicated beats.
- State twice: "prototype only; no synthetic data; R2L/U2R recall limited."
