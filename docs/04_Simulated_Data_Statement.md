# Simulated Data Statement (Deliverable D)

**Statement: this project uses NO simulated or synthetic data.**

- **Source:** the public NSL-KDD benchmark — `KDDTrain+.txt` (training) and `KDDTest+.txt` (held-out evaluation, n=22,544), with detailed attack labels mapped to five categories (Normal / DoS / Probe / R2L / U2R). The provided `KDDTest_binary.arff` collapsed-label file was inspected and retained but not used for 5-class training.
- **What was NOT simulated:** no synthetic rows, no GAN/SMOTE-generated traffic, no mocked predictions. `app/sample_inputs.csv` contains three real-schema example rows drawn from the NSL-KDD feature format for demo purposes — their *predictions* are produced live by the trained model, not staged.
- **Caveats (disclosed, not hidden):** NSL-KDD is historical and does not represent modern encrypted, cloud, or contemporary attack traffic; KDDTest+ is novelty-heavy (17 test-only attack types). Results therefore demonstrate prototype functionality on a benchmark — they must not be presented as expected production performance.
- **Privacy/confidentiality:** no personal, organisational, or sensitive network data were used; nothing in the repository requires redaction, and no credentials or private data are included.
