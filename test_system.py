"""Group 5 — Stage-8 whole-system tests (Module 6 evidence). Run: python test_system.py"""
import time, joblib, pandas as pd

FEATURES = ["duration","protocol_type","service","flag","src_bytes","dst_bytes","land","wrong_fragment","urgent","hot",
"num_failed_logins","logged_in","num_compromised","root_shell","su_attempted","num_root","num_file_creations",
"num_shells","num_access_files","num_outbound_cmds","is_host_login","is_guest_login","count","srv_count",
"serror_rate","srv_serror_rate","rerror_rate","srv_rerror_rate","same_srv_rate","diff_srv_rate",
"srv_diff_host_rate","dst_host_count","dst_host_srv_count","dst_host_same_srv_rate","dst_host_diff_srv_rate",
"dst_host_same_src_port_rate","dst_host_srv_diff_host_rate","dst_host_serror_rate","dst_host_srv_serror_rate",
"dst_host_rerror_rate","dst_host_srv_rerror_rate"]
LABELS = {"Normal","DoS","Probe","R2L","U2R"}
results = []
def check(name, fn):
    try:
        fn(); results.append((name, True, "")); print(f"[PASS] {name}")
    except Exception as e:
        results.append((name, False, str(e))); print(f"[FAIL] {name}: {e}")

def t1():
    pipe = joblib.load("models/nids_pipeline.joblib")
    assert hasattr(pipe, "predict"), "no predict method"
def t2():
    pipe = joblib.load("models/nids_pipeline.joblib")
    df = pd.read_csv("sample_inputs.csv" if __import__("os").path.exists("sample_inputs.csv") else "app/sample_inputs.csv")
    assert list(df.columns) == FEATURES, f"column mismatch: {list(df.columns)[:3]}..."
    pred = pipe.predict(df)
    assert set(pred) <= LABELS, f"unexpected labels {set(pred)}"
def t3():
    pipe = joblib.load("models/nids_pipeline.joblib")
    df = pd.read_csv("sample_inputs.csv" if __import__("os").path.exists("sample_inputs.csv") else "app/sample_inputs.csv")
    proba = pipe.predict_proba(df)
    assert proba.shape == (len(df), 5), proba.shape
    assert abs(proba.sum(axis=1) - 1).max() < 1e-5, "probabilities do not sum to 1"
def t4():
    # invalid-input handling: unknown service + missing column must fail safely (not crash silently)
    pipe = joblib.load("models/nids_pipeline.joblib")
    df = pd.read_csv("sample_inputs.csv" if __import__("os").path.exists("sample_inputs.csv") else "app/sample_inputs.csv")
    row = df.iloc[[0]].copy(); row["service"] = "never_heard_of_this"  # OneHot(handle_unknown=ignore) must tolerate
    pred = pipe.predict(row); assert pred[0] in LABELS
    try:
        pipe.predict(df.drop(columns=["duration"])); raise AssertionError("missing column should raise")
    except (ValueError, KeyError): pass
def t5():
    pipe = joblib.load("models/nids_pipeline.joblib")
    df = pd.read_csv("sample_inputs.csv" if __import__("os").path.exists("sample_inputs.csv") else "app/sample_inputs.csv")
    t0=time.time(); pipe.predict(df.iloc[:500] if len(df)>=1 else df); dt=(time.time()-t0)/len(df)*1000
    print(f"   latency ≈ {dt:.2f} ms/record"); assert dt < 50, f"too slow: {dt}"
def t6():
    # determinism: same input -> same output
    pipe = joblib.load("models/nids_pipeline.joblib")
    df = pd.read_csv("sample_inputs.csv" if __import__("os").path.exists("sample_inputs.csv") else "app/sample_inputs.csv")
    assert list(pipe.predict(df)) == list(pipe.predict(df))

for i, fn in enumerate([t1,t2,t3,t4,t5,t6], 1):
    names = {1:"model artifact loads",2:"single + batch prediction on sample_inputs.csv",
             3:"predict_proba shape + sums to 1",4:"invalid/unknown input handling",
             5:"latency budget (<50 ms/record)",6:"deterministic predictions"}
    check(f"Test {i}: {names[i]}", fn)
n_pass = sum(1 for _,ok,_ in results if ok)
print(f"\n{n_pass}/{len(results)} tests passed.")
raise SystemExit(0 if n_pass==len(results) else 1)
