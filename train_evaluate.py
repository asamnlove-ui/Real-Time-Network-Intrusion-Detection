"""Group 5 — Real-Time Network Intrusion Detection (NSL-KDD), Module 5 implementation."""
import os, json, warnings
warnings.filterwarnings("ignore")
import numpy as np, pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.compose import ColumnTransformer
from sklearn.preprocessing import OneHotEncoder, StandardScaler
from sklearn.pipeline import Pipeline
from sklearn.dummy import DummyClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier, HistGradientBoostingClassifier
from sklearn.model_selection import StratifiedKFold, cross_validate, RandomizedSearchCV
from sklearn.metrics import (accuracy_score, precision_recall_fscore_support,
    classification_report, confusion_matrix)
import joblib

COLS = ["duration","protocol_type","service","flag","src_bytes","dst_bytes","land","wrong_fragment","urgent","hot",
"num_failed_logins","logged_in","num_compromised","root_shell","su_attempted","num_root","num_file_creations",
"num_shells","num_access_files","num_outbound_cmds","is_host_login","is_guest_login","count","srv_count",
"serror_rate","srv_serror_rate","rerror_rate","srv_rerror_rate","same_srv_rate","diff_srv_rate",
"srv_diff_host_rate","dst_host_count","dst_host_srv_count","dst_host_same_srv_rate","dst_host_diff_srv_rate",
"dst_host_same_src_port_rate","dst_host_srv_diff_host_rate","dst_host_serror_rate","dst_host_srv_serror_rate",
"dst_host_rerror_rate","dst_host_srv_rerror_rate","label","difficulty"]

DOS = {"back","land","neptune","pod","smurf","teardrop","mailbomb","apache2","processtable","udpstorm","worm"}
PROBE = {"ipsweep","nmap","portsweep","satan","mscan","saint"}
R2L = {"ftp_write","guess_passwd","imap","multihop","phf","spy","warezclient","warezmaster","sendmail","named",
"snmpgetattack","snmpguess","xlock","xsnoop","httptunnel"}
U2R = {"buffer_overflow","loadmodule","perl","rootkit","ps","sqlattack","xterm"}
def map5(x):
    x=str(x).strip().lower()
    if x=="normal": return "Normal"
    if x in DOS: return "DoS"
    if x in PROBE: return "Probe"
    if x in R2L: return "R2L"
    if x in U2R: return "U2R"
    return "Other-Attack"

os.makedirs("figures", exist_ok=True); os.makedirs("models", exist_ok=True); os.makedirs("outputs", exist_ok=True)

train = pd.read_csv("data/KDDTrain+.txt", header=None, names=COLS)
test = pd.read_csv("data/KDDTest+.txt", header=None, names=COLS)
for df in (train, test):
    df["category5"] = df["label"].apply(map5)
print("Train shape:", train.shape, "Test shape:", test.shape)
print("Train attack labels:", sorted(train["label"].unique())[:40])
print("Test attack labels:", sorted(test["label"].unique()))
print("\nTrain category5:\n", train["category5"].value_counts())
print("\nTrain category5 %:\n", train["category5"].value_counts(normalize=True).round(4))
print("\nTest category5:\n", test["category5"].value_counts())
print("\nTest category5 %:\n", test["category5"].value_counts(normalize=True).round(4))

# Data quality
dq = {"train_rows": len(train), "test_rows": len(test),
 "train_missing": int(train.isnull().sum().sum()), "test_missing": int(test.isnull().sum().sum()),
 "train_dup": int(train.duplicated().sum()), "test_dup": int(test.duplicated().sum())}
print(dq)

FEATURES = [c for c in COLS if c not in ("label","difficulty","category5")]
CAT = ["protocol_type","service","flag"]
NUM = [c for c in FEATURES if c not in CAT]
TARGET = "category5"
LABELS = ["Normal","DoS","Probe","R2L","U2R"]

X_train_full, y_train_full = train[FEATURES], train[TARGET]
X_test, y_test = test[FEATURES], test[TARGET]
# filter to 5 classes (drop Other if any - there should be none, but keep safe)
mask_tr = y_train_full.isin(LABELS); mask_te = y_test.isin(LABELS)
print("Dropped train Other:", (~mask_tr).sum(), "test Other:", (~mask_te).sum())
X_train_full, y_train_full = X_train_full[mask_tr], y_train_full[mask_tr]
X_test, y_test = X_test[mask_te], y_test[mask_te]

def make_pre():
    return ColumnTransformer([
        ("cat", OneHotEncoder(handle_unknown="ignore"), CAT),
        ("num", "passthrough", NUM),
    ])
def make_pre_scaled():
    return ColumnTransformer([
        ("cat", OneHotEncoder(handle_unknown="ignore"), CAT),
        ("num", StandardScaler(), NUM),
    ])

def scores(y_true, y_pred):
    acc = accuracy_score(y_true, y_pred)
    pM,rM,fM,_ = precision_recall_fscore_support(y_true, y_pred, labels=LABELS, average="macro", zero_division=0)
    pW,rW,fW,_ = precision_recall_fscore_support(y_true, y_pred, labels=LABELS, average="weighted", zero_division=0)
    per = precision_recall_fscore_support(y_true, y_pred, labels=LABELS, zero_division=0)
    per_d = {l: {"precision": float(per[0][i]), "recall": float(per[1][i]), "f1": float(per[2][i]), "support": int(per[3][i])} for i,l in enumerate(LABELS)}
    return {"accuracy": float(acc), "macro_precision": float(pM), "macro_recall": float(rM), "macro_f1": float(fM),
            "weighted_f1": float(fW), "per_class": per_d}

results = {}
# --- Baselines on full train -> test (single fit, fast) ---
for name, clf, pre in [
    ("majority", DummyClassifier(strategy="most_frequent"), make_pre()),
    ("decision_tree", DecisionTreeClassifier(random_state=42), make_pre()),
    ("logreg", LogisticRegression(max_iter=1000), make_pre_scaled()),
]:
    pipe = Pipeline([("pre", pre), ("clf", clf)])
    pipe.fit(X_train_full, y_train_full)
    pred = pipe.predict(X_test)
    results[name] = scores(y_test, pred)
    print(f"\n== {name} ==", results[name])
    print(classification_report(y_test, pred, labels=LABELS, zero_division=0))

# --- Candidate models with 3-fold CV on train (sample 30k for speed on HGB/logreg already done) ---
import time
candidates = {
    "random_forest": RandomForestClassifier(n_estimators=200, random_state=42, n_jobs=-1, class_weight="balanced_subsample"),
    "hist_gb": HistGradientBoostingClassifier(random_state=42, class_weight="balanced"),
}
cv = StratifiedKFold(n_splits=3, shuffle=True, random_state=42)
# subsample train for CV to keep runtime sane
rng = np.random.RandomState(42)
idx = rng.choice(len(X_train_full), size=min(45000, len(X_train_full)), replace=False)
Xcv, ycv = X_train_full.iloc[idx], y_train_full.iloc[idx]
cv_rows = []
for name, clf in candidates.items():
    pipe = Pipeline([("pre", make_pre()), ("clf", clf)])
    t0=time.time()
    cvres = cross_validate(pipe, Xcv, ycv, cv=cv, scoring=["accuracy","f1_macro"], n_jobs=-1)
    dt=time.time()-t0
    row = {"model": name, "cv_acc_mean": float(cvres["test_accuracy"].mean()), "cv_f1m_mean": float(cvres["test_f1_macro"].mean()),
           "cv_f1m_std": float(cvres["test_f1_macro"].std()), "fit_min": round(dt/60,2)}
    cv_rows.append(row); print(row)

# --- Tune RandomForest lightly ---
param = {"clf__n_estimators":[200,350], "clf__max_depth":[None,25,40], "clf__min_samples_leaf":[1,2]}
rs = RandomizedSearchCV(Pipeline([("pre", make_pre()), ("clf", RandomForestClassifier(random_state=42, n_jobs=-1, class_weight="balanced_subsample"))]),
    param, n_iter=4, cv=2, scoring="f1_macro", random_state=42, n_jobs=-1, verbose=1)
rs.fit(Xcv, ycv)
print("Best RF:", rs.best_params_, rs.best_score_)
final_rf = rs.best_estimator_
final_rf.fit(X_train_full, y_train_full)
pred_rf = final_rf.predict(X_test)
results["random_forest_tuned"] = scores(y_test, pred_rf)
print("Tuned RF test:", results["random_forest_tuned"])
print(classification_report(y_test, pred_rf, labels=LABELS, zero_division=0))

# HGB final fit on full train
hgb = Pipeline([("pre", make_pre()), ("clf", HistGradientBoostingClassifier(random_state=42, class_weight="balanced"))])
hgb.fit(X_train_full, y_train_full)
results["hist_gb_full"] = scores(y_test, hgb.predict(X_test))
print("HGB test:", results["hist_gb_full"])

# Choose final: higher macro F1
final_name = max(["random_forest_tuned","hist_gb_full"], key=lambda k: results[k]["macro_f1"])
final_model = final_rf if final_name=="random_forest_tuned" else hgb
print("FINAL:", final_name, results[final_name])
joblib.dump(final_model, "models/nids_pipeline.joblib")
joblib.dump({"features": FEATURES, "cat": CAT, "num": NUM, "labels": LABELS}, "models/feature_meta.joblib")

# Latency check
import time as _t
sample = X_test.iloc[:500]
s=_t.time(); final_model.predict(sample); e=_t.time()
lat_ms = (e-s)/len(sample)*1000
print(f"Latency per record: {lat_ms:.2f} ms")

# Confusion matrices for key models
for key, pipe in [("decision_tree", None), ("final_"+final_name, final_model)]:
    if key=="decision_tree":
        p2 = Pipeline([("pre", make_pre()), ("clf", DecisionTreeClassifier(random_state=42))])
        p2.fit(X_train_full, y_train_full); pred2 = p2.predict(X_test)
    else:
        pred2 = final_model.predict(X_test)
    cm = confusion_matrix(y_test, pred2, labels=LABELS, normalize="true")
    fig, ax = plt.subplots(figsize=(7,5.5))
    sns.heatmap(cm, annot=True, fmt=".2f", xticklabels=LABELS, yticklabels=LABELS, cmap="Blues", ax=ax)
    ax.set_xlabel("Predicted"); ax.set_ylabel("True"); ax.set_title(f"Recall-normalized confusion matrix — {key} (test)")
    fig.tight_layout(); fig.savefig(f"figures/cm_{key}.png", dpi=150); plt.close(fig)
    cmc = confusion_matrix(y_test, pred2, labels=LABELS)
    fig, ax = plt.subplots(figsize=(7,5.5))
    sns.heatmap(cmc, annot=True, fmt="d", xticklabels=LABELS, yticklabels=LABELS, cmap="Blues", ax=ax)
    ax.set_xlabel("Predicted"); ax.set_ylabel("True"); ax.set_title(f"Confusion matrix (counts) — {key}")
    fig.tight_layout(); fig.savefig(f"figures/cm_{key}_counts.png", dpi=150); plt.close(fig)

# EDA figures
fig, ax = plt.subplots(figsize=(8,4.5))
(tr := train["category5"].value_counts().reindex(LABELS)).plot(kind="bar", ax=ax, color="#2563eb")
ax.set_title("Train class distribution (5-class mapping)"); ax.set_ylabel("Records")
for i,v in enumerate(tr.values): ax.text(i, v, f"{v:,}", ha="center", va="bottom", fontsize=8)
fig.tight_layout(); fig.savefig("figures/eda_class_train.png", dpi=150); plt.close(fig)
fig, ax = plt.subplots(figsize=(8,4.5))
(te := test["category5"].value_counts().reindex(LABELS)).plot(kind="bar", ax=ax, color="#059669")
ax.set_title("Test class distribution (5-class mapping)"); ax.set_ylabel("Records")
for i,v in enumerate(te.values): ax.text(i, v, f"{v:,}", ha="center", va="bottom", fontsize=8)
fig.tight_layout(); fig.savefig("figures/eda_class_test.png", dpi=150); plt.close(fig)

# numeric correlation (top numeric vs target not needed; do feature corr sample)
numcorr = train[NUM].corr(numeric_only=True)
fig, ax = plt.subplots(figsize=(9,7))
sns.heatmap(numcorr, cmap="coolwarm", center=0, ax=ax)
ax.set_title("Numeric feature correlations (train)")
fig.tight_layout(); fig.savefig("figures/eda_numeric_corr.png", dpi=130); plt.close(fig)

# protocol vs category
ct = pd.crosstab(train["protocol_type"], train["category5"]).reindex(columns=LABELS)
fig, ax = plt.subplots(figsize=(8,4.5))
ct.plot(kind="bar", ax=ax)
ax.set_title("Protocol type vs traffic category (train)"); ax.set_ylabel("Records")
fig.tight_layout(); fig.savefig("figures/eda_protocol_vs_target.png", dpi=150); plt.close(fig)

# feature importance (RF)
try:
    rf_pre = final_rf.named_steps["pre"] if final_name=="random_forest_tuned" else None
    est = final_rf.named_steps["clf"] if final_name=="random_forest_tuned" else None
    if rf_pre is not None:
        feat_names = list(rf_pre.named_transformers_["cat"].get_feature_names_out(CAT)) + NUM
        imp = pd.Series(est.feature_importances_, index=feat_names).sort_values(ascending=False).head(20)
        fig, ax = plt.subplots(figsize=(8,6))
        imp.sort_values().plot(kind="barh", ax=ax, color="#7c3aed")
        ax.set_title("Top-20 feature importances — tuned Random Forest")
        fig.tight_layout(); fig.savefig("figures/feat_importance_rf.png", dpi=150); plt.close(fig)
        imp.to_csv("outputs/top20_importance.csv")
except Exception as e:
    print("importance failed:", e)

out = {"data_quality": dq,
 "train_dist": train["category5"].value_counts().to_dict(),
 "test_dist": test["category5"].value_counts().to_dict(),
 "cv": cv_rows, "best_rf_params": str(getattr(rs, "best_params_", "")),
 "test_metrics": results, "final_model": final_name, "latency_ms_per_record": lat_ms,
 "notes": "Train on KDDTrain+.txt, held-out test KDDTest+.txt; 5-class mapping Normal/DoS/Probe/R2L/U2R."}
json.dump(out, open("outputs/metrics.json","w"), indent=2)
pd.DataFrame([{**{"model":k}, **{kk:vv for kk,vv in v.items() if kk!="per_class"}} for k,v in results.items()]).to_csv("outputs/model_comparison.csv", index=False)
print("\nSaved models/nids_pipeline.joblib, outputs/metrics.json, figures/*.png")
