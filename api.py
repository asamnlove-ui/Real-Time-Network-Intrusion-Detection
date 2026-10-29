"""Group 5 — FastAPI alternative deployment (Module 6, Task 2). Run: uvicorn api:app --reload"""
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field
from typing import List
import joblib, pandas as pd

FEATURES = ["duration","protocol_type","service","flag","src_bytes","dst_bytes","land","wrong_fragment","urgent","hot",
"num_failed_logins","logged_in","num_compromised","root_shell","su_attempted","num_root","num_file_creations",
"num_shells","num_access_files","num_outbound_cmds","is_host_login","is_guest_login","count","srv_count",
"serror_rate","srv_serror_rate","rerror_rate","srv_rerror_rate","same_srv_rate","diff_srv_rate",
"srv_diff_host_rate","dst_host_count","dst_host_srv_count","dst_host_same_srv_rate","dst_host_diff_srv_rate",
"dst_host_same_src_port_rate","dst_host_srv_diff_host_rate","dst_host_serror_rate","dst_host_srv_serror_rate",
"dst_host_rerror_rate","dst_host_srv_rerror_rate"]

pipe = joblib.load("models/nids_pipeline.joblib")
app = FastAPI(title="Group5 NIDS API", version="1.0",
              description="Decision-support prototype only — not a security control. All predictions require analyst review.")

class Connection(BaseModel):
    duration: float = Field(ge=0, le=60000)
    protocol_type: str
    service: str
    flag: str
    src_bytes: float = Field(ge=0)
    dst_bytes: float = Field(ge=0)
    land: str = "0"
    wrong_fragment: float = 0
    urgent: float = 0
    hot: float = 0
    num_failed_logins: float = 0
    logged_in: str = "1"
    num_compromised: float = 0
    root_shell: float = 0
    su_attempted: float = 0
    num_root: float = 0
    num_file_creations: float = 0
    num_shells: float = 0
    num_access_files: float = 0
    num_outbound_cmds: float = 0
    is_host_login: str = "0"
    is_guest_login: str = "0"
    count: float = 5
    srv_count: float = 5
    serror_rate: float = Field(default=0, ge=0, le=1)
    srv_serror_rate: float = Field(default=0, ge=0, le=1)
    rerror_rate: float = Field(default=0, ge=0, le=1)
    srv_rerror_rate: float = Field(default=0, ge=0, le=1)
    same_srv_rate: float = Field(default=1, ge=0, le=1)
    diff_srv_rate: float = Field(default=0, ge=0, le=1)
    srv_diff_host_rate: float = Field(default=0, ge=0, le=1)
    dst_host_count: float = 100
    dst_host_srv_count: float = 100
    dst_host_same_srv_rate: float = Field(default=1, ge=0, le=1)
    dst_host_diff_srv_rate: float = Field(default=0, ge=0, le=1)
    dst_host_same_src_port_rate: float = Field(default=0, ge=0, le=1)
    dst_host_srv_diff_host_rate: float = Field(default=0, ge=0, le=1)
    dst_host_serror_rate: float = Field(default=0, ge=0, le=1)
    dst_host_srv_serror_rate: float = Field(default=0, ge=0, le=1)
    dst_host_rerror_rate: float = Field(default=0, ge=0, le=1)
    dst_host_srv_rerror_rate: float = Field(default=0, ge=0, le=1)

@app.get("/health")
def health():
    return {"status": "ok", "model": "HistGradientBoosting", "classes": list(pipe.classes_)}

@app.post("/predict")
def predict(conn: Connection):
    try:
        df = pd.DataFrame([conn.model_dump()], columns=FEATURES)
        pred = pipe.predict(df)[0]
        proba = pipe.predict_proba(df)[0]
        probs = {c: round(float(p), 4) for c, p in zip(pipe.classes_, proba)}
        return {"predicted_category": pred, "probabilities": probs,
                "caution": "Advisory only — analyst review required. R2L/U2R recall is limited."}
    except Exception as e:
        raise HTTPException(400, f"Prediction failed safely: {e}")

@app.post("/predict_batch")
def predict_batch(rows: List[Connection]):
    try:
        df = pd.DataFrame([r.model_dump() for r in rows], columns=FEATURES)
        preds = pipe.predict(df); probas = pipe.predict_proba(df)
        return {"predictions": [
            {"predicted_category": p, "probabilities": {c: round(float(v), 4) for c, v in zip(pipe.classes_, pr)}}
            for p, pr in zip(preds, probas)]}
    except Exception as e:
        raise HTTPException(400, f"Batch prediction failed safely: {e}")
