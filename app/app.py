"""Group 5 — Real-Time Network Intrusion Detection prototype (Streamlit)."""
import time, joblib, pandas as pd, streamlit as st

st.set_page_config(page_title="NIDS — Real-Time Network Intrusion Detection", layout="wide")
st.title("🛡️ Real-Time Network Intrusion Detection — Group 5")
st.caption("FUSE AI-201 · Multi-class classification of network traffic: Normal / DoS / Probe / R2L / U2R · NSL-KDD")

@st.cache_resource
def load():
    import os
    cands = ["models/nids_pipeline.joblib", "app/../models/nids_pipeline.joblib",
             os.path.join(os.path.dirname(__file__), "..", "models", "nids_pipeline.joblib"),
             os.path.join(os.path.dirname(__file__), "models", "nids_pipeline.joblib")]
    cands_m = [c.replace("nids_pipeline", "feature_meta") for c in cands]
    pipe = meta = None
    for c in cands:
        try:
            pipe = joblib.load(c); break
        except Exception: continue
    for c in cands_m:
        try:
            meta = joblib.load(c); break
        except Exception: continue
    if pipe is None or meta is None:
        raise FileNotFoundError("models/nids_pipeline.joblib + feature_meta.joblib not found. Run from portfolio root: streamlit run app/app.py")
    return pipe, meta
try:
    pipe, meta = load()
    LABELS = meta["labels"]
except Exception as e:
    st.error(f"Could not load model (models/nids_pipeline.joblib). Train first. Details: {e}")
    st.stop()

FEATURES, CAT, NUM = meta["features"], meta["cat"], meta["num"]
PROTOS = ["tcp","udp","icmp"]
SERVICES = ['aol','auth','bgp','courier','csnet_ns','ctf','daytime','discard','domain','domain_u','echo','eco_i','ecr_i','efs','exec','finger','ftp','ftp_data','gopher','harvest','hostnames','http','http_2784','http_443','http_8001','imap4','IRC','iso_tsap','klogin','kshell','ldap','link','login','mtp','name','netbios_dgm','netbios_ns','netbios_ssn','netstat','nnsp','nntp','ntp_u','other','pm_dump','pop_2','pop_3','printer','private','red_i','remote_job','rje','shell','smtp','sql_net','ssh','sunrpc','supdup','systat','telnet','tftp_u','tim_i','time','urh_i','urp_i','uucp','uucp_path','vmnet','whois','X11','Z39_50']
FLAGS = ['OTH','REJ','RSTO','RSTOS0','RSTR','S0','S1','S2','S3','SF','SH']

with st.sidebar:
    st.header("About")
    st.write("Type a single connection record **or** upload a CSV with the 41 NSL-KDD feature columns. The saved preprocessing + model pipeline is applied identically to training.")
    st.info("⚠️ Decision-support prototype only — not a security control. All predictions require analyst review. Dataset is a historical benchmark and does not represent modern encrypted/cloud traffic.")
    st.write("**Model:** HistGradientBoosting + One-Hot (protocol/service/flag)")
    st.write("**Test performance:** acc 0.80 · macro-F1 0.66 · weighted-F1 0.78 (held-out KDDTest+)")

tab1, tab2 = st.tabs(["🔍 Single-record prediction", "📤 Batch CSV prediction"])

def predict_df(df):
    t0=time.time()
    pred = pipe.predict(df)
    proba = pipe.predict_proba(df) if hasattr(pipe, "predict_proba") else None
    dt=(time.time()-t0)/max(len(df),1)*1000
    return pred, proba, dt

with tab1:
    st.subheader("Enter one network-connection record")
    c1,c2,c3 = st.columns(3)
    with c1:
        duration = st.number_input("duration", 0, 60000, 0)
        protocol_type = st.selectbox("protocol_type", PROTOS, index=0)
        service = st.selectbox("service", SERVICES, index=SERVICES.index("http"))
        flag = st.selectbox("flag", FLAGS, index=FLAGS.index("SF"))
        src_bytes = st.number_input("src_bytes", 0, 1000000000, 300)
        dst_bytes = st.number_input("dst_bytes", 0, 1000000000, 2000)
        land = st.selectbox("land", ["0","1"], index=0)
        wrong_fragment = st.number_input("wrong_fragment", 0, 10, 0)
        urgent = st.number_input("urgent", 0, 20, 0)
        hot = st.number_input("hot", 0, 100, 0)
    with c2:
        num_failed_logins = st.number_input("num_failed_logins", 0, 10, 0)
        logged_in = st.selectbox("logged_in", ["0","1"], index=1)
        num_compromised = st.number_input("num_compromised", 0, 100, 0)
        root_shell = st.number_input("root_shell", 0, 5, 0)
        su_attempted = st.number_input("su_attempted", 0, 5, 0)
        num_root = st.number_input("num_root", 0, 100, 0)
        num_file_creations = st.number_input("num_file_creations", 0, 100, 0)
        num_shells = st.number_input("num_shells", 0, 10, 0)
        num_access_files = st.number_input("num_access_files", 0, 20, 0)
        num_outbound_cmds = st.number_input("num_outbound_cmds", 0, 10, 0)
    with c3:
        is_host_login = st.selectbox("is_host_login", ["0","1"], index=0)
        is_guest_login = st.selectbox("is_guest_login", ["0","1"], index=0)
        count = st.number_input("count", 0, 600, 5)
        srv_count = st.number_input("srv_count", 0, 600, 5)
        serror_rate = st.slider("serror_rate", 0.0, 1.0, 0.0)
        srv_serror_rate = st.slider("srv_serror_rate", 0.0, 1.0, 0.0)
        rerror_rate = st.slider("rerror_rate", 0.0, 1.0, 0.0)
        srv_rerror_rate = st.slider("srv_rerror_rate", 0.0, 1.0, 0.0)
        same_srv_rate = st.slider("same_srv_rate", 0.0, 1.0, 1.0)
        diff_srv_rate = st.slider("diff_srv_rate", 0.0, 1.0, 0.0)
    c4,c5,c6 = st.columns(3)
    with c4:
        srv_diff_host_rate = st.slider("srv_diff_host_rate", 0.0, 1.0, 0.0)
        dst_host_count = st.number_input("dst_host_count", 0, 255, 100)
        dst_host_srv_count = st.number_input("dst_host_srv_count", 0, 255, 100)
        dst_host_same_srv_rate = st.slider("dst_host_same_srv_rate", 0.0, 1.0, 1.0)
    with c5:
        dst_host_diff_srv_rate = st.slider("dst_host_diff_srv_rate", 0.0, 1.0, 0.0)
        dst_host_same_src_port_rate = st.slider("dst_host_same_src_port_rate", 0.0, 1.0, 0.0)
        dst_host_srv_diff_host_rate = st.slider("dst_host_srv_diff_host_rate", 0.0, 1.0, 0.0)
        dst_host_serror_rate = st.slider("dst_host_serror_rate", 0.0, 1.0, 0.0)
    with c6:
        dst_host_srv_serror_rate = st.slider("dst_host_srv_serror_rate", 0.0, 1.0, 0.0)
        dst_host_rerror_rate = st.slider("dst_host_rerror_rate", 0.0, 1.0, 0.0)
        dst_host_srv_rerror_rate = st.slider("dst_host_srv_rerror_rate", 0.0, 1.0, 0.0)
    col_a, col_b, col_c = st.columns(3)
    with col_a:
        go = st.button("🔎 Classify traffic", type="primary")
    with col_b:
        if st.button("Fill: Normal example"):
            st.session_state["_ex"]="normal"; st.rerun()
    with col_c:
        if st.button("Fill: Suspected DoS example"):
            st.session_state["_ex"]="dos"; st.rerun()
    if go:
        row = dict(duration=duration, protocol_type=protocol_type, service=service, flag=flag,
            src_bytes=src_bytes, dst_bytes=dst_bytes, land=str(land), wrong_fragment=wrong_fragment,
            urgent=urgent, hot=hot, num_failed_logins=num_failed_logins, logged_in=str(logged_in),
            num_compromised=num_compromised, root_shell=root_shell, su_attempted=su_attempted,
            num_root=num_root, num_file_creations=num_file_creations, num_shells=num_shells,
            num_access_files=num_access_files, num_outbound_cmds=num_outbound_cmds,
            is_host_login=str(is_host_login), is_guest_login=str(is_guest_login), count=count,
            srv_count=srv_count, serror_rate=serror_rate, srv_serror_rate=srv_serror_rate,
            rerror_rate=rerror_rate, srv_rerror_rate=srv_rerror_rate, same_srv_rate=same_srv_rate,
            diff_srv_rate=diff_srv_rate, srv_diff_host_rate=srv_diff_host_rate, dst_host_count=dst_host_count,
            dst_host_srv_count=dst_host_srv_count, dst_host_same_srv_rate=dst_host_same_srv_rate,
            dst_host_diff_srv_rate=dst_host_diff_srv_rate, dst_host_same_src_port_rate=dst_host_same_src_port_rate,
            dst_host_srv_diff_host_rate=dst_host_srv_diff_host_rate, dst_host_serror_rate=dst_host_serror_rate,
            dst_host_srv_serror_rate=dst_host_srv_serror_rate, dst_host_rerror_rate=dst_host_rerror_rate,
            dst_host_srv_rerror_rate=dst_host_srv_rerror_rate)
        df = pd.DataFrame([row], columns=FEATURES)
        try:
            pred, proba, ms = predict_df(df)
            st.success(f"**Predicted class: {pred[0]}**  ·  inference ≈ {ms:.1f} ms/record")
            if proba is not None:
                p = pd.DataFrame([proba[0]], columns=list(pipe.classes_)).T.rename(columns={0: "probability"}).sort_values("probability", ascending=False)
                st.bar_chart(p)
                st.dataframe(p.style.format("{:.3f}"), use_container_width=True)
            st.warning("Analyst review required — confidence is not a guarantee. R2L/U2R recall is limited; treat Normal predictions on unusual logins with care.")
        except Exception as e:
            st.error(f"Prediction failed safely: {e}")

with tab2:
    st.subheader("Upload CSV of connection records (41 feature columns)")
    st.download_button("⬇ Download CSV template", pd.DataFrame(columns=FEATURES).to_csv(index=False), "nids_template.csv", "text/csv")
    up = st.file_uploader("Choose CSV", type=["csv"])
    if up is not None:
        try:
            df = pd.read_csv(up)
            missing = [c for c in FEATURES if c not in df.columns]
            if missing:
                st.error(f"Missing columns: {missing}. Extra columns are ignored.")
            else:
                df = df[FEATURES]
                pred, proba, ms = predict_df(df)
                out = df.copy(); out["predicted_category"] = pred
                if proba is not None:
                    for i,cl in enumerate(pipe.classes_): out[f"prob_{cl}"] = proba[:,i].round(4)
                st.success(f"Classified {len(out)} records · ≈ {ms:.2f} ms/record")
                st.dataframe(out.head(50), use_container_width=True)
                st.bar_chart(out["predicted_category"].value_counts())
                st.download_button("⬇ Download predictions", out.to_csv(index=False), "nids_predictions.csv", "text/csv")
        except Exception as e:
            st.error(f"Could not process file: {e}")
