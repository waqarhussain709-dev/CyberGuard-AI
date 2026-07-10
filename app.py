import streamlit as st
import pandas as pd
import joblib

# 1. Model aur assets ko load karna
model = joblib.load('cyber_attack_model.pkl')
label_mapping = joblib.load('label_mapping.pkl')
model_columns = joblib.load('model_columns.pkl')

st.title("🛡️ CyberGuard-AI: Network Intrusion Detection System")
st.write("Enter network packet features to detect cyber attacks in real-time.")

# 2. Main input fields banana
duration = st.number_input("Duration (seconds)", min_value=0, value=0)
src_bytes = st.number_input("Source Bytes Sent", min_value=0, value=0)
dst_bytes = st.number_input("Destination Bytes Received", min_value=0, value=0)
count = st.number_input("Connection Count (past 2 seconds)", min_value=0, value=200)
serror_rate = st.slider("SYN Error Rate (0.0 to 1.0)", 0.0, 1.0, 0.0)

# Protocol type select box
protocol = st.selectbox("Protocol Type", ["tcp", "udp", "icmp"])

# 3. Prediction Button logic
if st.button("Analyze Packet"):
    # Raw data structure banana
    input_data = {
        'duration': duration, 'src_bytes': src_bytes, 'dst_bytes': dst_bytes, 
        'count': count, 'serror_rate': serror_rate, 'protocol_type': protocol
    }
    
    # DataFrame me badalna aur encoding align karna
    df = pd.DataFrame([input_data])
    df_encoded = pd.get_dummies(df)
    df_adjusted = df_encoded.reindex(columns=model_columns, fill_value=0)
    
    # Model se output lena
    pred_code = model.predict(df_adjusted)
    result = label_mapping[pred_code]
    
    # Output display karna
    if result == 'normal':
        st.success(f"✅ Secure Traffic: Status is {result.upper()}")
    else:
        st.error(f"🚨 Cyber Attack Detected: Pattern matches {result.upper()} attack!")
