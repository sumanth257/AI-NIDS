
import pandas as pd
from sklearn.ensemble import IsolationForest
import joblib

print("Loading network traffic dataset...")

data = pd.read_csv("network_traffic.csv")

# Convert protocol into numerical values
protocol_map = {
    "ICMP": 1,
    "TCP": 6,
    "UDP": 17,
    "OTHER": 0
}

# Select basic numerical network features
features = data[
    [
        "source_port",
        "destination_port",
        "packet_size"
    ]
].copy()

features["protocol"] = data["protocol"].map(protocol_map)

# Extract TCP flags into individual numerical features
flags = data["tcp_flags"].fillna("NONE").astype(str)

features["tcp_syn"] = flags.str.contains("S", regex=False).astype(int)
features["tcp_ack"] = flags.str.contains("A", regex=False).astype(int)
features["tcp_fin"] = flags.str.contains("F", regex=False).astype(int)
features["tcp_rst"] = flags.str.contains("R", regex=False).astype(int)
features["tcp_psh"] = flags.str.contains("P", regex=False).astype(int)
features["tcp_urg"] = flags.str.contains("U", regex=False).astype(int)
features["tcp_ece"] = flags.str.contains("E", regex=False).astype(int)
features["tcp_cwr"] = flags.str.contains("C", regex=False).astype(int)

# Handle missing values
features = features.fillna(0)

print("Dataset records:", len(features))
print("Features used:", list(features.columns))

print("Training AI anomaly detection model...")

model = IsolationForest(
    n_estimators=150,
    contamination=0.05,
    random_state=42
)

model.fit(features)

# Save trained model
joblib.dump(model, "nids_model.pkl")

print("AI model trained successfully!")
print("Saved as nids_model.pkl")

