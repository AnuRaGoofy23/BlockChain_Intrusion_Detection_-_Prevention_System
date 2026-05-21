import pickle
import numpy as np
from sklearn.ensemble import IsolationForest

def generate_dummy_model():
    print("Generating dummy Isolation Forest model...")
    # Features: [gas_used, value_eth, is_contract, tx_frequency, failed_tx_ratio]
    # Simple synthetic data
    X = np.array([
        [21000, 0.5, 0, 1, 0.0], # Normal transfer
        [21000, 1.2, 0, 2, 0.0], # Normal transfer
        [500000, 0.0, 1, 1, 0.0], # Normal contract interaction
        [3000000, 50.0, 1, 10, 0.8], # Anomaly: High gas, value, high freq, many fails
        [8000000, 0.0, 1, 50, 1.0], # Anomaly: Gas limit reached, extreme freq and fails
        [50000, 0.1, 1, 2, 0.0], # Normal contract call
    ])

    # contamination = proportion of outliers in the data set
    clf = IsolationForest(n_estimators=100, contamination=0.3, random_state=42)
    clf.fit(X)

    with open("model.pkl", "wb") as f:
        pickle.dump(clf, f)
    print("Model saved to model.pkl")

if __name__ == "__main__":
    generate_dummy_model()
