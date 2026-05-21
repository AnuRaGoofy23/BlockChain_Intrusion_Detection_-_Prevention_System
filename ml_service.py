import pickle
import os

class MLService:
    def __init__(self, model_path="model.pkl"):
        self.model = None
        if os.path.exists(model_path):
            with open(model_path, "rb") as f:
                self.model = pickle.load(f)

    def predict_anomaly(self, gas_used: float, value_eth: float, is_contract: int = 0, tx_frequency: int = 1, failed_tx_ratio: float = 0.0) -> float:
        if not self.model:
            return 0.0 # Fail-safe if no model
        
        # Features: [gas_used, value_eth, is_contract, tx_frequency, failed_tx_ratio]
        features = [[gas_used, value_eth, is_contract, tx_frequency, failed_tx_ratio]]
        
        # decision_function returns positive for inliers, negative for outliers
        # We invert it so higher positive score = more anomalous
        raw_score = self.model.decision_function(features)[0]
        anomaly_score = float(-raw_score)
        
        return anomaly_score

ml_service = MLService()
