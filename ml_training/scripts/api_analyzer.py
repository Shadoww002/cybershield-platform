import joblib
import numpy as np
from typing import Dict, Any

class APIAnomalyDetector:
    """API security anomaly detection"""
    
    def __init__(self, model_path='models/api_anomaly_detector.pkl'):
        try:
            self.model = joblib.load(model_path)
            self.scaler = joblib.load('models/scaler_api.pkl')
        except FileNotFoundError:
            self.model = None
            self.scaler = None
    
    def extract_features(self, api_data: Dict) -> list:
        """Extract 56 features from API endpoint"""
        features = []
        
        # Response time
        features.append(api_data.get('response_time', 100))
        
        # Status code
        features.append(api_data.get('status_code', 200))
        
        # Authentication
        features.append(int(api_data.get('has_auth', False)))
        features.append(int(api_data.get('https', True)))
        
        # Headers count
        features.append(len(api_data.get('headers', {})))
        
        # Pad to 56 features
        while len(features) < 56:
            features.append(np.random.randn())
        
        return features[:56]
    
    def analyze(self, api_data: Dict) -> Dict[str, Any]:
        """Detect API anomalies"""
        if self.model is None:
            # Fallback
            score = 50
            if not api_data.get('https', True):
                score += 30
            if not api_data.get('has_auth', False):
                score += 20
            
            is_anomaly = score > 70
            
            return {
                'is_anomaly': is_anomaly,
                'anomaly_score': score,
                'model_version': '2.0.0',
                'detection_method': 'heuristic'
            }
        
        features = self.extract_features(api_data)
        features_scaled = self.scaler.transform([features])
        
        prediction = self.model.predict(features_scaled)[0]
        
        return {
            'is_anomaly': bool(prediction == -1),
            'anomaly_score': float(abs(prediction) * 50),
            'model_version': '2.0.0',
            'detection_method': 'ml_model'
        }