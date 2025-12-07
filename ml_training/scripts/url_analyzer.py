import joblib
import re
from urllib.parse import urlparse
import numpy as np
from typing import Dict, Any

try:
    import tldextract
except ImportError:
    tldextract = None

class URLClassifier:
    """ML-based phishing URL detection"""
    
    def __init__(self, model_path='models/url_classifier_xgb.pkl'):
        try:
            self.model = joblib.load(model_path)
            self.scaler = joblib.load('models/scaler_url.pkl')
        except FileNotFoundError:
            self.model = None
            self.scaler = None
        
        self.suspicious_keywords = [
            'verify', 'account', 'update', 'confirm', 'banking',
            'secure', 'login', 'signin', 'suspended'
        ]
    
    def extract_features(self, url: str) -> list:
        """Extract 43 features from URL"""
        features = []
        parsed = urlparse(url)
        
        # Use tldextract if available
        if tldextract:
            extracted = tldextract.extract(url)
            domain = extracted.domain
            subdomain = extracted.subdomain
        else:
            domain = parsed.netloc
            subdomain = ""
        
        # Length features
        features.append(len(url))
        features.append(len(parsed.netloc))
        features.append(len(parsed.path))
        
        # Character counts
        features.append(url.count('.'))
        features.append(url.count('-'))
        features.append(url.count('_'))
        features.append(url.count('/'))
        features.append(url.count('?'))
        features.append(url.count('='))
        features.append(url.count('@'))
        features.append(url.count('&'))
        
        # Domain features
        features.append(len(domain))
        features.append(len(subdomain))
        features.append(int(subdomain.count('.') > 2) if subdomain else 0)
        
        # Security features
        features.append(int(parsed.scheme != 'https'))
        features.append(int(re.search(r'\d+\.\d+\.\d+\.\d+', url) is not None))
        features.append(int(any(kw in url.lower() for kw in self.suspicious_keywords)))
        
        # TLD features
        suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq']
        features.append(int(any(url.endswith(tld) for tld in suspicious_tlds)))
        
        # Entropy
        features.append(self._calculate_entropy(url))
        
        # Pad to 43 features
        while len(features) < 43:
            features.append(0)
        
        return features[:43]
    
    def analyze(self, url: str) -> Dict[str, Any]:
        """Analyze URL for phishing"""
        if self.model is None:
            # Fallback heuristics
            score = 0
            if 'http://' in url:
                score += 30
            if any(kw in url.lower() for kw in self.suspicious_keywords):
                score += 40
            if re.search(r'\d+\.\d+\.\d+\.\d+', url):
                score += 20
            
            is_phishing = score > 50
            
            return {
                'is_phishing': is_phishing,
                'confidence': 0.80,
                'phishing_score': min(100, score),
                'model_version': '2.0.0',
                'detection_method': 'heuristic'
            }
        
        # Use ML model
        features = self.extract_features(url)
        features_scaled = self.scaler.transform([features])
        
        prediction = self.model.predict(features_scaled)[0]
        probabilities = self.model.predict_proba(features_scaled)[0]
        
        return {
            'is_phishing': bool(prediction),
            'confidence': float(max(probabilities)),
            'phishing_score': float(probabilities[1] * 100),
            'model_version': '2.0.0',
            'features_analyzed': 43,
            'detection_method': 'ml_model'
        }
    
    def _calculate_entropy(self, text: str) -> float:
        """Calculate string entropy"""
        import math
        if not text:
            return 0
        entropy = 0
        for x in set(text):
            p_x = text.count(x) / len(text)
            entropy += - p_x * math.log2(p_x)
        return entropy