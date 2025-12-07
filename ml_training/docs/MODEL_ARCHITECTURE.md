# ML Model Architecture

## Overview
CyberML Platform uses multiple machine learning models for threat detection.

## Models

### 1. Malware Detector
- **Type**: Random Forest Classifier
- **Features**: 87 static features
- **Accuracy**: 94.3%
- **Use Case**: Binary file analysis

### 2. URL Phishing Classifier
- **Type**: XGBoost Gradient Boosting
- **Features**: 43 URL features
- **Accuracy**: 95.8%
- **Use Case**: Phishing detection

### 3. API Anomaly Detector
- **Type**: Isolation Forest
- **Features**: 56 API features
- **Detection Rate**: 89.2%
- **Use Case**: API security testing

