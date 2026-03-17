import os
import pickle

current_dir = os.path.dirname(os.path.abspath(__file__))
model_path = os.path.join(current_dir, "..", "models", "phishing_model.pkl")

model = None
try:
    with open(model_path, 'rb') as f:
        model = pickle.load(f)
except Exception as e:
    print(f"Warning: Could not load phishing model: {e}")

SUSPICIOUS_KEYWORDS = ["urgent", "verify", "account", "suspended", "password", "invoice", "bank", "claim", "gift card"]

def analyze_email(content: str) -> dict:
    keywords_found = [kw for kw in SUSPICIOUS_KEYWORDS if kw in content.lower()]
    
    if model:
        prob = model.predict_proba([content])[0][1] 
        risk_score = int(prob * 100)
    else:
        risk_score = min(100, len(keywords_found) * 20)
        
    if risk_score > 70:
        risk_level = "CRITICAL"
        explanation = "Email contains strong phishing indicators such as urgency, credential requests, or malicious patterns."
    elif risk_score > 30:
        risk_level = "MEDIUM"
        explanation = "Email shows some suspicious characteristics. Exercise caution."
    else:
        risk_level = "LOW"
        explanation = "Email appears to be legitimate based on current analysis."
        
    return {
        "risk_score": risk_score,
        "risk_level": risk_level,
        "suspicious_keywords": keywords_found,
        "explanation": explanation
    }
