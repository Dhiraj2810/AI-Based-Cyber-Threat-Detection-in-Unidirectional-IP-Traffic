import os
import sys
import random
import string
import joblib
import numpy as np
import pandas as pd
from lightgbm import LGBMClassifier
from sklearn.ensemble import IsolationForest
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from backend.features.feature_extractor import calculate_shannon_entropy

MODEL_DIR = os.path.join(os.path.dirname(__file__), "models")
os.makedirs(MODEL_DIR, exist_ok=True)

# Sample benign domains and TLDs for DGA training
BENIGN_DOMAINS = [
    "google.com", "microsoft.com", "amazon.com", "github.com", "wikipedia.org",
    "cloudflare.com", "apple.com", "youtube.com", "fastapi.tiangolo.com",
    "pypi.org", "scikit-learn.org", "python.org", "stackoverflow.com",
    "news.ycombinator.com", "subdomain.internal.corp.net", "api.stripe.com"
]

TLDS = [".com", ".net", ".org", ".info", ".biz", ".ru", ".cc", ".xyz"]

def generate_dga_domain() -> str:
    """Generate synthetic DGA domain names (random chars/digits)."""
    length = random.randint(12, 35)
    chars = string.ascii_lowercase + string.digits
    domain = "".join(random.choice(chars) for _ in range(length))
    return domain + random.choice(TLDS)

def get_domain_feature_vector(domain: str) -> list:
    entropy = calculate_shannon_entropy(domain)
    length = len(domain)
    vowels = sum(1 for c in domain if c.lower() in "aeiou")
    vowel_ratio = vowels / max(length, 1)
    digits = sum(1 for c in domain if c.isdigit())
    digit_ratio = digits / max(length, 1)
    subdomains = domain.count('.')
    return [entropy, length, vowel_ratio, digit_ratio, subdomains]

def train_dga_model():
    print("[*] Generating synthetic DGA training data...")
    X, y = [], []
    
    # Benign samples
    for _ in range(2000):
        base = random.choice(BENIGN_DOMAINS)
        prefix = "".join(random.choices(string.ascii_lowercase, k=random.randint(0, 8)))
        domain = f"{prefix}.{base}" if prefix else base
        X.append(get_domain_feature_vector(domain))
        y.append(0)

    # DGA samples
    for _ in range(2000):
        domain = generate_dga_domain()
        X.append(get_domain_feature_vector(domain))
        y.append(1)

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    
    model = LGBMClassifier(n_estimators=100, learning_rate=0.05, random_state=42, verbose=-1)
    model.fit(X_train, y_train)

    preds = model.predict(X_test)
    print("--- DGA Model Evaluation ---")
    print(classification_report(y_test, preds))

    model_path = os.path.join(MODEL_DIR, "dga_lgbm.joblib")
    joblib.dump(model, model_path)
    print(f"[+] DGA model saved to {model_path}")

def train_c2_beaconing_model():
    print("[*] Generating synthetic C2 Beaconing training data...")
    # Feature vector: [iat_mean, iat_std, iat_cv, duration, total_packets]
    X_benign = []
    for _ in range(2000):
        # Benign human traffic: variable timing, high IAT std & CV
        iat_mean = random.uniform(0.1, 15.0)
        iat_std = iat_mean * random.uniform(0.6, 2.5)  # High variance
        iat_cv = iat_std / iat_mean
        duration = random.uniform(1.0, 300.0)
        packets = random.randint(5, 500)
        X_benign.append([iat_mean, iat_std, iat_cv, duration, packets])

    X_beacon = []
    for _ in range(500):
        # C2 Beaconing: very low timing variance (regular pulse)
        iat_mean = random.uniform(5.0, 60.0)  # e.g., beacon every 10s, 30s, 60s
        iat_std = iat_mean * random.uniform(0.01, 0.1)  # Extremely low variance!
        iat_cv = iat_std / iat_mean
        duration = random.uniform(60.0, 3600.0)
        packets = random.randint(10, 200)
        X_beacon.append([iat_mean, iat_std, iat_cv, duration, packets])

    X_train = np.array(X_benign)
    model = IsolationForest(contamination=0.1, random_state=42)
    model.fit(X_train)

    model_path = os.path.join(MODEL_DIR, "c2_isolation_forest.joblib")
    joblib.dump(model, model_path)
    print(f"[+] C2 Isolation Forest model saved to {model_path}")

def train_encrypted_malware_model():
    print("[*] Generating synthetic Encrypted Malware training data...")
    # Features: [tls_sni_entropy, tls_ciphers_count, size_mean, size_std, byte_ratio]
    X, y = [], []

    # Benign TLS
    for _ in range(1500):
        sni_entropy = random.uniform(2.5, 4.0)
        ciphers_count = random.randint(15, 35)
        size_mean = random.uniform(400, 1200)
        size_std = random.uniform(200, 600)
        byte_ratio = random.uniform(0.1, 0.9)
        X.append([sni_entropy, ciphers_count, size_mean, size_std, byte_ratio])
        y.append(0)

    # Malicious Encrypted Sessions (e.g. Cobalt Strike / RAT TLS tunnel)
    for _ in range(1500):
        sni_entropy = random.uniform(4.5, 5.8)  # High entropy random domain/IP SNI
        ciphers_count = random.randint(2, 6)     # Minimal cipher suites hardcoded in malware binary
        size_mean = random.uniform(100, 300)     # Fixed size heartbeats
        size_std = random.uniform(5, 40)         # Low size std
        byte_ratio = random.uniform(1.5, 10.0)
        X.append([sni_entropy, ciphers_count, size_mean, size_std, byte_ratio])
        y.append(1)

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    
    model = LGBMClassifier(n_estimators=100, learning_rate=0.05, random_state=42, verbose=-1)
    model.fit(X_train, y_train)

    preds = model.predict(X_test)
    print("--- Encrypted Malware Model Evaluation ---")
    print(classification_report(y_test, preds))

    model_path = os.path.join(MODEL_DIR, "encrypted_malware_lgbm.joblib")
    joblib.dump(model, model_path)
    print(f"[+] Encrypted Malware model saved to {model_path}")

if __name__ == "__main__":
    train_dga_model()
    train_c2_beaconing_model()
    train_encrypted_malware_model()
