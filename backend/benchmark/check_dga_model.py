import os
import sys
import time
import joblib
import numpy as np

MODEL_PATH = os.path.join(os.path.dirname(__file__), "..", "models", "dga_lgbm.joblib")

def main():
    os.environ["OMP_NUM_THREADS"] = "1"
    os.environ["OPENBLAS_NUM_THREADS"] = "1"
    os.environ["MKL_NUM_THREADS"] = "1"

    model = joblib.load(MODEL_PATH)
    if hasattr(model, "set_params"):
        model.set_params(n_jobs=1)

    ml_feature_rows = []
    for _ in range(50):
        entropy = 4.25
        length = 45
        vowel_ratio = 0.2
        digit_ratio = 0.15
        subdomains = 2
        ml_feature_rows.append([entropy, length, vowel_ratio, digit_ratio, subdomains])

    X = np.array(ml_feature_rows)

    # Warmup
    _ = model.predict_proba(X)

    t0 = time.perf_counter()
    for _ in range(20):
        _ = model.predict_proba(X)[:, 1]
    t1 = time.perf_counter()
    print(f"20 x 50-row predict_proba calls with n_jobs=1: {t1 - t0:.4f}s")

if __name__ == "__main__":
    main()
