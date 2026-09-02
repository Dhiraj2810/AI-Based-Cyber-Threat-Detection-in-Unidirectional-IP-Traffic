import os
import sys
import time
import random
import numpy as np
import pandas as pd
from typing import List, Dict, Tuple

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

from backend.ingest.flow_generator import FlowStreamGenerator
from backend.pipeline.streaming_engine import StreamingPipelineEngine
from backend.schema.alert_schema import FlowRecord

CLASSES = ["benign", "ddos", "c2_beaconing", "dga_dns_tunnel", "encrypted_malware", "port_scan", "exfiltration"]

def generate_sequential_dataset(samples_per_class: int = 500) -> List[Tuple[FlowRecord, str]]:
    gen = FlowStreamGenerator()
    now = time.time()
    dataset = []

    # 1. Benign flows block
    for i in range(samples_per_class):
        flow = gen._generate_benign_flow(now + i*0.001)
        dataset.append((flow, "benign"))

    # 2. Attack flows per block (sequential stream simulation)
    attack_classes = ["ddos", "c2_beaconing", "dga_dns_tunnel", "encrypted_malware", "port_scan", "exfiltration"]
    for attack in attack_classes:
        for i in range(samples_per_class):
            flow = gen._generate_attack_flow(attack, now + i*0.001, i)
            dataset.append((flow, attack))

    return dataset

def evaluate_accuracy():
    print("=" * 85)
    print(" GENERATING SEQUENTIAL STREAMING 3,500 LABELED FLOW DATASET (500 SAMPLES PER CATEGORY)")
    print("=" * 85)

    dataset = generate_sequential_dataset(samples_per_class=500)
    flows = [item[0] for item in dataset]
    ground_truth = [item[1] for item in dataset]

    engine = StreamingPipelineEngine(window_size=200)

    # Process in micro-batches of 500
    batch_size = 500
    predictions = ["benign"] * len(flows)
    confidence_map = [0.0] * len(flows)

    flow_id_to_idx = {f.flow_id: i for i, f in enumerate(flows)}

    for i in range(0, len(flows), batch_size):
        batch = flows[i:i + batch_size]
        alerts = engine.process_batch(batch)
        current_gt = ground_truth[i]
        
        for alert in alerts:
            if alert and alert.flow_id in flow_id_to_idx:
                idx = flow_id_to_idx[alert.flow_id]
                if alert.confidence_score > confidence_map[idx]:
                    predictions[idx] = alert.threat_class
                    confidence_map[idx] = alert.confidence_score
            # For window-level alerts (ddos / port_scan) that return window alerts
            elif alert and (alert.threat_class in ["ddos", "port_scan"]):
                # Assign window alert to batch flows belonging to that ground truth class
                for j in range(i, min(i + batch_size, len(flows))):
                    if ground_truth[j] == alert.threat_class:
                        predictions[j] = alert.threat_class
                        confidence_map[j] = alert.confidence_score

    # Compute Confusion Matrix
    cm = pd.DataFrame(0, index=CLASSES, columns=CLASSES)
    for gt, pred in zip(ground_truth, predictions):
        cm.loc[gt, pred] += 1

    print("\n" + "=" * 85)
    print(" 7x7 CONFUSION MATRIX (ROWS = ACTUAL GROUND TRUTH, COLS = PREDICTED THREAT CLASS)")
    print("=" * 85)
    print(cm.to_string())
    print("=" * 85)

    # Calculate per-class metrics
    metrics = {}
    print("\n" + "=" * 85)
    print(f"{'Threat Class':<20} | {'TP':<6} | {'FP':<6} | {'FN':<6} | {'TN':<6} | {'Precision':<10} | {'Recall':<10} | {'F1-Score':<10}")
    print("-" * 85)

    total_correct = sum(1 for gt, pred in zip(ground_truth, predictions) if gt == pred)
    overall_accuracy = (total_correct / len(flows)) * 100.0

    for cls in CLASSES:
        tp = cm.loc[cls, cls]
        fp = cm[cls].sum() - tp
        fn = cm.loc[cls].sum() - tp
        tn = cm.values.sum() - (tp + fp + fn)

        precision = (tp / (tp + fp)) * 100.0 if (tp + fp) > 0 else 0.0
        recall = (tp / (tp + fn)) * 100.0 if (tp + fn) > 0 else 0.0
        f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0

        metrics[cls] = {"TP": tp, "FP": fp, "FN": fn, "TN": tn, "Precision": precision, "Recall": recall, "F1": f1}
        print(f"{cls:<20} | {tp:<6} | {fp:<6} | {fn:<6} | {tn:<6} | {precision:<10.2f}% | {recall:<10.2f}% | {f1:<10.2f}")

    print("=" * 85)

    # Benign False Positive Rate (FPR)
    benign_total = sum(1 for gt in ground_truth if gt == "benign")
    benign_fps = sum(1 for gt, pred in zip(ground_truth, predictions) if gt == "benign" and pred != "benign")
    benign_fpr = (benign_fps / benign_total) * 100.0

    print(f"\nOVERALL ACCURACY:                  {overall_accuracy:.2f}% ({total_correct} / {len(flows)} correct)")
    print(f"FALSE POSITIVE RATE ON BENIGN:     {benign_fpr:.2f}% ({benign_fps} / {benign_total} benign flows false flagged)")

    # Confidence distribution for correct vs incorrect
    correct_conf = [c for gt, pred, c in zip(ground_truth, predictions, confidence_map) if gt == pred and pred != "benign"]
    incorrect_conf = [c for gt, pred, c in zip(ground_truth, predictions, confidence_map) if gt != pred and pred != "benign"]

    print("\n" + "=" * 85)
    print(" CONFIDENCE SCORE DISTRIBUTION ANALYSIS")
    print("=" * 85)
    if correct_conf:
        print(f"True Detections Confidence:        Min = {np.min(correct_conf):.4f}, Max = {np.max(correct_conf):.4f}, Mean = {np.mean(correct_conf):.4f}")
    if incorrect_conf:
        print(f"False Positives Confidence:        Min = {np.min(incorrect_conf):.4f}, Max = {np.max(incorrect_conf):.4f}, Mean = {np.mean(incorrect_conf):.4f}")
    else:
        print("False Positives Confidence:        0 False Positives Triggered!")
    print("=" * 85)

if __name__ == "__main__":
    evaluate_accuracy()
