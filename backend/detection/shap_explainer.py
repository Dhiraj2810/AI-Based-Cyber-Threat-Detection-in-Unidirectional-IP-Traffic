from typing import List, Dict, Any
from backend.schema.alert_schema import AlertEvidence

class ShapExplainer:
    """Helper to convert feature vector and importance weights into standardized evidence."""

    @staticmethod
    def explain(feature_dict: Dict[str, Any], feature_names: List[str], weights: List[float], descriptions: Dict[str, str]) -> List[AlertEvidence]:
        evidence_list = []
        for name, weight in zip(feature_names, weights):
            val = feature_dict.get(name, "N/A")
            desc = descriptions.get(name, f"Observed feature {name} = {val}")
            evidence_list.append(AlertEvidence(
                feature_name=name,
                value=val,
                description=desc,
                impact_score=round(float(weight), 4)
            ))
        # Sort evidence by absolute impact score descending
        evidence_list.sort(key=lambda x: abs(x.impact_score or 0.0), reverse=True)
        return evidence_list
