import json
import os
from datetime import datetime


def save_json(target: str, data: dict, findings: dict) -> str:
    os.makedirs("output", exist_ok=True)
    ts   = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = f"output/scan_{ts}.json"

    all_findings = []
    for category, items in findings.items():
        for f in items:
            f["category"] = category
            all_findings.append(f)

    report = {
        "meta": {
            "target":    target,
            "timestamp": ts,
            "tool":      "VAPT Framework v0.3",
        },
        "recon":    data,
        "findings": all_findings,
    }

    with open(path, "w") as f:
        json.dump(report, f, indent=2, default=str)

    return path
