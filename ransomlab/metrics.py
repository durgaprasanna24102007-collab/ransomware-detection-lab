def confusion_metrics(rows):
    tp = fp = tn = fn = 0
    for r in rows:
        expected = str(r.get("expected", "")).lower()
        detected = bool(r.get("detected", False))
        positive = expected in {"positive", "attack", "suspicious"}
        if positive and detected: tp += 1
        elif positive and not detected: fn += 1
        elif not positive and detected: fp += 1
        else: tn += 1
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    fpr = fp / (fp + tn) if fp + tn else 0.0
    return {"TP": tp, "FP": fp, "TN": tn, "FN": fn,
            "precision": precision, "recall": recall, "false_positive_rate": fpr}
