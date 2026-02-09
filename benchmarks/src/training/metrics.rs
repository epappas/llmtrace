//! Validation metrics for fusion classifier training.
//!
//! Computes confusion-matrix-derived metrics from predicted and ground-truth labels.

/// Validation metrics computed from a confusion matrix.
#[derive(Debug, Clone)]
pub struct ValidationMetrics {
    pub accuracy: f64,
    pub precision: f64,
    pub recall: f64,
    pub f1: f64,
    pub fpr: f64,
    pub tp: usize,
    pub fp: usize,
    pub tn: usize,
    pub fn_count: usize,
}

/// Compute validation metrics from predicted and ground-truth labels.
///
/// Class 0 = safe (benign), Class 1 = injection (malicious).
pub fn compute_validation_metrics(predictions: &[i64], labels: &[i64]) -> ValidationMetrics {
    assert_eq!(
        predictions.len(),
        labels.len(),
        "predictions and labels must have same length"
    );

    let mut tp: usize = 0;
    let mut fp: usize = 0;
    let mut tn: usize = 0;
    let mut fn_count: usize = 0;

    for (&pred, &label) in predictions.iter().zip(labels.iter()) {
        match (pred, label) {
            (1, 1) => tp += 1,
            (1, 0) => fp += 1,
            (0, 0) => tn += 1,
            (0, 1) => fn_count += 1,
            _ => {}
        }
    }

    let total = (tp + fp + tn + fn_count) as f64;
    let accuracy = if total > 0.0 {
        (tp + tn) as f64 / total
    } else {
        0.0
    };

    let precision = if tp + fp > 0 {
        tp as f64 / (tp + fp) as f64
    } else {
        0.0
    };

    let recall = if tp + fn_count > 0 {
        tp as f64 / (tp + fn_count) as f64
    } else {
        0.0
    };

    let f1 = if precision + recall > 0.0 {
        2.0 * precision * recall / (precision + recall)
    } else {
        0.0
    };

    let fpr = if fp + tn > 0 {
        fp as f64 / (fp + tn) as f64
    } else {
        0.0
    };

    ValidationMetrics {
        accuracy,
        precision,
        recall,
        f1,
        fpr,
        tp,
        fp,
        tn,
        fn_count,
    }
}

impl std::fmt::Display for ValidationMetrics {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "acc={:.4} prec={:.4} rec={:.4} f1={:.4} fpr={:.4} (tp={} fp={} tn={} fn={})",
            self.accuracy,
            self.precision,
            self.recall,
            self.f1,
            self.fpr,
            self.tp,
            self.fp,
            self.tn,
            self.fn_count,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_perfect_predictions() {
        let preds = vec![0, 0, 1, 1];
        let labels = vec![0, 0, 1, 1];
        let m = compute_validation_metrics(&preds, &labels);
        assert!((m.accuracy - 1.0).abs() < 1e-9);
        assert!((m.precision - 1.0).abs() < 1e-9);
        assert!((m.recall - 1.0).abs() < 1e-9);
        assert!((m.f1 - 1.0).abs() < 1e-9);
        assert!((m.fpr).abs() < 1e-9);
    }

    #[test]
    fn test_all_wrong() {
        let preds = vec![1, 1, 0, 0];
        let labels = vec![0, 0, 1, 1];
        let m = compute_validation_metrics(&preds, &labels);
        assert!((m.accuracy).abs() < 1e-9);
        assert!((m.precision).abs() < 1e-9);
        assert!((m.recall).abs() < 1e-9);
        assert!((m.fpr - 1.0).abs() < 1e-9);
    }

    #[test]
    fn test_mixed() {
        // 3 TP, 1 FP, 2 TN, 1 FN
        let preds = vec![1, 1, 1, 1, 0, 0, 0];
        let labels = vec![1, 1, 1, 0, 0, 0, 1];
        let m = compute_validation_metrics(&preds, &labels);
        assert_eq!(m.tp, 3);
        assert_eq!(m.fp, 1);
        assert_eq!(m.tn, 2);
        assert_eq!(m.fn_count, 1);
        assert!((m.accuracy - 5.0 / 7.0).abs() < 1e-9);
        assert!((m.precision - 3.0 / 4.0).abs() < 1e-9);
        assert!((m.recall - 3.0 / 4.0).abs() < 1e-9);
        assert!((m.fpr - 1.0 / 3.0).abs() < 1e-9);
    }

    #[test]
    fn test_empty() {
        let m = compute_validation_metrics(&[], &[]);
        assert!((m.accuracy).abs() < 1e-9);
        assert!((m.f1).abs() < 1e-9);
    }

    #[test]
    fn test_all_positive() {
        let preds = vec![1, 1, 1];
        let labels = vec![1, 1, 1];
        let m = compute_validation_metrics(&preds, &labels);
        assert!((m.recall - 1.0).abs() < 1e-9);
        assert!((m.fpr).abs() < 1e-9); // no negatives
    }
}
