//! The decision layer ("System 1"): fast, calibrated decisions that route work.
//!
//! A classifier proposes something (an intent, a candidate action) with a confidence.
//! [`RoutingPolicy`] combines that confidence with the action's [`RiskLevel`] to decide
//! whether it runs on its own, waits for a technician, or goes to a human entirely.
//!
//! Providers are pluggable (ADR-0005): a calibrated classifier API such as TypeSafe's
//! Jev, or a general LLM as fallback. Nothing outside this crate depends on a provider.

use std::future::Future;

pub use ponte_actions::RiskLevel;

/// A value with a calibrated confidence in `[0, 1]`.
#[derive(Debug, Clone, PartialEq)]
pub struct Scored<T> {
    pub value: T,
    pub confidence: f32,
}

/// Classifies a support ticket into one of the given labels.
pub trait IntentClassifier {
    type Error: std::error::Error + Send + Sync + 'static;

    /// Returns one score per label, highest confidence first.
    fn classify(
        &self,
        ticket_text: &str,
        labels: &[&str],
    ) -> impl Future<Output = Result<Vec<Scored<String>>, Self::Error>> + Send;
}

/// What happens to a proposed action.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Route {
    /// Runs without a human in the loop. Logged like everything else.
    AutoExecute,
    /// Waits in the approval queue for a technician.
    NeedsApproval,
    /// The proposal is not trusted enough to act on: hand the ticket to a human.
    EscalateToHuman,
}

#[derive(Debug, Clone, PartialEq, thiserror::Error)]
#[error("thresholds must satisfy 0 <= approval ({approval}) <= auto ({auto}) <= 1")]
pub struct InvalidThresholds {
    pub approval: f32,
    pub auto: f32,
}

/// The risk x confidence matrix.
///
/// The default thresholds are placeholders. They only become meaningful after the
/// provider's calibration is measured on labelled Portuguese tickets (RF-48).
#[derive(Debug, Clone, PartialEq)]
pub struct RoutingPolicy {
    auto_threshold: f32,
    approval_threshold: f32,
    max_auto_risk: RiskLevel,
}

impl RoutingPolicy {
    /// # Errors
    /// Fails unless `0 <= approval_threshold <= auto_threshold <= 1`.
    pub fn new(
        auto_threshold: f32,
        approval_threshold: f32,
        max_auto_risk: RiskLevel,
    ) -> Result<Self, InvalidThresholds> {
        let valid = (0.0..=1.0).contains(&approval_threshold)
            && (0.0..=1.0).contains(&auto_threshold)
            && approval_threshold <= auto_threshold;
        if !valid {
            return Err(InvalidThresholds {
                approval: approval_threshold,
                auto: auto_threshold,
            });
        }
        // High-risk actions are never auto-executed, whatever the configuration says.
        let max_auto_risk = max_auto_risk.min(RiskLevel::Medium);
        Ok(Self {
            auto_threshold,
            approval_threshold,
            max_auto_risk,
        })
    }

    #[must_use]
    pub fn route(&self, risk: RiskLevel, confidence: f32) -> Route {
        if confidence.is_nan() || confidence < self.approval_threshold {
            return Route::EscalateToHuman;
        }
        if risk <= self.max_auto_risk && confidence >= self.auto_threshold {
            Route::AutoExecute
        } else {
            Route::NeedsApproval
        }
    }
}

impl Default for RoutingPolicy {
    fn default() -> Self {
        Self {
            auto_threshold: 0.9,
            approval_threshold: 0.6,
            max_auto_risk: RiskLevel::Low,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_matrix() {
        let p = RoutingPolicy::default();
        assert_eq!(p.route(RiskLevel::Read, 0.95), Route::AutoExecute);
        assert_eq!(p.route(RiskLevel::Low, 0.95), Route::AutoExecute);
        assert_eq!(p.route(RiskLevel::Medium, 0.95), Route::NeedsApproval);
        assert_eq!(p.route(RiskLevel::High, 0.99), Route::NeedsApproval);
        assert_eq!(p.route(RiskLevel::Low, 0.7), Route::NeedsApproval);
        assert_eq!(p.route(RiskLevel::Read, 0.3), Route::EscalateToHuman);
    }

    #[test]
    fn nan_confidence_escalates() {
        let p = RoutingPolicy::default();
        assert_eq!(p.route(RiskLevel::Read, f32::NAN), Route::EscalateToHuman);
    }

    #[test]
    fn high_risk_is_never_auto_executed() {
        let p = RoutingPolicy::new(0.0, 0.0, RiskLevel::High).unwrap();
        assert_eq!(p.route(RiskLevel::High, 1.0), Route::NeedsApproval);
    }

    #[test]
    fn invalid_thresholds_are_rejected() {
        assert!(RoutingPolicy::new(0.5, 0.8, RiskLevel::Low).is_err());
        assert!(RoutingPolicy::new(1.2, 0.8, RiskLevel::Low).is_err());
        assert!(RoutingPolicy::new(0.9, f32::NAN, RiskLevel::Low).is_err());
    }
}
