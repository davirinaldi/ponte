# 0005. Pluggable decision layer with risk x confidence routing

- Status: Accepted
- Date: 2026-10-12
- Requirements: RF-17, RF-46, RF-47, RF-48

## Context

Deciding what runs automatically by risk alone ignores how sure the system is. Calibrated
classifiers (for example TypeSafe's Jev, a typed "System 1" model that returns probabilities)
can say how confident a decision is, fast and cheaply. But such providers are young, closed,
and unproven on Brazilian Portuguese support text.

## Decision

`crates/decision` defines classifier traits and a `RoutingPolicy` that maps (risk, confidence) to
auto-execute, needs-approval or escalate. High risk is never auto-executed. Providers are
adapters behind the traits, with a general LLM as fallback. Confidence is stored with every
AI-initiated action. Thresholds that enable automatic execution are only set after a
calibration report on labelled Portuguese tickets.

## Consequences

- The core does not depend on any model vendor.
- Automation is earned by measurement, not by configuration.
- Extra work: a labelled dataset and a calibration report per provider.

## Alternatives considered

- **Risk-only policy**: simpler, but either too timid or too trusting.
- **Hard dependency on one provider**: faster to demo, but conflicts with self-hosted open source.
