# 0009. Verify the server certificate against the operating system's trust store

- Status: Proposed
- Date: 2026-10-12
- Requirements: RNF-01

## Context

The agent speaks TLS through rustls (ADR-0004), and rustls must be told which certificate
authorities to trust. The roots can be compiled into the binary or read from the operating
system. Supported machines sit behind small-shop routers and sometimes behind corporate
proxies that inspect TLS with their own authority installed on each PC. Software houses that
self-host may also use a certificate from an internal authority. Nobody on site will debug a
connection that fails.

## Decision

The agent verifies the server certificate against the operating system's trust store.
Hostname verification stays on and plain `ws://` stays limited to localhost. There is no
certificate pinning in phase 1.

Whether this goes through `rustls-platform-verifier` or `rustls-native-certs` is decided in
M1 by binary size (RNF-12); both read the Windows store.

## Consequences

- The agent connects behind TLS inspection the customer's IT deployed, and to self-hosted
  servers with an internal authority, with no extra configuration.
- Whoever can add a root to the machine's store can read and alter the channel. For a local
  administrator that is nothing new: they already control the agent. A TLS-inspecting proxy is
  the real addition. It sees telemetry and action output, which may carry personal data from a
  log tail, and it can inject messages.
- What that proxy cannot do is bounded the same way as a compromised server: it can only
  trigger actions that are already signed, within local policy (ADR-0003), and it cannot pose
  as the device elsewhere without the device key (ADR-0008).
- Trust and revocation follow Windows updates instead of agent releases.
- The agent behaves differently from machine to machine, since stores differ. Connection
  errors must name the certificate problem in the log.

## Alternatives considered

- **Roots compiled into the binary (`webpki-roots`)**: the same behaviour everywhere and no
  dependency on the system, but it never connects behind TLS inspection or to an internal
  authority.
- **Pin the server's key or authority**: the strongest option, and rotating it means touching
  every machine. Worth offering later as an opt-in for customers that do not inspect TLS.
