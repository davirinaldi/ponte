# 0009. Verify the server certificate against the operating system's trust store

- Status: Accepted
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
Hostname verification stays on and plain `ws://` stays limited to localhost. Nothing is
pinned by default; an opt-in pin of the server's public key, for customers that do not
inspect TLS, comes with the hardening milestone (M5).

The verifier is `rustls-platform-verifier`, chosen in M1 over `rustls-native-certs`. Binary
size (RNF-12) was to decide and does not separate them: on x86_64 Windows with the release
profile, a minimal WebSocket client grows by 8 KB with the first and 47 KB with the second.
Behaviour does. Windows fetches root certificates on demand, so the store of a fresh or
rarely updated machine lists only a few. `rustls-native-certs` reads that list once and
trusts nothing else; the platform verifier asks Windows to build the chain, which fetches
the missing root, follows intermediate certificates and applies the machine's own policy.

The agent offers TLS 1.3 only (RNF-01) and names its crypto provider (`ring`) itself, so
nothing depends on a process-wide default.

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
- Verifying a certificate can make Windows fetch a root, an intermediate or revocation data
  over HTTP. The agent's connection deadline leaves room for that.
- An inspecting proxy that stops at TLS 1.2 does not connect.
- The agent behaves differently from machine to machine, since stores differ. Connection
  errors must name the certificate problem in the log.

## Alternatives considered

- **Roots compiled into the binary (`webpki-roots`)**: the same behaviour everywhere and no
  dependency on the system, but it never connects behind TLS inspection or to an internal
  authority.
- **Pin the server's key or authority by default**: the strongest option against
  interception, but rotating it means touching every machine, and one mistake locks the whole
  fleet out with no way to reach it. Kept as an opt-in.
