# crates/sign

`ponte-sign`, the offline tool that signs action manifests (ADR-0010). Whoever holds its
key decides what every agent that trusts the key may run, so this crate guards the key
and shows the person signing exactly what they sign.

- **The password comes from the terminal only.** `cli::Console::password` is the one door:
  `rpassword` in the binary, a scripted console in `cfg(test)`. Never add a flag, an
  environment variable, a file or a read from stdin that takes a password: it would end
  up in a shell history, a CI log or a process list.
- **A key file is never overwritten** (`create_new`), and `keygen` checks the `.pub` too
  before asking anything. Losing a key is worse than an error message. `sign --out` only
  replaces a file that is already an envelope (renewing a signature), through a temporary
  file and a rename. Where files have modes the key file is `0600`; on Windows the
  folder's access list decides, and the key is encrypted either way.
- **The key file is fail closed.** Unknown fields, formats and algorithms are refused, and
  so is an argon2 cost outside its range (`keyfile.rs`): below it a stolen file is cheap
  to attack, above it opening the file exhausts the machine. The public key is in the
  associated data, and after decrypting the private key must make that public key.
- **Sign what was shown.** `sign` validates with `validate_shape`, prints the summary
  from the same parsed manifest, signs the exact bytes that were read, and verifies its
  own envelope with `ponte_actions::verify` before writing it. Without `--yes` it writes
  nothing and asks for no password.
- Validity: `issued_at` one hour before the clock, 90 days by default, 1 to 365 (ADR-0010).
- Secrets are wiped after use (`Password` on drop, derived keys with `fill(0)`,
  `SigningKey` by `ed25519-dalek`), and never printed: `Password` has a redacted `Debug`.
- Messages may quote the user's own manifest (it is their file); nothing here logs.
- Tests run the whole command line in the process (`src/tests.rs`) and the real binary
  on the commands that need no password (`tests/cli.rs`). argon2 runs at its real cost in
  tests; the root `Cargo.toml` optimises it in dev builds.
