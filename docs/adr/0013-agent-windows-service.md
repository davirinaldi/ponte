# 0013. Run the agent as a Windows service under SYSTEM, with its key under DPAPI

- Status: Accepted
- Date: 2026-10-18
- Requirements: RF-44, RNF-01, RNF-03, RNF-04, RNF-12

## Context

The agent of M1 is a console program. Its device key is a plain file
(`platform::keystore`, `PROTECTED = false`), its data directory gets whatever permissions
its parent gives, and it says on every start that it is for development only. Under
`C:\ProgramData`, every local user can read those files and create files beside them.
`platform/windows.rs` is a placeholder.

M2 runs actions that need SYSTEM: starting and stopping other services and deleting files
the ERP owns. That turns every file the agent reads at start into a way in for a local
user (ADR-0011), and every crash into an incident on the machines it supports. The roadmap
promised for M2 a service lifecycle, the key under DPAPI in a data directory only SYSTEM
and administrators can open, key bytes wiped with `zeroize`, and a stop bounded by
`shutdown_timeout`.

## Decision

**The service.** The agent runs as a Windows service under LocalSystem. `ponte-agent
service --config <path>` is what the service manager starts; `ponte-agent run <config>`
runs the same agent in a console, for development and diagnosis. The lifecycle uses the
`windows-service` crate, and the Windows calls the agent makes itself go through
`windows-sys` with only the features it needs, at the version the tree already has if
`windows-service` allows it. Both stay under `cfg(windows)`. `zeroize` wipes every buffer
the agent owns that holds the key's secret, once it is no longer needed: the buffer DPAPI
returns (wiped before it is freed), the bytes read from disk, and the key type itself,
which wipes on drop and is kept behind a `Box` so that it is not copied by moves. The
signing key type of `ed25519-dalek` implements `Clone`, so "no copies" is held by review.
Copies a move leaves on the stack are out of reach; this is best effort, not a guarantee.

**Elevation is read from the token.** Whether the agent applies the ownership and ACL rules
of ADR-0011 and refuses `ws://` depends on whether its token is elevated, not on whether it
was started as a service. An administrator's elevated console gets the same rules as the
service; an ordinary console does not need them, because it can do no more than the user
who started it. If the agent cannot tell whether its token is elevated, it applies the
rules as if it were. An elevated agent also refuses to start when its own executable, or the
folder that holds it, can be changed by anyone but SYSTEM, Administrators or
TrustedInstaller. That does not stop a user who already replaced the binary, since the
replacement does not check, but it catches the mistake at install, before anyone relies on
it.

**The data directory** is created with a protected ACL that inherits nothing: SYSTEM and
Administrators, full control, nobody else. An existing one must pass the rule of ADR-0011
or the agent does not start.

**DPAPI (RNF-04).**

- The device key is protected with `CryptProtectData` in the scope of the account that runs
  the agent (SYSTEM in production), never the machine scope, with
  `CRYPTPROTECT_UI_FORBIDDEN` and a fixed context string as entropy, so the blob is not
  interchangeable with other DPAPI data of the same account.
- The plain key file of M1 is not migrated. The agent refuses it and asks for a new
  enrollment: migrating would leave the plain key recoverable on the disk, and no agent is
  in the field.
- A blob this account cannot open, typically one made by an administrator's elevated
  console before the service was installed, is refused with a message that names that
  likely cause and says to enroll again.

What DPAPI protects: the key in a copy or a backup of the data directory, and the key from
users without administrator rights, on top of the ACL. What it does not protect: anyone
who is an administrator or runs code as SYSTEM, since both can decrypt it, and anyone with
offline access to an unencrypted disk, since the secret behind SYSTEM's DPAPI lives in the
registry on that disk. A key bound to the TPM (RNF-04, "when available") comes later, with
an ADR.

**Stopping.** On a stop request the agent takes no new requests, closes its session and
waits up to `shutdown_timeout_secs` (10 by default, 1 to 60) for the running action,
telling the service manager it is still stopping. A run that does not finish in time is
left "started" in the journal and becomes `Failed { reason: Interrupted }` at the next start
(ADR-0012). When the whole machine shuts down Windows may give less time than that; the
journal covers what it cuts. Requests still waiting in the queue are dropped without an answer, since
the server sends them again when the next session starts, and a request that arrives
during the stop is refused with `ShuttingDown`. A request whose preconditions are being
read when the stop comes is not started. The process then ends without waiting for an
action that overran the timeout (`shutdown_background`).

**Logs.** As a service the agent writes to `<data_dir>\logs`, in two files of at most 5 MB
each, the older one replaced when the newer one is full. A small writer of its own does
it, opening each file as ADR-0011 opens files on the user's ground (no reparse point, one
link). In a console it writes to stderr as today. A failure before the log can be trusted
(a configuration refused, a data directory that fails the ACL rule) goes to the Event Log,
under the source `PonteAgent`, as a fixed code and the name of the setting at fault. Until
the installer registers a message file for that source, Event Viewer shows the text with a
note that the description is missing.

**Installation by `sc.exe` until the MSI of M5.** The walkthrough gives the commands:
`sc.exe create` with the executable under `Program Files`, its path quoted (an unquoted
path with spaces lets a user plant `C:\Program.exe`), `start= auto` and `obj= LocalSystem`,
and `sc.exe failure` with restart actions for RF-44. The configuration and the data
directory live under `C:\ProgramData\Ponte`, created with the ACL above.

## Consequences

- The agent can finally act, and a bug in it is a bug running as SYSTEM. The policy of
  ADR-0011, the strict parsing of ADR-0006 and the "never panic" rule are what keep that
  from becoming a takeover, and the security review of every change to the agent stays
  mandatory.
- An installer that gets the permissions wrong ends with an agent that refuses to start,
  and says why in the Event Log. That is deliberate and will cost support time.
- Lab machines of M1 on Windows enroll again (ADR-0012).
- DPAPI raises the bar for copying a key, not for an administrator or for someone holding
  the disk. BitLocker on the supported machines is the customer's choice and makes a
  difference here.
- Two new dependencies on Windows (`windows-service`, `windows-sys` named directly) count
  against the budget of RNF-12, and their size is measured with the rest in M2.
- Installing by hand with `sc.exe` is error-prone, which is why the walkthrough spells out
  every command and the agent checks its own executable's permissions.
- Starting without the source registered leaves Event Log entries that read awkwardly
  until the MSI exists.

## Alternatives considered

- **A virtual service account (`NT SERVICE\PonteAgent`) instead of SYSTEM**: least
  privilege today. The installer could grant it start and stop rights on each ERP service
  and write access to each delete root, and a bug would reach less. Rejected because the
  next steps need SYSTEM anyway: the session helper of M4 is started in the user's session
  with a token only SYSTEM can obtain (`WTSQueryUserToken`), and the remote control of
  phase 3 must reach the secure desktop and UAC prompts. Moving to SYSTEM later would mean
  two privilege models in a row. Splitting the agent into a SYSTEM broker and an
  unprivileged worker may be worth it once the helper exists; it is not an M2 change.
- **LocalService or NetworkService**: the same limits as a virtual account, shared with
  other services.
- **The service lifecycle written by hand**: about 150 lines of `unsafe` the project would
  own, against a small, widely used crate.
- **DPAPI in the machine scope**: any process of any user on the machine could decrypt the
  key.
- **Migrate the M1 key into DPAPI**: no new enrollment, but the plain key stays
  recoverable from the disk, and only lab machines would benefit.
- **`tracing-appender` for the file log**: more dependencies, and it does not open files
  the way a SYSTEM process on a user's machine must.
- **An MSI now**: the right end state, and a milestone of its own (M5).
