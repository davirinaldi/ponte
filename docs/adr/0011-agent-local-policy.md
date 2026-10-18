# 0011. The agent applies a local policy of its own to every signed manifest

- Status: Accepted
- Date: 2026-10-18
- Requirements: RF-11, RF-12, RF-13, RF-14, RF-19, RNF-02, RNF-03

## Context

A signature says who wrote a manifest, not that running it here and now is safe. ADR-0003
promised a local policy (allowed roots, a risk ceiling, consent for high risk) that the
agent applies whatever the server decided. Today it has only the first:

- `AgentConfig` has `allowed_roots` and nothing else about actions. No risk ceiling, no
  list of services, no rate limit. Any signed manifest may stop `WinDefend`.
- `PathPolicy` is lexical. It refuses `..`, UNC and device paths, alternate data streams,
  trailing dots and spaces, DOS device names and wildcards, but it accepts a whole drive
  (`C:\`) as a root, and it cannot see junctions, symbolic links or hard links.
- `Manifest::validate` checks shapes when someone calls it. Nothing stops code from
  running a `Manifest` that was never validated, and nothing bounds the number of steps
  or the length of a description.
- A verify check can be filler: nothing ties it to what the steps touched, and there is no
  check that a path is gone.

M2 also brings an adversary the earlier milestones did not have to face: the ordinary user
of the PC. That user often has write access to the ERP's folders, can create folders under
`C:\` and `C:\ProgramData`, can plant junctions and hard links, can create named pipes and
can race the agent. The agent runs as SYSTEM, so every file it opens on behalf of a
manifest is a chance for that user to point it somewhere else.

## Decision

### What M2 runs

- **Primitives:** `service_start`, `service_stop`, `service_restart` and `delete_file`.
- **Checks:** `service_state`, `path_exists`, `disk_free_at_least` and a new `path_absent`.
- **Refused:** `clear_temp_dir`, `read_file_tail`, `kill_process` and `sql_readonly`, by
  the agent and by `ponte-sign`, until each has a design of its own in an ADR.
  `clear_temp_dir` works in a profile folder the user controls, where a junction swapped
  at the right moment would make SYSTEM delete files of Windows. `read_file_tail` is how a
  compromised server would pull personal data off a machine; it waits for the approvals
  of M3. `kill_process` and `sql_readonly` have no manifest that needs them yet, and the
  safety of the second rests on a database account the agent cannot see. The types stay
  in `Primitive`; refusing them is policy, not a format change.

### What the configuration adds

| Field | Meaning | Default |
|---|---|---|
| `max_risk` | The highest risk the agent runs: `read`, `low` or `medium` | `medium` |
| `allowed_services` | Up to 32 service names, ASCII only. Every service a step or a check names must be on it | empty: no service is touched |
| `delete_roots` | Where `delete_file` may act, each inside an `allowed_root` | empty: nothing is deleted |
| `max_actions_per_hour` | Requests marked "started" in the last hour, counted from the journal on disk (ADR-0012), 1 to 60 | 20 |
| `min_manifest_interval_secs` | Time between two runs of the same manifest id, any version, 60 to 86 400 | 600 |

One action runs at a time. The two limits count the requests the journal marked "started",
which happens once preconditions pass and before the first step (ADR-0012), so a refused
request costs nothing towards them, and they are read from the journal so a restart does
not reset them. They exist for a compromised server in a loop: twenty restarts of the ERP in an
hour already stops a business, and the per-manifest interval caps any one action at six an
hour by default. Service names are compared case-insensitively, as Windows does, over ASCII.
The ceiling defaults to `medium` because the lists default to empty: naming a service or a
delete root is already the deliberate act, and a ceiling of `low` would only add a second
setting to every installation that restarts a service. That holds only while every
primitive at `medium` or above needs a list entry; the ADR that re-enables a refused
primitive revisits this default.

### Services refused whatever the list says

A compiled list of names is refused, and it wins over `allowed_services`: `WinDefend`,
`MpsSvc`, `EventLog`, `RpcSs`, `CryptSvc`, `BFE`, `Sense`, `WdFilter`, `lsass`, the agent's
own service and others, kept in the code with a test. A list of names never covers every
antivirus or third-party driver, so a structural rule backs it up. Read from the service
manager when the action runs, not when the configuration loads, a service is refused if:

- its type is anything but `SERVICE_WIN32_OWN_PROCESS` (drivers and shared `svchost`
  services are out);
- it is a protected service (`SERVICE_CONFIG_LAUNCH_PROTECTED` other than none);
- its binary lies inside `%SystemRoot%`, or its binary path cannot be parsed;
- its name is not ASCII.

These rules apply to every service a manifest names, in steps and in checks alike: nothing
in M2 needs to read the state of a refused service, and one rule has fewer gaps than two.

### Roots, kept apart

`allowed_roots` bound the path checks. `delete_roots` bound `delete_file`, and each must lie
inside an `allowed_root`. A careless signer then cannot delete the ERP's database just
because its folder is readable. No root of either kind may be:

- a whole drive;
- the Windows folder or anything inside it;
- a `Program Files` folder, `ProgramData`, the folder that holds user profiles, or the root
  of any user's profile (folders inside them are allowed);
- `$Recycle.Bin`, `System Volume Information`, `Recovery` or `Boot` at the root of a drive,
  or anything inside them;
- the folder of the agent's executable, or anything inside it.

The forbidden folders are named by what Windows reports for them (known folders and the
profile list), not by hard-coded drive letters. The lexical check that runs everywhere
(`PathPolicy::new`) applies the usual names on every drive letter, since it cannot know
which drive Windows is on and a `Windows` folder on another drive is no place for a root
either; it also counts `Program Files (Arm)` and `Documents and Settings` (the old name
of the profiles folder, still a junction) among the folders above, and refuses any root
with a `~` in it, because `C:\PROGRA~1` is `Program Files` under its short name. Step 3 of
M2 added those three; the plan had only the usual locations under `C:`. The rule holds for the path as written and for the path the
root resolves to when the agent starts. The configuration file, the `data_dir` and the
enrollment token may not lie inside any root.

### Verification covers what the steps touched

RF-13 asks for at least one verify check; a check that names something else proves nothing.

- Every service and every path a step names must also be named by a verify check:
  `service_state` for a service, `path_exists` or `path_absent` for a path.
- Every `delete_file` has a `path_exists` precondition on the same path.
- The expected state is the signer's to choose, and `ponte-sign sign` prints it. A verify
  that contradicts its step makes the action fail, which is safe.

This corrects the plan of M2, which demanded `path_absent` whenever `delete_file` was the
last step naming a path. `erp.clear-stale-lock` deletes the lock and then starts the ERP,
which creates the lock again; a forced `path_absent` would fail every time on the very case
the action exists for.

### The configuration is a root of trust

`manifest_keys` makes the configuration decide what SYSTEM runs (ADR-0010). When the agent
runs elevated, which it learns from its token and not from how it was started, it refuses
to start unless:

- the configuration file, the `data_dir` and the enrollment token, and the folders that
  hold them, are owned by SYSTEM or Administrators and grant no right to change them (write,
  append, delete, change the ACL or the owner) to anyone else;
- every folder above those, up to the root of the drive, is owned by SYSTEM, Administrators
  or TrustedInstaller and grants nobody else the right to delete or rename what it holds
  (`DELETE`, `FILE_DELETE_CHILD`) or to change its ACL or owner. Others may still create new
  entries there: `C:\` and `C:\ProgramData` allow that to every user by default, and it does
  not let them replace an entry that already exists.

The `data_dir` is created with a protected ACL that inherits nothing. Logs, the journal and
the key are opened as in the next section. An elevated agent refuses `ws://`, even to this
machine: any local process that binds the port first would otherwise be "the server", and
could take the enrollment token. ADR-0013 says how this applies to the service.

The plan of M2 asked that every folder above these files be owned by SYSTEM or
Administrators with no write access for anyone else. Taken literally, `C:\` and
`C:\ProgramData` fail that rule on every Windows machine, so the rule above names the
rights that matter instead.

### Opening a file on the user's ground

Every path that comes from a manifest, the configuration or the token is opened:

- with `SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION`, so a named pipe planted at the
  end of a path cannot impersonate SYSTEM, and with `FILE_FLAG_OPEN_REPARSE_POINT`, so a
  reparse point at the end of the path is opened, not followed, and then refused;
- then checked: `GetFileType` must be `FILE_TYPE_DISK`; a `delete_file` target must be a
  regular file with exactly one link; a path check accepts a regular file or a directory,
  never a reparse point;
- without `FILE_SHARE_DELETE`, so nobody renames or deletes it while the agent holds it.

Reparse points in the middle of a path are still followed by Windows, so the agent then
reads the final path of the handle (`GetFinalPathNameByHandleW`) and checks it against the
roots as they resolved at start, segment by segment with `CompareStringOrdinal`, ignoring
case the way the file system does. The lexical check folds ASCII only, so the two can
disagree; a path must pass both. A final path under `\\?\UNC\` or on a volume with no
drive letter (`\\?\Volume{...}`) is refused. `delete_file` deletes through the same handle
(`FileDispositionInfo`), so what was checked is what goes. `path_absent` holds only when
Windows answers "file not found" or "path not found"; any other error is a failed check,
never "absent". Short 8.3 names, alternate data streams and hard links are covered by the
lexical policy, the final-path check and the link count.

### Only a validated type runs

`Manifest` → `ValidManifest` → `VerifiedManifest` → `RunnableManifest`.

- `validate_shape()` makes a `ValidManifest` without knowing the machine: id, names, risk,
  coverage, the primitives this release runs, the lexical shape of paths, and limits: at
  most 16 steps, 16 checks per list, a title of 120 characters and descriptions of 2,000,
  on top of the 16 KiB of the signed text (ADR-0010) and the limits that exist today
  (timeout 1 to 600 seconds, names of 256 characters). `ponte-sign` and the server's
  catalog use it.
- `verify` (ADR-0010) checks the signature and the validity, then parses and validates the
  shape. It is the only way to a `VerifiedManifest`.
- `VerifiedManifest::validate(&LocalPolicy)` adds the agent's roots, services and risk
  ceiling and yields a `RunnableManifest`, which therefore only exists after the signature
  and its validity were checked. Only a `RunnableManifest` can be executed.

Step 3 of M2 changed three things the plan had:

- The plan named three states. With three, `validate` would have hung on the
  `ValidManifest` that `ponte-sign` makes without any signature, so a fourth state sits
  between them.
- A few shape rules the plan left out: an id of at most 64 bytes, a version of at least 1,
  a title and descriptions that are not blank and a title on one line, service names in
  ASCII (the agent refuses any other service anyway, so the signer learns it first), and
  paths that name something below the drive. Errors name the rule and the place (step 2,
  verify check 0), never the path or the name, so an agent can log them without logging
  what a manifest touches.
- The list of refused services lives beside the policy in `ponte-actions`, so a
  `RunnableManifest` never names one. The structural refusals read the service manager and
  stay in the agent.

### High risk

`high` is refused. A configuration that sets `max_risk = "high"` is refused until the
session helper of M4 can ask the person at the machine (RF-19); from then on `high` needs
both the setting and that consent. The plan of M2 let `high` run with an explicit setting;
that would have broken ADR-0003, which promised consent for high risk, so the setting waits
for the consent.

### Parameters

RF-12 asks for parameters validated by a schema. Manifests stay without them in M2: paths
and service names are fixed and signed. A parameter is a hole in the signature by design,
so it comes after M2 with an ADR of its own.

## Consequences

- A signed manifest is no longer enough. It must also fit the machine's configuration,
  which the software house's installer writes for each site, and an installer that forgets
  a service or a root makes actions fail with a clear refusal.
- A compromised server cannot touch a service or a file outside what the configuration
  names, cannot stop the security services of Windows, and cannot run more than the rate
  limits allow. It can still run any allowed manifest at a moment of its choosing
  (ADR-0012).
- Some legitimate services are out: anything that shares an `svchost`, anything installed
  under `%SystemRoot%`, protected services. Supporting one is a change to this ADR.
- The ACL rule can refuse to start on a machine where someone loosened the permissions of
  `C:\ProgramData`. The refusal goes to the Event Log (ADR-0013), because the log folder
  itself is not trusted then.
- The Windows file layer is the most delicate code of the milestone, and it is
  Windows-only: its tests run in the Windows job of CI, and the parts that do not depend on
  Windows (roots, coverage, limits) are tested everywhere.
- Restarting a service whose binary a user can replace gives that user SYSTEM. The policy
  cannot see that; it is an accepted risk in `docs/threat-model.md`, with install guidance.
- Four primitives listed in RF-11 do not run in M2, and neither do parameters (RF-12).

## Alternatives considered

- **Trust the signature alone**: one software house's key then decides what runs on every
  machine it signs for, with no say for the site, and a careless manifest has no second
  line.
- **Allow and deny lists of services only by name**: simple, but no list keeps up with
  antivirus products and drivers. The structural rule does.
- **One set of roots for reading and deleting**: fewer settings, but a root wide enough to
  check that the ERP's database exists would also let a manifest delete it.
- **Resolve every path with `canonicalize` before opening it**: a check and a use that are
  two calls apart, which a user can race with a junction. Checking the open handle closes
  that window.
- **A virtual service account instead of SYSTEM, to shrink what a mistake can reach**:
  rejected in ADR-0013.
- **Ship `clear_temp_dir` and `read_file_tail` in M2 with extra checks**: neither is needed
  by the demo, and each needs a design (a profile folder the user owns; data leaving the
  machine) that M2 has no time to get right.
