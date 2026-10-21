-- Signing keys, the catalog of signed manifests and action requests (M2, ADR-0010 and
-- ADR-0012).
--
-- The rules a store follows are written on `ActionStore` and `ActionAdmin` in
-- `src/agents/store/actions.rs`. The constraints here are the second line, as in 0001.
--
-- Dates that travel in a signed envelope or a request (`issued_at`, `expires_at`) are
-- seconds since the Unix epoch, as the wire has them, in a `bigint`: the server converts
-- them with a check both ways and never saturates. Instants of the server itself are
-- `timestamptz`, as in 0001.

-- The keys the server trusts to sign manifests (`catalog key`). Public keys only: the
-- private key never comes near the server (ADR-0003, ADR-0010).
CREATE TABLE signing_keys (
    public_key bytea       PRIMARY KEY CHECK (octet_length(public_key) = 32),
    added_at   timestamptz NOT NULL
);

-- Every envelope `catalog add` accepted. Identified by the SHA-256 of the public key
-- followed by the transcript, so re-signing a version adds a row instead of colliding.
-- Rows stay when a key is removed: requests point at them.
CREATE TABLE manifests (
    hash        bytea       PRIMARY KEY CHECK (octet_length(hash) = 32),
    -- The rule of `ponte_actions`: lowercase dotted segments, at most 64 bytes. Printed
    -- in a terminal, so nothing else may get in.
    manifest_id text        NOT NULL CHECK (
        octet_length(manifest_id) <= 64
        AND manifest_id ~ '^[a-z][a-z0-9-]*(\.[a-z][a-z0-9-]*)+$'
    ),
    version     bigint      NOT NULL CHECK (version BETWEEN 1 AND 4294967295),
    risk        text        NOT NULL CHECK (risk IN ('read', 'low', 'medium', 'high')),
    -- The exact TOML that was signed (`ManifestText`).
    manifest    text        NOT NULL CHECK (octet_length(manifest) BETWEEN 1 AND 16384),
    issued_at   bigint      NOT NULL CHECK (issued_at >= 0),
    expires_at  bigint      NOT NULL CHECK (expires_at > issued_at),
    public_key  bytea       NOT NULL CHECK (octet_length(public_key) = 32),
    signature   bytea       NOT NULL CHECK (octet_length(signature) = 64),
    added_at    timestamptz NOT NULL
);

CREATE INDEX manifests_id_version ON manifests (manifest_id, version);

-- What an operator asked for, and what became of it. The table M3 turns into the queue of
-- approvals.
CREATE TABLE action_requests (
    id            uuid        PRIMARY KEY,
    device_id     uuid        NOT NULL REFERENCES devices (id),
    manifest_hash bytea       NOT NULL REFERENCES manifests (hash),
    -- `ponte_protocol::Initiator`, as the server wrote it. Read back strictly.
    initiator     jsonb       NOT NULL,
    expires_at    bigint      NOT NULL CHECK (expires_at >= 0),
    -- `cancelled` with no `sent_at` is an operator's cancel; with one, the agent's answer.
    -- `expired` is a request that was never sent.
    status        text        NOT NULL CHECK (status IN (
        'queued', 'sent', 'succeeded', 'failed', 'rejected', 'cancelled', 'timed_out', 'expired'
    )),
    created_at    timestamptz NOT NULL,
    sent_at       timestamptz,
    finished_at   timestamptz,
    -- The code of `failed` (`FailReason`) or `rejected` (`RejectReason`), never text.
    reason        text        CHECK (reason ~ '^[a-z_]{1,64}$'),
    step          smallint    CHECK (step BETWEEN 0 AND 255),
    duration_ms   bigint      CHECK (duration_ms >= 0),
    -- Untrusted text from the machine (`Output`): bounded here too, and never logged.
    output        text        CHECK (octet_length(output) <= 65536),
    CONSTRAINT action_requests_sent CHECK ((status = 'queued') = (sent_at IS NULL)
        OR status IN ('cancelled', 'expired')),
    CONSTRAINT action_requests_never_sent CHECK (
        status <> 'expired' OR sent_at IS NULL),
    CONSTRAINT action_requests_finished CHECK (
        (status IN ('queued', 'sent')) = (finished_at IS NULL)),
    CONSTRAINT action_requests_answered CHECK (
        (status IN ('queued', 'sent', 'expired') OR (status = 'cancelled' AND sent_at IS NULL))
        = (duration_ms IS NULL)),
    CONSTRAINT action_requests_reason CHECK (
        (status IN ('failed', 'rejected')) = (reason IS NOT NULL)),
    CONSTRAINT action_requests_step CHECK (status = 'failed' OR step IS NULL),
    CONSTRAINT action_requests_output CHECK (duration_ms IS NOT NULL OR output IS NULL)
);

CREATE INDEX action_requests_device ON action_requests (device_id, status);
CREATE INDEX action_requests_due ON action_requests (status, expires_at);

-- When the server stored the last heartbeat it kept (RF-49: an active device's only), to
-- show each device's clock offset against `collected_at` (ADR-0010).
ALTER TABLE devices ADD COLUMN telemetry_at timestamptz;
