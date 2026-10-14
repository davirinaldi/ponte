-- Customers, enrollment tokens and devices (M1, ADR-0008).
--
-- The rules a store follows are written on `DeviceStore` and `DeviceAdmin` in
-- `src/agents/store.rs`. The constraints here are the second line: if the code ever gets a
-- rule wrong, the database refuses instead of storing it.

CREATE TABLE customers (
    id         uuid        PRIMARY KEY,
    name       text        NOT NULL UNIQUE CHECK (char_length(name) BETWEEN 1 AND 100),
    created_at timestamptz NOT NULL DEFAULT now()
);

-- The SHA-256 of each token, never the token: a copy of this table enrolls nobody.
CREATE TABLE enrollment_tokens (
    hash        bytea       PRIMARY KEY CHECK (octet_length(hash) = 32),
    customer_id uuid        NOT NULL REFERENCES customers (id),
    max_uses    bigint      NOT NULL CHECK (max_uses BETWEEN 1 AND 4294967295),
    uses        bigint      NOT NULL DEFAULT 0 CHECK (uses >= 0 AND uses <= max_uses),
    expires_at  timestamptz NOT NULL,
    revoked_at  timestamptz,
    created_at  timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX enrollment_tokens_customer ON enrollment_tokens (customer_id);

CREATE TABLE devices (
    id             uuid        PRIMARY KEY,
    customer_id    uuid        NOT NULL REFERENCES customers (id),
    -- A key enrolls once.
    public_key     bytea       NOT NULL CHECK (octet_length(public_key) = 32),
    enrolled_with  bytea       NOT NULL REFERENCES enrollment_tokens (hash),
    status         text        NOT NULL CHECK (status IN ('pending', 'active', 'revoked')),
    -- What the agent said about itself when it last connected. Untrusted.
    agent_version  text        NOT NULL CHECK (char_length(agent_version) BETWEEN 1 AND 64),
    os             text        NOT NULL CHECK (char_length(os) BETWEEN 1 AND 64),
    enrolled_at    timestamptz NOT NULL DEFAULT now(),
    -- The session the device is connected under; NULL when it is not connected.
    online_session uuid,
    last_seen      timestamptz,
    -- The last heartbeat of an active device (RF-49: never one of a pending device).
    telemetry      jsonb,
    CONSTRAINT devices_public_key_key UNIQUE (public_key)
);

CREATE INDEX devices_customer ON devices (customer_id);
