-- Down for 000044 — drop the pre-login UA/IP binding columns.
ALTER TABLE oidc_pre_login_sessions
    DROP COLUMN IF EXISTS client_ip,
    DROP COLUMN IF EXISTS user_agent;
