# amanda — SAREK Vault CLI Client

`amanda` is the command-line client for the SAREK post-quantum secrets vault. It
communicates with the `sarek` server over HTTPS using Bearer-token authentication.

---

## Table of Contents

1. [Building](#building)
2. [Configuration](#configuration)
3. [TLS / Certificate Trust](#tls--certificate-trust)
4. [Token Lifecycle](#token-lifecycle)
5. [Command Reference](#command-reference)
6. [Token Management (admin)](#token-management-admin-only)
7. [Workflows](#workflows)
8. [Access Control](#access-control)
9. [Secret Wrapping](#secret-wrapping)

---

## Building

```bash
cmake -S amanda -B amanda/build
cmake --build amanda/build -j$(nproc)
```

The built binary is `amanda/build/amanda`.

**Dependencies** (same as the rest of the project):
- OpenSSL 3 (`libssl`, `libcrypto`)
- yaml-cpp
- libcrystals (installed to `/usr/local/lib`)
- XKCP, BLAKE3, oneTBB (transitive through libcrystals)
- cpp-httplib (header-only, expected on system include path)
- nlohmann/json (header-only, expected on system include path)

---

## Configuration

Amanda reads `$HOME/.sarekrc` on startup. All settings can also be overridden on
the command line.

**Example `~/.sarekrc`:**

```yaml
# sarek server to connect to
server: https://sarek.local:8443

# PEM file used to verify the server's TLS certificate.
# Required when the server uses a self-signed cert; omit for CA-signed certs.
cacert: /home/alice/.sarek-cert.pem

# Default username for 'amanda login'. Avoids being prompted every time.
# Does not apply to any other command.
username: alice

# Tray alias used by 'create' when --tray is omitted.
# Set with: amanda mark-default --alias <name>
default_tray: my-vault-key
```

All fields are optional. Defaults if the file does not exist:
`server: https://localhost:8443`, empty `cacert` (system CA bundle), empty
`username` (prompted interactively), empty `default_tray` (falls back to
`system-token` for encryption).

`default_tray` is the only field written back automatically by amanda (via
`mark-default`); all other fields must be set by hand.
Command-line flags always override config file values.

### Global flags

These apply before any command and override the config file:

| Flag | Config key | Purpose |
|------|-----------|---------|
| `--server <url>` | `server` | Override the server URL |
| `--cacert <path>` | `cacert` | PEM file to trust for server certificate verification |
| `--insecure` | — | Skip TLS certificate verification entirely (**dev only**) |

`--cacert` and `--insecure` are mutually exclusive. `--cacert` is the correct
choice whenever the server uses a self-signed certificate; `--insecure` should
only be used during local development.

---

## TLS / Certificate Trust

### Client certificate trust (amanda side)

Amanda does **not** present a client certificate (does not use mutual TLS). It only needs
to verify the server's certificate. There are three scenarios:

#### 1. Self-signed certificate — `--cacert` (recommended for internal/LAN use)

Because the self-signed cert is its own CA, pass it directly as the trust anchor:

```bash
# Copy the cert from the server once (or from a trusted source)
scp user@sarek.local:/etc/sarek/cert.pem ~/.sarek-cert.pem

# Use it on every amanda command
amanda --server https://sarek.local:8443 \
       --cacert ~/.sarek-cert.pem \
       health
```

Or set the server URL in `~/.sarekrc` and always pass `--cacert`:

```bash
amanda --cacert ~/.sarek-cert.pem login
amanda --cacert ~/.sarek-cert.pem create /mypath --from-text "secret"
```

#### 2. CA-signed certificate (Let's Encrypt / internal PKI)

When the server uses a certificate issued by a recognised CA (or an internal CA
whose root is already installed on the client machine), no extra flags are
needed — amanda uses the system CA bundle by default:

```bash
amanda --server https://vault.example.com:8443 login
```

#### 3. Plain HTTP development mode — `--insecure`

When `sarek` is started with `--dev` (plain HTTP, no TLS) use `http://` in the
URL. No cert flags needed:

```bash
amanda --server http://localhost:8443 --insecure health
```

`--insecure` is also accepted for HTTPS with a self-signed cert when you do not
want to manage the cert file:

```bash
amanda --server https://localhost:8443 --insecure health
```

> **Warning**: `--insecure` disables all certificate verification and is
> vulnerable to man-in-the-middle attacks. Never use it in production.

### TLS notes

The `sarek` server advertises `X25519MLKEM768:X25519` as its preferred TLS 1.3
key exchange group — a post-quantum hybrid KEM. Amanda's underlying httplib
SSLClient uses OpenSSL 3.5 and will negotiate this group automatically with a
compatible server. The server's certificate type (P-256 ECDSA above) is
independent of the key exchange group; any standard cert type works.

---

## Token Lifecycle

Tokens are raw binary blobs signed with the server's `system-token` tray
(ECDSA P-256 + Dilithium). Amanda stores them at `$HOME/.sarek` with `0600`
permissions and reads them back on every command.

- **Login** writes a token. The server registers it in its `manage_token` database.
- **Logout** sends `DELETE /logout` and deletes `$HOME/.sarek`.
- If `$HOME/.sarek` is absent, commands that require authentication will fail
  with a 401 from the server.
- Tokens have a 24-hour TTL. After expiry, log in again.
- **Revocation**: An admin can revoke any token immediately via `revoke-token`,
  `revoke-tokens`, or `revoke-all`. If you send a revoked or unrecognised token,
  the server returns a 401 and amanda automatically deletes `$HOME/.sarek` —
  the next command will tell you to log in again.

---

## Command Reference

### Token Management Commands (admin only)

| Command | Description |
|---------|-------------|
| `list-tokens` | List all active and revoked tokens with status |
| `revoke-token <token_id>` | Revoke one specific token by its UUID |
| `revoke-tokens <username>` | Revoke all active tokens for one user |
| `revoke-all` | Revoke every active token (forces all users to re-login) |

See [Token Management](#token-management-admin-only) below for full details.

### Secret Wrapping

| Command | Description |
|---------|-------------|
| `wrap [--ttl <time>]` | Wrap stdin → opaque one-time delivery token |

See [Secret Wrapping](#secret-wrapping) below for full details.

---

### `login`

```
amanda login [--username <name>] [--token <base64>]
```

**Password login** (normal use):

```bash
amanda login
amanda login --username alice
```

Prompts for username (if omitted and not set in `~/.sarekrc`) and password
(hidden). On success writes the token to `$HOME/.sarek`.

**Invite-token login** (first login after an admin runs `newuser`):

```bash
amanda login --token $(cat invite.txt)
```

Decodes the base64 invite token, saves it to `$HOME/.sarek`, then prompts the
user to set a new password via `POST /users/password`. After this the user can
log in normally with their chosen password.

---

### `logout`

```
amanda logout
```

Deletes `$HOME/.sarek` and notifies the server (server acknowledgement only;
no server-side session state is maintained).

---

### `newuser` *(admin only)*

```
amanda newuser --username <name> [--assert <scope> ...]
```

Creates a new user account with no initial password and prints a base64-encoded
invite token to stdout. The admin sends this token to the new user, who redeems
it with `amanda login --token`.

```bash
# Admin creates bob with access to /bob/*
amanda newuser --username bob --assert "slc:/bob/*" > bob_invite.txt

# Send bob_invite.txt to Bob out of band.
# Bob runs:
amanda login --token $(cat bob_invite.txt)
# → prompted to set password; logged in as bob
```

Multiple `--assert` flags are allowed:

```bash
amanda newuser --username carol \
  --assert "slc:/team-a/*" \
  --assert "slc:/shared/*"
```

The server always adds `usr:<username>` automatically.

---

### `listuser`

```
amanda listuser
```

List all users. Calls `GET /users`.

- **Admin**: sees full detail for every user (user ID, flags, assertions).
- **Non-admin**: sees full detail for own row only; other users appear with username only.

```
USERNAME        USER_ID              FLAGS     ASSERTIONS
alice           1234567890123456     admin     usr:alice /*
bob             9876543210987654               usr:bob slc:/bob/*   [you]
carol           1111111111111111     locked    usr:carol slc:/carol/*
dave            2222222222222222
```

The `[you]` marker identifies the currently authenticated user. It is matched
against `cfg.username` (from `~/.sarekrc`) or, if that is empty, against the
`usr:` assertion found in the own detail row.

---

### `changepass`

```
amanda changepass [--username <name>]
```

Change a user's password.

- Without `--username`: changes the password of the currently authenticated user
  (taken from `cfg.username` in `~/.sarekrc`, or prompted interactively if
  absent).
- With `--username <name>`: admin may change any user's password; non-admin
  attempting to change another user's password receives a `403`.

Prompts for `New password:` and `Confirm:` via `getpass()`. Errors if the two
entries do not match.

```bash
# Change own password
amanda changepass

# Admin changes another user's password
amanda changepass --username bob
```

No current-password prompt is required; a valid Bearer token is sufficient.

---

### `keygen`

```
amanda keygen --alias <name> [--tray <level>] [--pg crystals]
```

Generate a new cryptographic tray owned by the authenticated user.

| Option | Default | Notes |
|--------|---------|-------|
| `--alias` | *(required)* | Unique tray name |
| `--tray` | `level3` | Tray security level |
| `--pg` | *(optional)* | Profile group; only `crystals` is defined |

**Tray levels:**

| Level | Classical KEM | PQ KEM | Classical Sig | PQ Sig |
|-------|--------------|--------|---------------|--------|
| `level0` | X25519 | — | Ed25519 | — |
| `level1` | P-384 | — | ECDSA P-384 | — |
| `level2` | X25519 | Kyber-768 | Ed25519 | Dilithium3 |
| `level3` | X25519 | Kyber-768 | Ed25519 | Dilithium3 |
| `level5` | P-521 | Kyber-1024 | ECDSA P-521 | Dilithium5 |

```bash
amanda keygen --alias mykey --tray level3
```

---

### `trays`

```
amanda trays [-v]
```

List tray aliases owned by the authenticated user. With `-v`, also fetches and
prints full detail for each tray.

```bash
amanda trays
amanda trays -v
```

---

### `tray`

```
amanda tray --alias <name> [--public]
```

Print details for one tray. `--public` shows only `pk_b64` fields (omits
`has_sk` / `sk_b64`), safe for sharing.

```bash
amanda tray --alias mykey
amanda tray --alias mykey --public
```

---

### `export-tray`

```
amanda export-tray --alias <name> [--to-file <path>]
```

Retrieve the full tray including secret key bytes (`sk_b64`). Only the tray
owner or an admin may call this. Without `--to-file`, JSON is written to stdout.

```bash
amanda export-tray --alias mykey
amanda export-tray --alias mykey --to-file mykey-backup.json
```

> Keep exported files safe: they contain private key material. Store backups
> encrypted or on offline media.

---

### `mark-default`

```
amanda mark-default --alias <name>
```

Sets `default_tray` in `$HOME/.sarekrc`. The default tray is used by `create`
when `--tray` is not specified.

```bash
amanda mark-default --alias mykey
```

---

### `create`

```
amanda create <path> [--from-file <file>] [--from-text <text>]
              [--mimetype <type>] [--tray <alias>]
```

Store a secret at the given vault path. Input is read from the first of:
`--from-file`, `--from-text`, or stdin.

The MIME type defaults to one detected from the file extension, or
`application/octet-stream` if unknown.

```bash
# From text
amanda create /team-a/db-password --from-text "hunter2"

# From file (MIME type detected as application/x-pem-file)
amanda create /team-a/tls-key --from-file server.key

# From stdin
cat secret.bin | amanda create /team-a/blob --mimetype application/octet-stream

# Override encryption tray
amanda create /team-a/db-password --from-text "hunter2" --tray mykey
```

The `?tray=<alias>` query parameter selects the KEM tray used to encrypt the
secret. Defaults to `default_tray` from config, then falls back to
`system-token`.

---

### `read`

```
amanda read <path> [--to-file <file>]
```

Retrieve and decrypt a secret. Without `--to-file`, raw bytes go to stdout (safe
to pipe or redirect).

```bash
amanda read /team-a/db-password
amanda read /team-a/tls-key --to-file restored.key
```

---

### `meta`

```
amanda meta <path>
```

Print metadata for a secret without decrypting it.

```
path:      /team-a/db-password
object_id: 9876543
created:   1700000000
size:      7
mimetype:  text/plain
tray_id:   xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
```

If the path is a link, a `link_path` line is also shown.

---

### `secrets`

```
amanda secrets [--prefix <prefix>]
```

List all visible vault paths, optionally filtered to those starting with `prefix`.

```bash
amanda secrets
amanda secrets --prefix /team-a/
```

---

### `link`

```
amanda link --target <path> --link <path>
```

Create a symlink. `link` is the new path; `target` is the existing path it
points to. The token must have scope over both paths. Links are followed
transparently by `read`.

```bash
amanda link --target /team-a/db-password --link /shared/db-password
```

---

### `health`

```
amanda health
```

Unauthenticated liveness check. Useful for verifying connectivity and TLS trust
before logging in.

```bash
amanda --cacert ~/.sarek-cert.pem health
# → healthy
```

---

### `wrap`

```
amanda wrap [--ttl <number>[s|m|h|d]]
```

Encrypt data read from stdin and store it as a one-time wrapped secret on the server. Prints the opaque base64url token to stdout. The recipient redeems the token via an unauthenticated HTTP GET — no amanda installation required.

| Option | Default | Notes |
|--------|---------|-------|
| `--ttl` | `3600` (1 hour) | TTL for the wrapped secret |

**TTL format**: a number followed by `s` (seconds), `m` (minutes), `h` (hours), or `d` (days). A bare integer is interpreted as seconds. Range: 600 s (10 min) – 432 000 s (5 days).

**Prerequisites**: a `wrap` tray must exist on the server (create once with `amanda keygen --alias wrap`).

```bash
# Wrap a password (default 1-hour TTL)
echo "hunter2" | amanda wrap
# → ABCDEFGHIJKLMNOPQRSTUV

# Wrap a file with a 24-hour TTL
cat secret.key | amanda wrap --ttl 24h
# → XYZ123...

# Wrap with explicit seconds
echo "s3cr3t" | amanda wrap --ttl 7200
```

The recipient redeems the token — no auth required:

```bash
curl https://sarek.host:8443/wrapped/ABCDEFGHIJKLMNOPQRSTUV
# → hunter2
```

A second attempt returns `404`. Expired tokens are purged automatically by the server's hourly cleanup thread.

---

### Token Management *(admin only)*

These commands require an admin token (assertion `/*`).

#### `list-tokens`

```
amanda list-tokens
```

Lists all issued tokens with their status:

```
TOKEN_ID                              USERNAME          CREATED               EXPIRES               STATUS
------------------------------------  ----------------  --------------------  --------------------  -------
a1b2c3d4-e5f6-4abc-8def-1234567890ab  alice             2026-03-11 10:00:00Z  2026-03-12 10:00:00Z  active
f0e1d2c3-b4a5-4678-9012-abcdef012345  bob               2026-03-10 08:30:00Z  2026-03-11 08:30:00Z  REVOKED
```

#### `revoke-token`

```
amanda revoke-token <token_id>
```

Revoke a single token by its UUID. The token is immediately invalidated;
the next request using it will receive a 401 and the client will auto-delete
its local token file.

```bash
amanda revoke-token a1b2c3d4-e5f6-4abc-8def-1234567890ab
# Revoked token: a1b2c3d4-e5f6-4abc-8def-1234567890ab
```

#### `revoke-tokens`

```
amanda revoke-tokens <username>
```

Revoke all active tokens belonging to the given user. Useful when a user's
device is lost or account is compromised.

```bash
amanda revoke-tokens alice
# Revoked 2 token(s) for user 'alice'
```

#### `revoke-all`

```
amanda revoke-all
```

Revoke every active token in the system. All users must re-login.
Prompts for confirmation before proceeding.

```bash
amanda revoke-all
# This will revoke ALL active tokens and force all users to re-login.
# Type 'yes' to confirm: yes
# Revoked 7 token(s). All users must re-login.
```

---

## Workflows

### First-time setup

```bash
# 1. Start sarek (see sarek/README.md)
sarek --cert /etc/sarek/cert.pem --key /etc/sarek/key.pem

# 2. Copy the server cert once
scp user@sarek.local:/etc/sarek/cert.pem ~/.sarek-cert.pem

# 3. Configure amanda
cat > ~/.sarekrc <<EOF
server: https://sarek.local:8443
default_tray: ""
EOF

# 4. Log in as admin
amanda --cacert ~/.sarek-cert.pem login --username admin
```

### Storing and retrieving a secret

```bash
# Create a secret
amanda create /myproject/api-key --from-text "sk-abc123"

# Read it back
amanda read /myproject/api-key

# Check metadata
amanda meta /myproject/api-key
```

### Onboarding a new user (admin workflow)

```bash
# Step 1: Admin creates the account and generates an invite token
amanda newuser --username bob --assert "slc:/bob/*" > bob_invite.txt
# bob_invite.txt contains a base64 bearer token

# Step 2: Admin sends bob_invite.txt to Bob out of band (email, Signal, etc.)

# Step 3: Bob redeems the token and sets a password
amanda login --token $(cat bob_invite.txt)
# → Set password: ****
# → Confirm password: ****
# → Password set. Logged in.

# Step 4: Bob can now log in normally
amanda login --username bob
```

### Generating and backing up a tray

```bash
# Generate a level3 tray
amanda keygen --alias my-vault-key --tray level3
amanda mark-default --alias my-vault-key

# Export for offline backup (contains private keys)
amanda export-tray --alias my-vault-key --to-file my-vault-key-backup.json
chmod 600 my-vault-key-backup.json
# Store offline / in a safe location
```

### Sending a one-time secret (wrap)

```bash
# One-time setup: create the wrap tray (admin only)
amanda keygen --alias wrap --tray level3

# Wrap a secret with a 2-hour window
echo "TempPass#2026!" | amanda wrap --ttl 2h
# → ABCDEF123456789_abcdef-XY

# Give the recipient this URL (no auth required to redeem):
# https://sarek.local:8443/wrapped/ABCDEF123456789_abcdef-XY
```

### Creating a shared link

```bash
# Alice stores a secret under her namespace
amanda create /alice/db-creds --from-text "password123"

# Admin creates a link accessible to the /shared/* scope
amanda link --target /alice/db-creds --link /shared/db-creds

# Bob (with slc:/shared/* assertion) can read it
amanda read /shared/db-creds
```

---

## Access Control

Token assertions control what paths a user can read and write:

| Assertion | Meaning |
|-----------|---------|
| `/*` | Full admin access |
| `slc:/team-a/*` | All paths under `/team-a/` |
| `slc:/team-a/db-password` | Exactly that one path |
| `usr:<username>` | Identity marker (always present; not a path grant) |

Assertions are set when the user is created and are embedded in the signed
token. They cannot be changed without re-issuing the token.

A token covers both `read` and `create` for any path within its scope. There
is currently no read-only or write-only scope distinction.

### Sending a one-time secret to a new user

```bash
# Before first use: create the wrap tray (admin, once per server)
amanda keygen --alias wrap --tray level3

# Alice wraps a temporary database password for Bob (24-hour window)
echo "TempPass#2026!" | amanda wrap --ttl 24h
# → ABCDEF123456789_abcdef-XY

# Alice sends Bob this URL out-of-band (email, Slack, etc.):
# https://sarek.local:8443/wrapped/ABCDEF123456789_abcdef-XY

# Bob redeems it once — no account required
curl --cacert ~/.sarek-cert.pem \
     "https://sarek.local:8443/wrapped/ABCDEF123456789_abcdef-XY"
# → TempPass#2026!

# Any further attempt returns 404
```

---

## Secret Wrapping

Secret wrapping is a one-time, unauthenticated secret delivery mechanism. The sender (authenticated) encrypts a value and receives an opaque token. The recipient redeems the URL once — the record is deleted on first access.

### Setup (one time per server, admin)

```bash
amanda keygen --alias wrap --tray level3
```

The `wrap` tray is the server-side encryption key for all wrapped secrets. It must exist before any `wrap` command is used.

### Wrapping

```bash
# From stdin (default 1-hour TTL)
echo "s3cr3t" | amanda wrap

# From a file, 2-day TTL
cat private.key | amanda wrap --ttl 2d

# 30-minute TTL (in seconds)
echo "ephemeral" | amanda wrap --ttl 1800
```

Each `wrap` call prints a 22-character base64url token. Share the full redemption URL with the recipient:

```
https://<server>:<port>/wrapped/<token>
```

### Redeeming (recipient, no auth)

```bash
curl https://sarek.host:8443/wrapped/<token>
```

The response body is the raw plaintext. After one successful redemption, the token is deleted and returns `404` forever.

### Expiry

Tokens with a TTL that has elapsed also return `404`. Expired records are purged hourly by the server's background cleanup thread.

### Security notes

- The token is opaque (16 random bytes, base64url-encoded). It is not a bearer token and carries no user identity.
- The secret is encrypted server-side using the `wrap` tray (hybrid KEM, OBIWAN format) before being stored in BDB.
- Keep the redemption URL confidential until the recipient is ready — it is the only credential needed to read the secret.

---

## Files Written by amanda

| Path | Contents | Permissions |
|------|----------|-------------|
| `$HOME/.sarekrc` | YAML config (server URL, default tray) | `0644` |
| `$HOME/.sarek` | Raw binary bearer token | `0600` |
