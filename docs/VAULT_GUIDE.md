# HashiCorp Vault — 200-User Credential System

> This document explains how the HPE pipeline manages credentials for 200 enterprise users via HashiCorp Vault.

---

## Architecture Overview

```
user_profiles.json (200 users)
         │
         ▼ (on backend startup)
   vault_client.py
         │
         ▼
   HashiCorp Vault (Dev Mode)
   ┌──────────────────────────────┐
   │  secret/hpe/users/USR-0001  │ ← db_password, api_key, service_token
   │  secret/hpe/users/USR-0002  │
   │  secret/hpe/users/USR-0003  │
   │  ...                        │
   │  secret/hpe/users/USR-0200  │
   └──────────────────────────────┘
```

---

## How It Works

### 1. Startup — Credential Seeding

When the backend starts (`main.py` → `vault_client.connect_vault()`):
1. Reads all 200 user profiles from `user_profiles.json`
2. For each user, creates a Vault secret at `secret/hpe/users/{user_id}`
3. Each secret contains:
   - `db_password` — 32-char cryptographically secure password
   - `api_key` — Prefixed with `hpe_` + 48 hex chars
   - `service_token` — UUID v4
   - `role` — from profile (Developer, Admin, Finance, HR, Sales)
   - `home_region` — from profile (US-East, US-West, EU-Central, Asia-Pacific, South-America)
   - `rotation_count` — starts at 0
   - `status` — "active" initially
   - `last_rotation_reason` — "initial_provisioning"

### 2. Threat Detection — Per-User Rotation

When the AI engine detects a threat for a specific user:
1. `threat_engine.py` calls `vault_client.rotate_credentials(user=event.user_id)`
2. Only **that user's** credentials are regenerated
3. The secret at `secret/hpe/users/{user_id}` is updated with:
   - Brand new `db_password`, `api_key`, `service_token`
   - Incremented `rotation_count`
   - `status` → "rotated"
   - `last_rotation_reason` → `"threat_detected_score_0.XXXX"`

### 3. API Access — Viewing Credentials

| Endpoint | What you see |
|---|---|
| `/api/vault/users` | All 200 users, masked passwords |
| `/api/vault/users/USR-0042` | Single user detail |
| `/api/vault/credentials` | Latest rotated user (for dashboard) |
| Vault UI (`localhost:8200`) | Full unmasked values |

---

## Viewing in Vault UI

1. Open `http://localhost:8200`
2. Login method: **Token**
3. Token: `hpe-dev-token`
4. Navigate: **Secrets** → **secret/** → **hpe/** → **users/**
5. Click any user (e.g., `USR-0042`) to see full credentials

---

## User Roles Distribution

| Role | Count | Description |
|---|---|---|
| Developer | ~50 | High download volumes, varied hours |
| Sales | ~50 | Moderate activity, high travel probability |
| Finance | ~35 | Regular hours, low downloads |
| Admin | ~30 | High privileges, varied patterns |
| HR | ~20 | Regular hours, low volume |

*Note: Some users have `is_shift_worker: true` which gives them unusual login hours. These are NOT threats — the AI must learn to distinguish legitimate shift work from actual attacks.*

---

## Security Notes

- **Dev mode only**: The `hpe-dev-token` is a hardcoded dev token. In production, use proper Vault authentication (AppRole, Kubernetes auth, etc.)
- **Masked API responses**: The `/api/vault/users` endpoint masks passwords (first 4 chars + `****` + last 4 chars). Full values are only visible in the Vault UI.
- **KV v2**: We use Vault's KV v2 secrets engine, which provides versioning. You can see the full history of credential rotations for each user.
