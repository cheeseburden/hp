"""
vault_client.py — Real HashiCorp Vault client for credential management.
Uses hvac library to interact with Vault in dev mode.
Manages individual credentials for all 200 users (USR-0001 to USR-0200).
"""

import json
import logging
import uuid
import secrets
import string
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, List, Optional
import hvac
from app.config import VAULT_ADDR, VAULT_TOKEN, VAULT_SECRETS_PATH, PROFILES_PATH

logger = logging.getLogger("hpe.vault")

_client: Optional[hvac.Client] = None
_connected = False
_rotation_count = 0
_user_profiles: List[Dict[str, Any]] = []


def connect_vault() -> bool:
    """Initialize connection to HashiCorp Vault."""
    global _client, _connected

    try:
        _client = hvac.Client(url=VAULT_ADDR, token=VAULT_TOKEN)

        if _client.is_authenticated():
            logger.info(f"Vault connected and authenticated at {VAULT_ADDR}")

            # Load user profiles
            _load_user_profiles()

            # Initialize credentials for ALL 200 users
            _init_all_user_secrets()

            _connected = True
            return True
        else:
            logger.error("Vault authentication failed")
            _connected = False
            return False

    except Exception as e:
        logger.error(f"Vault connection failed: {e}")
        _connected = False
        return False


def _load_user_profiles():
    """Load user profiles from the JSON file."""
    global _user_profiles
    path = Path(PROFILES_PATH)
    if not path.exists():
        logger.warning(f"User profiles not found at {PROFILES_PATH}, generating default 200 users")
        _user_profiles = [
            {"user_id": f"USR-{i:04d}", "role": "Employee", "home_region": "US-East"}
            for i in range(1, 201)
        ]
        return

    try:
        with open(path, "r", encoding="utf-8") as f:
            _user_profiles = json.load(f)
        logger.info(f"Loaded {len(_user_profiles)} user profiles for Vault credential seeding")
    except Exception as e:
        logger.error(f"Failed to load user profiles: {e}")
        _user_profiles = []


def _init_all_user_secrets():
    """Initialize individual credentials in Vault for all 200 users."""
    if not _user_profiles:
        logger.warning("No user profiles loaded — skipping Vault credential seeding")
        return

    created = 0
    skipped = 0

    for profile in _user_profiles:
        user_id = profile.get("user_id", "UNKNOWN")
        vault_path = f"hpe/users/{user_id}"

        try:
            # Check if credentials already exist for this user
            existing = None
            try:
                existing = _client.secrets.kv.v2.read_secret_version(
                    path=vault_path,
                    raise_on_deleted_version=False,
                )
            except Exception:
                pass  # Secret doesn't exist yet

            if existing and existing.get("data", {}).get("data", {}):
                skipped += 1
                continue

            # Create fresh credentials for this user
            creds = {
                "user_id": user_id,
                "role": profile.get("role", "Employee"),
                "home_region": profile.get("home_region", "Unknown"),
                "db_password": _generate_password(),
                "api_key": _generate_api_key(),
                "service_token": str(uuid.uuid4()),
                "created_at": datetime.now(timezone.utc).isoformat(),
                "rotation_count": 0,
                "status": "active",
                "last_rotation_reason": "initial_provisioning",
            }

            _client.secrets.kv.v2.create_or_update_secret(
                path=vault_path,
                secret=creds,
            )
            created += 1

        except Exception as e:
            logger.warning(f"Vault: Failed to init credentials for {user_id}: {e}")

    logger.info(f"Vault: Initialized {created} new user credentials, {skipped} already existed "
                f"(total users: {len(_user_profiles)})")


def is_connected() -> bool:
    """Check if Vault is connected."""
    return _connected


def rotate_credentials(reason: str = "threat_detected", user: str = "unknown",
                       threat_score: float = 0.0) -> Dict[str, Any]:
    """
    Rotate credentials for a SPECIFIC user in Vault when a threat is detected.
    Writes new credentials to secret/hpe/users/{user_id}.
    """
    global _rotation_count

    if not _client or not _connected:
        return {"success": False, "error": "Vault not connected"}

    try:
        _rotation_count += 1
        vault_path = f"hpe/users/{user}"

        # Read current credentials to get the rotation count
        current_rotation = 0
        try:
            existing = _client.secrets.kv.v2.read_secret_version(
                path=vault_path,
                raise_on_deleted_version=False,
            )
            current_data = existing.get("data", {}).get("data", {})
            current_rotation = current_data.get("rotation_count", 0)
        except Exception:
            pass

        # Find user profile for metadata
        user_profile = next((p for p in _user_profiles if p.get("user_id") == user), {})

        new_creds = {
            "user_id": user,
            "role": user_profile.get("role", "Unknown"),
            "home_region": user_profile.get("home_region", "Unknown"),
            "db_password": _generate_password(),
            "api_key": _generate_api_key(),
            "service_token": str(uuid.uuid4()),
            "created_at": datetime.now(timezone.utc).isoformat(),
            "rotation_count": current_rotation + 1,
            "status": "rotated",
            "last_rotation_reason": reason,
            "triggered_by_threat_score": threat_score,
        }

        # Write to user-specific path in Vault
        _client.secrets.kv.v2.create_or_update_secret(
            path=vault_path,
            secret=new_creds,
        )

        logger.info(f"Vault: Credentials rotated for {user} "
                    f"(rotation #{current_rotation + 1}, reason={reason})")

        return {
            "success": True,
            "user_id": user,
            "rotation_id": str(uuid.uuid4()),
            "rotation_number": current_rotation + 1,
            "global_rotation_count": _rotation_count,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "reason": reason,
            "services_affected": ["database", "api_gateway", "service_mesh"],
            "new_credentials_hash": secrets.token_hex(8),
        }

    except Exception as e:
        logger.error(f"Vault credential rotation failed for {user}: {e}")
        return {"success": False, "error": str(e)}


def get_current_credentials() -> Dict[str, Any]:
    """Read current credentials from Vault (metadata only, not actual secrets)."""
    if not _client or not _connected:
        return {"error": "Vault not connected"}

    try:
        response = _client.secrets.kv.v2.read_secret_version(
            path="hpe/credentials",
            raise_on_deleted_version=False,
        )
        data = response.get("data", {}).get("data", {})
        return {
            "rotation_count": data.get("rotation_count", 0),
            "created_at": data.get("created_at", ""),
            "rotation_reason": data.get("rotation_reason", "initial"),
            "has_db_password": bool(data.get("db_password")),
            "has_api_key": bool(data.get("api_key")),
            "has_service_token": bool(data.get("service_token")),
        }
    except Exception as e:
        logger.error(f"Vault read error: {e}")
        return {"error": str(e)}


def get_rotation_count() -> int:
    """Get total rotation count."""
    return _rotation_count


def get_visible_credentials() -> Dict[str, Any]:
    """Return the latest rotated user's credentials in a display-safe format."""
    if not _client or not _connected:
        return {"error": "Vault not connected", "rotation_count": _rotation_count}

    # Find the most recently rotated user
    latest_user = _find_latest_rotated_user()
    if not latest_user:
        return {
            "rotation_count": _rotation_count,
            "db_password": "****",
            "api_key": "****",
            "service_token": "****",
            "created_at": "",
            "rotation_reason": "no_rotations_yet",
            "triggered_by_user": "",
            "threat_score": 0,
        }

    return latest_user


def _find_latest_rotated_user() -> Optional[Dict[str, Any]]:
    """Find the user whose credentials were most recently rotated."""
    if not _client or not _connected:
        return None

    latest = None
    latest_time = ""

    # Check a sample of users for the latest rotation (not all 200 for performance)
    for profile in _user_profiles:
        user_id = profile.get("user_id", "")
        try:
            resp = _client.secrets.kv.v2.read_secret_version(
                path=f"hpe/users/{user_id}",
                raise_on_deleted_version=False,
            )
            data = resp.get("data", {}).get("data", {})
            if data.get("status") == "rotated":
                created = data.get("created_at", "")
                if created > latest_time:
                    latest_time = created
                    latest = data
        except Exception:
            continue

    if not latest:
        return None

    db_pw = latest.get("db_password", "")
    api_key = latest.get("api_key", "")
    svc_token = latest.get("service_token", "")

    return {
        "rotation_count": _rotation_count,
        "user_id": latest.get("user_id", ""),
        "role": latest.get("role", ""),
        "db_password": db_pw[:4] + "****" + db_pw[-4:] if len(db_pw) > 8 else "****",
        "api_key": api_key[:8] + "****" if len(api_key) > 8 else "****",
        "service_token": svc_token[:8] + "****" if len(svc_token) > 8 else "****",
        "created_at": latest.get("created_at", ""),
        "rotation_reason": latest.get("last_rotation_reason", "initial"),
        "triggered_by_user": latest.get("user_id", ""),
        "threat_score": latest.get("triggered_by_threat_score", 0),
    }


def get_all_user_credentials() -> List[Dict[str, Any]]:
    """
    Return masked credentials for ALL 200 users.
    Each entry includes: user_id, role, region, masked passwords, rotation info.
    """
    if not _client or not _connected:
        return []

    results = []
    for profile in _user_profiles:
        user_id = profile.get("user_id", "")
        vault_path = f"hpe/users/{user_id}"

        try:
            resp = _client.secrets.kv.v2.read_secret_version(
                path=vault_path,
                raise_on_deleted_version=False,
            )
            data = resp.get("data", {}).get("data", {})

            db_pw = data.get("db_password", "")
            api_key = data.get("api_key", "")
            svc_token = data.get("service_token", "")

            results.append({
                "user_id": user_id,
                "role": data.get("role", profile.get("role", "")),
                "home_region": data.get("home_region", profile.get("home_region", "")),
                "db_password": db_pw[:4] + "****" + db_pw[-4:] if len(db_pw) > 8 else "****",
                "api_key": api_key[:8] + "****" if len(api_key) > 8 else "****",
                "service_token": svc_token[:8] + "****" if len(svc_token) > 8 else "****",
                "rotation_count": data.get("rotation_count", 0),
                "status": data.get("status", "unknown"),
                "created_at": data.get("created_at", ""),
                "last_rotation_reason": data.get("last_rotation_reason", ""),
            })
        except Exception as e:
            results.append({
                "user_id": user_id,
                "role": profile.get("role", ""),
                "home_region": profile.get("home_region", ""),
                "error": str(e),
                "status": "error",
            })

    return results


def get_user_credentials(user_id: str) -> Dict[str, Any]:
    """Return masked credentials for a SINGLE user."""
    if not _client or not _connected:
        return {"error": "Vault not connected"}

    vault_path = f"hpe/users/{user_id}"

    try:
        resp = _client.secrets.kv.v2.read_secret_version(
            path=vault_path,
            raise_on_deleted_version=False,
        )
        data = resp.get("data", {}).get("data", {})

        db_pw = data.get("db_password", "")
        api_key = data.get("api_key", "")
        svc_token = data.get("service_token", "")

        return {
            "user_id": user_id,
            "role": data.get("role", ""),
            "home_region": data.get("home_region", ""),
            "db_password": db_pw[:4] + "****" + db_pw[-4:] if len(db_pw) > 8 else "****",
            "api_key": api_key[:8] + "****" if len(api_key) > 8 else "****",
            "service_token": svc_token[:8] + "****" if len(svc_token) > 8 else "****",
            "rotation_count": data.get("rotation_count", 0),
            "status": data.get("status", "unknown"),
            "created_at": data.get("created_at", ""),
            "last_rotation_reason": data.get("last_rotation_reason", ""),
            "triggered_by_threat_score": data.get("triggered_by_threat_score", 0),
        }

    except Exception as e:
        logger.error(f"Vault: Failed to read credentials for {user_id}: {e}")
        return {"error": str(e), "user_id": user_id}


def _generate_password(length: int = 32) -> str:
    """Generate a cryptographically secure password."""
    chars = string.ascii_letters + string.digits + string.punctuation
    return "".join(secrets.choice(chars) for _ in range(length))


def _generate_api_key() -> str:
    """Generate a random API key."""
    return f"hpe_{secrets.token_hex(24)}"


def disconnect_vault():
    """Close Vault connection."""
    global _connected
    _connected = False
    logger.info("Vault disconnected")
