"""Structured audit-event subsystem (log-only, SIEM-exportable).

This module is the generalized core that the per-domain audit emitters build
on. It emits one structured JSON line per security-relevant action (auth,
admin-config change, access-control change, credential access) onto a dedicated
``onyx.audit`` logger tree, carrying tenant / request / actor / client-IP
context so events can be attributed and reviewed.

The emitted schema is intentionally shaped toward OCSF (the Open Cybersecurity
Schema Framework used by AWS Security Lake, Splunk, Sentinel, etc.): field
names and the action taxonomy map cleanly onto OCSF event classes
(Authentication / Account Change / API Activity) so a customer can drop the
stream into their SIEM with no per-SIEM integration on our side. We emit plain
JSON today; the OCSF-class hint is carried on every event so a future
OCSF-native emitter mode is a formatting change, not a re-instrumentation.

Design invariants (carried over from ``credential_audit`` — non-negotiable):

* **Never raise into the caller.** Audit emission sits on request and connector
  hot paths; every step is best-effort and any failure is swallowed.
* **Never log a secret value.** The emitter only serializes the fields it is
  handed; call sites must never pass secrets (not even inside ``extra``).
* **Always tenant-tag.** Tenant context is gathered best-effort on every event.
* **Redis-backed dedup on hot event classes.** Opt-in per call via
  ``dedup_key``; if Redis is unavailable we degrade to always-emit (we never
  silently drop an audit event because of infra trouble).

To consume the trail, filter logs on the ``onyx.audit`` logger name (or a
child, e.g. ``onyx.audit.authentication``) and parse the JSON message body. The
message is a single clean JSON object regardless of ``LOG_FORMAT`` (we emit the
JSON as the log message itself rather than relying on the structured formatter,
so the trail is identical in ``plain`` and ``json`` modes).
"""

import json
import logging
import time
from dataclasses import dataclass
from enum import Enum
from typing import Any

AUDIT_SCHEMA_VERSION = "1.0"

# Root logger for the whole audit subsystem. Per-class children
# (``onyx.audit.authentication`` etc.) propagate up to it and to the root, so
# the configured handlers / log files still receive every event. We use a plain
# ``logging.getLogger`` (not ``setup_logger``) so the record message is exactly
# one JSON object with no human-readable prefix.
AUDIT_LOGGER_ROOT = "onyx.audit"

# Default dedup window for callers that opt into dedup without specifying one.
_DEFAULT_DEDUP_TTL_SECONDS = 600


class OCSFEventClass(str, Enum):
    """OCSF event-class hint carried on every audit event.

    Values are the OCSF class names; the numeric ``class_uid`` is noted for the
    future OCSF-native emitter. Keeping this on every event means downstream
    consumers can route by class without re-deriving it from the action.
    """

    AUTHENTICATION = "authentication"  # OCSF class_uid 3002
    ACCOUNT_CHANGE = "account_change"  # OCSF class_uid 3001
    API_ACTIVITY = "api_activity"  # OCSF class_uid 6003


class AuditOutcome(str, Enum):
    """Outcome of the audited action. Maps onto OCSF ``status``."""

    SUCCESS = "success"
    FAILURE = "failure"
    DENIED = "denied"  # authn/authz refusal (distinct from an operational error)


class AuditAction(str, Enum):
    """Stable taxonomy of audited actions.

    The string values are dotted ``<domain>.<verb>`` names and are part of the
    exported schema contract — treat them as append-only (never rename/remove a
    value once shipped; consumers filter on them). Only ``CREDENTIAL_ACCESS`` is
    wired up as of this change (via ``credential_audit``); the remaining members
    are the taxonomy the auth / admin-config / access-control call sites land on
    in follow-up changes.
    """

    # --- Authentication (OCSF Authentication, 3002) ---
    LOGIN = "auth.login"
    LOGIN_FAILURE = "auth.login_failure"
    LOGOUT = "auth.logout"
    REGISTER = "auth.register"
    PASSWORD_FORGOT = "auth.password_forgot"
    PASSWORD_RESET = "auth.password_reset"
    EMAIL_VERIFY = "auth.email_verify"

    # --- Account Change (OCSF Account Change, 3001) ---
    USER_CREATE = "user.create"
    USER_DELETE = "user.delete"
    USER_DEACTIVATE = "user.deactivate"
    USER_REACTIVATE = "user.reactivate"
    USER_ROLE_CHANGE = "user.role_change"
    USER_GROUP_CHANGE = "user.group_change"

    # --- API Activity (OCSF API Activity, 6003): admin config + resource CRUD ---
    LLM_PROVIDER_CREATE = "llm_provider.create"
    LLM_PROVIDER_UPDATE = "llm_provider.update"
    LLM_PROVIDER_DELETE = "llm_provider.delete"
    CONNECTOR_CREATE = "connector.create"
    CONNECTOR_UPDATE = "connector.update"
    CONNECTOR_DELETE = "connector.delete"
    CC_PAIR_CREATE = "cc_pair.create"
    CC_PAIR_UPDATE = "cc_pair.update"
    CC_PAIR_DELETE = "cc_pair.delete"
    API_KEY_CREATE = "api_key.create"
    API_KEY_REGENERATE = "api_key.regenerate"
    API_KEY_DELETE = "api_key.delete"
    CREDENTIAL_CREATE = "credential.create"
    CREDENTIAL_UPDATE = "credential.update"
    CREDENTIAL_DELETE = "credential.delete"
    CREDENTIAL_ACCESS = "credential.access"


# Action -> OCSF class. Every ``AuditAction`` must have an entry; this is
# asserted at import time below so a newly added action can't ship untagged.
_OCSF_CLASS_BY_ACTION: dict[AuditAction, OCSFEventClass] = {
    AuditAction.LOGIN: OCSFEventClass.AUTHENTICATION,
    AuditAction.LOGIN_FAILURE: OCSFEventClass.AUTHENTICATION,
    AuditAction.LOGOUT: OCSFEventClass.AUTHENTICATION,
    AuditAction.REGISTER: OCSFEventClass.AUTHENTICATION,
    AuditAction.PASSWORD_FORGOT: OCSFEventClass.AUTHENTICATION,
    AuditAction.PASSWORD_RESET: OCSFEventClass.AUTHENTICATION,
    AuditAction.EMAIL_VERIFY: OCSFEventClass.AUTHENTICATION,
    AuditAction.USER_CREATE: OCSFEventClass.ACCOUNT_CHANGE,
    AuditAction.USER_DELETE: OCSFEventClass.ACCOUNT_CHANGE,
    AuditAction.USER_DEACTIVATE: OCSFEventClass.ACCOUNT_CHANGE,
    AuditAction.USER_REACTIVATE: OCSFEventClass.ACCOUNT_CHANGE,
    AuditAction.USER_ROLE_CHANGE: OCSFEventClass.ACCOUNT_CHANGE,
    AuditAction.USER_GROUP_CHANGE: OCSFEventClass.ACCOUNT_CHANGE,
    AuditAction.LLM_PROVIDER_CREATE: OCSFEventClass.API_ACTIVITY,
    AuditAction.LLM_PROVIDER_UPDATE: OCSFEventClass.API_ACTIVITY,
    AuditAction.LLM_PROVIDER_DELETE: OCSFEventClass.API_ACTIVITY,
    AuditAction.CONNECTOR_CREATE: OCSFEventClass.API_ACTIVITY,
    AuditAction.CONNECTOR_UPDATE: OCSFEventClass.API_ACTIVITY,
    AuditAction.CONNECTOR_DELETE: OCSFEventClass.API_ACTIVITY,
    AuditAction.CC_PAIR_CREATE: OCSFEventClass.API_ACTIVITY,
    AuditAction.CC_PAIR_UPDATE: OCSFEventClass.API_ACTIVITY,
    AuditAction.CC_PAIR_DELETE: OCSFEventClass.API_ACTIVITY,
    AuditAction.API_KEY_CREATE: OCSFEventClass.API_ACTIVITY,
    AuditAction.API_KEY_REGENERATE: OCSFEventClass.API_ACTIVITY,
    AuditAction.API_KEY_DELETE: OCSFEventClass.API_ACTIVITY,
    AuditAction.CREDENTIAL_CREATE: OCSFEventClass.API_ACTIVITY,
    AuditAction.CREDENTIAL_UPDATE: OCSFEventClass.API_ACTIVITY,
    AuditAction.CREDENTIAL_DELETE: OCSFEventClass.API_ACTIVITY,
    AuditAction.CREDENTIAL_ACCESS: OCSFEventClass.API_ACTIVITY,
}

# Fail loudly at import time if a new action was added without an OCSF mapping.
_unmapped = set(AuditAction) - set(_OCSF_CLASS_BY_ACTION)
if _unmapped:
    raise RuntimeError(
        f"AuditAction members missing an OCSF class mapping: "
        f"{sorted(a.value for a in _unmapped)}"
    )


@dataclass(frozen=True)
class AuditActor:
    """Who performed the action. All fields optional and best-effort.

    Never put a secret here. ``api_key_id`` is the API key's row id / public
    identifier, never the key value itself.
    """

    user_id: str | None = None
    email: str | None = None
    api_key_id: str | None = None
    auth_type: str | None = None  # e.g. "password", "oauth", "saml", "api_key"

    def to_dict(self) -> dict[str, Any]:
        return {
            "user_id": self.user_id,
            "email": self.email,
            "api_key_id": self.api_key_id,
            "auth_type": self.auth_type,
        }


# --- Best-effort context gathering --------------------------------------------
# These mirror the request-scoped contextvars the rest of the app sets. Every
# one degrades to ``None`` rather than raising, so emission works off the
# request path (e.g. in a connector thread) where context may be absent.


def _safe_get_tenant_id() -> str | None:
    try:
        from shared_configs.contextvars import get_current_tenant_id

        return get_current_tenant_id()
    except Exception:
        return None


def _safe_get_request_id() -> str | None:
    try:
        from shared_configs.contextvars import ONYX_REQUEST_ID_CONTEXTVAR

        return ONYX_REQUEST_ID_CONTEXTVAR.get()
    except Exception:
        return None


def _safe_get_endpoint() -> str | None:
    try:
        from shared_configs.contextvars import CURRENT_ENDPOINT_CONTEXTVAR

        return CURRENT_ENDPOINT_CONTEXTVAR.get()
    except Exception:
        return None


def _safe_get_client_ip() -> str | None:
    try:
        from onyx.utils.client_ip import current_client_ip

        return current_client_ip()
    except Exception:
        return None


def should_emit(dedup_key: str, ttl_seconds: int, tenant_id: str | None) -> bool:
    """Best-effort Redis ``SETNX``-with-``EX`` dedup for hot event classes.

    Returns ``True`` if this event should be emitted (the dedup window was not
    already claimed). If Redis is unavailable for any reason we fall back to
    always emitting — an audit event is never silently dropped because of infra
    issues, only intentionally deduped.
    """
    try:
        from onyx.redis.redis_pool import get_redis_client

        client = get_redis_client(tenant_id=tenant_id)
        # ``nx=True`` returns truthy only when the key did not already exist;
        # ``None`` means a prior event already claimed this window.
        result = client.set(f"audit:{dedup_key}", "1", ex=ttl_seconds, nx=True)
        return bool(result)
    except Exception:
        return True


def emit_audit_event(
    action: AuditAction,
    outcome: AuditOutcome,
    *,
    actor: AuditActor | None = None,
    resource_type: str | None = None,
    resource_id: str | int | None = None,
    dedup_key: str | None = None,
    dedup_ttl_seconds: int = _DEFAULT_DEDUP_TTL_SECONDS,
    extra: dict[str, Any] | None = None,
) -> None:
    """Emit a single structured audit line. **Never raises.**

    Args:
        action: The audited action, from the :class:`AuditAction` taxonomy.
        outcome: success / failure / denied.
        actor: Who did it (best-effort; may be ``None`` for unauthenticated
            paths such as a failed login).
        resource_type: Coarse type of the affected resource, e.g.
            ``"llm_provider"``, ``"user"``, ``"api_key"``.
        resource_id: Identifier of the affected resource (row id or name).
        dedup_key: If provided, suppress duplicate events sharing this key
            within ``dedup_ttl_seconds`` (Redis-backed; degrades to always-emit
            if Redis is down). Use for high-volume classes; omit for
            low-volume ones (most config/access-control changes).
        dedup_ttl_seconds: Dedup window when ``dedup_key`` is set.
        extra: Extra non-secret context merged into the event under ``"extra"``.
            **Never** put secret values here.

    Tenant / request / endpoint / client-IP context is gathered automatically.
    """
    try:
        tenant_id = _safe_get_tenant_id()

        if dedup_key is not None and not should_emit(
            dedup_key, dedup_ttl_seconds, tenant_id
        ):
            return

        ocsf_class = _OCSF_CLASS_BY_ACTION.get(action)

        payload: dict[str, Any] = {
            "audit_schema_version": AUDIT_SCHEMA_VERSION,
            "ts": time.time(),
            "action": action.value,
            "ocsf_class": ocsf_class.value if ocsf_class else None,
            "outcome": outcome.value,
            "tenant_id": tenant_id,
            "actor": actor.to_dict() if actor else None,
            "resource_type": resource_type,
            "resource_id": str(resource_id) if resource_id is not None else None,
            "request_id": _safe_get_request_id(),
            "endpoint": _safe_get_endpoint(),
            "source_ip": _safe_get_client_ip(),
            "extra": extra or None,
        }

        # One JSON object as the message body — parseable identically under
        # ``plain`` and ``json`` LOG_FORMAT. ``default=str`` keeps any stray
        # non-serializable value from raising.
        _logger_for(ocsf_class).info(json.dumps(payload, default=str))
    except Exception:
        # Audit must never break the caller. Last-resort swallow.
        return


def _logger_for(ocsf_class: OCSFEventClass | None) -> logging.Logger:
    """Return the per-class child logger (or the root if class is unknown)."""
    name = (
        AUDIT_LOGGER_ROOT
        if ocsf_class is None
        else f"{AUDIT_LOGGER_ROOT}.{ocsf_class.value}"
    )
    logger = logging.getLogger(name)
    logger.setLevel(logging.INFO)
    return logger
