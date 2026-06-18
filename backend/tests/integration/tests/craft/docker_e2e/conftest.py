"""Docker-e2e-only fixtures layered on the craft base conftest.

The real-httpx ``_test_client`` (and the no-reset/no-in-process-celery wiring)
lives in the parent ``craft/conftest.py`` -- the whole craft suite needs a real
api_server because ``DockerSandboxManager.provision`` health-checks
``http://sandbox-<id8>:4096``, a hostname only resolvable on the
``onyx_craft_sandbox`` bridge that the dockerized api_server (host port 8080)
can reach but a host process can't.

This file adds the docker-specific helpers (``docker_exec``,
``provision_sandbox``) and seeds a Slack ``external_app`` so the gate flow can
fire: ``ExternalAppActionMatcher`` only claims a request whose URL matches some
app's ``upstream_url_patterns``, and ``AUTO_PROVISION_DEFAULT_EXTERNAL_APPS``
defaults to off.
"""

from __future__ import annotations

import subprocess
from typing import Protocol
from uuid import UUID

import pytest

from onyx.db.engine.sql_engine import get_session_with_tenant
from onyx.db.enums import EndpointPolicy
from onyx.db.enums import ExternalAppType
from onyx.db.external_app import create_external_app
from onyx.db.external_app import get_built_in_external_app
from tests.integration.common_utils.managers.build_session import BuildSessionManager
from tests.integration.common_utils.test_models import DATestUser


class DockerExec(Protocol):
    def __call__(
        self,
        container: str,
        cmd: list[str],
        *,
        timeout: float = 30.0,
        user: str | None = None,
    ) -> subprocess.CompletedProcess[str]: ...


class ProvisionSandbox(Protocol):
    def __call__(self, user: DATestUser) -> tuple[UUID, str]: ...


def _container_name(sandbox_id: str) -> str:
    """Docker manager names containers ``sandbox-<id8>``."""
    return f"sandbox-{sandbox_id.split('-')[0]}"


def _docker_exec(
    container: str,
    cmd: list[str],
    *,
    timeout: float = 30.0,
    user: str | None = None,
) -> subprocess.CompletedProcess[str]:
    """Runs ``cmd`` inside ``container`` and captures stdout/stderr."""
    command = ["docker", "exec"]
    if user is not None:
        command.extend(["--user", user])
    command.extend([container, *cmd])
    return subprocess.run(
        command,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )


def _provision_sandbox(user: DATestUser) -> tuple[UUID, str]:
    """
    Creates a session via the real API and returns its (session_id, container).

    The create endpoint is synchronous -- by the time it returns, the sandbox
    container is RUNNING and opencode-serve has passed its health check.
    """
    session = BuildSessionManager.create(user)
    sandbox = session["sandbox"]
    assert sandbox is not None, f"Session response missing sandbox: {session!r}"
    assert sandbox["status"].upper() == "RUNNING", (
        f"Sandbox not RUNNING after create: {sandbox['status']!r}"
    )
    return UUID(session["id"]), _container_name(sandbox["id"])


@pytest.fixture(scope="session")
def docker_exec() -> DockerExec:
    return _docker_exec


@pytest.fixture(scope="session")
def provision_sandbox() -> ProvisionSandbox:
    return _provision_sandbox


@pytest.fixture(scope="module")
def slack_external_app() -> None:
    """
    Seeds Slack directly with ``enabled=True`` and an ``ASK`` policy on
    ``slack.messages.write`` so the gate matcher claims ``chat.postMessage``.

    Unlike ``provision_built_in_external_apps`` (which the cloud tenant-creation
    path runs when ``AUTO_PROVISION_DEFAULT_EXTERNAL_APPS=true``), this skips
    real credentials and the full action catalog -- the test only needs the one
    gated action. Re-seed is a no-op when the row already exists.
    """
    with get_session_with_tenant(tenant_id="public") as db:
        existing = get_built_in_external_app(db, ExternalAppType.SLACK)
        if existing is None:
            create_external_app(
                db_session=db,
                name="Slack",
                description="Slack integration for gate-flow e2e tests.",
                bundle_file_id="",
                bundle_sha256="",
                app_type=ExternalAppType.SLACK,
                upstream_url_patterns=["https://slack\\.com/api/.*"],
                auth_template={"Authorization": "Bearer {access_token}"},
                # Fake token. An unfillable template short-circuits the ASK gate
                # (forwards bare, no DB row), which breaks every gate-flow test.
                organization_credentials={"access_token": "fake-test-token"},
                enabled=True,
                is_public=True,
                action_policies={"slack.messages.write": EndpointPolicy.ASK},
            )
            db.commit()
