"""Fixtures for craft integration tests.

The craft suite runs against a real out-of-process api_server, not the
integration framework's in-process ``TestClient``: sandbox provisioning
health-checks a bridge-only ``sandbox-<id>`` hostname the host pytest process
can't resolve, so the in-process app can never finish a ``create session``.
These session-scoped overrides swap in an httpx client and drop the in-process
celery/playwright/reset wiring. The ``docker_e2e`` and ``k8s`` subdirs override
again for their own targets/seeding.
"""

from __future__ import annotations

from collections.abc import Generator
from uuid import UUID

import httpx
import pytest

from tests.integration.common_utils import http_client
from tests.integration.common_utils.constants import ADMIN_USER_NAME
from tests.integration.common_utils.managers.build_session import BuildSessionManager
from tests.integration.common_utils.managers.llm_provider import LLMProviderManager
from tests.integration.common_utils.managers.user import UserManager
from tests.integration.common_utils.test_models import DATestUser


@pytest.fixture(scope="session", autouse=True)
def _test_client() -> Generator[httpx.Client, None, None]:
    """httpx client targeting the real api_server, replacing the parent
    in-process TestClient. Same name + scope so pytest picks this override."""
    real_client = httpx.Client(timeout=httpx.Timeout(60.0, connect=10.0))
    http_client.set_test_client(real_client)
    try:
        yield real_client
    finally:
        real_client.close()
        http_client.set_test_client(None)


@pytest.fixture(scope="session", autouse=True)
def _install_playwright() -> None:
    """No-op override: craft API-boundary tests don't use playwright."""
    return None


@pytest.fixture(scope="session", autouse=True)
def _start_celery_workers() -> Generator[None, None, None]:
    """No-op override: the deployed ``background`` worker runs the celery tasks."""
    yield None


@pytest.fixture(scope="session", autouse=True)
def _module_reset_and_seed() -> None:
    """Skip the parent's ``reset_all()`` -- an out-of-process ``alembic downgrade
    base`` deadlocks against the api_server's pooled connections -- and seed an
    admin + LLM provider once per session."""
    admin = UserManager.create(name=ADMIN_USER_NAME)
    LLMProviderManager.create(user_performing_action=admin, api_key="test-api-key")


@pytest.fixture(scope="module")
def shared_session(request: pytest.FixtureRequest) -> tuple[DATestUser, UUID]:
    """One provisioned session + sandbox, shared across a module's tests.

    Provisioning a Docker/K8s sandbox per test dominates this lane's runtime, so
    tests that only need *a* valid session to exercise endpoint behavior reuse
    this one instead of creating their own. It is owned by a per-module user
    isolated from the function-scoped ``admin_user``/``basic_user`` fixtures, so
    a sibling test's create/delete (which terminates a user's prior sandbox)
    can't disturb it.

    Use it for read-only / validation / ownership / offline-proxy checks. Tests
    that mutate-and-assert session-scoped state -- upload counts/bytes against
    caps, message turns, create/delete/restore, or "pristine empty session"
    checks -- must create their own per-test session.
    """
    slug = request.module.__name__.rsplit(".", 1)[-1].replace("_", "-")
    owner = UserManager.create(name=f"craft-shared-{slug}")
    body = BuildSessionManager.create(owner)
    return owner, UUID(body["id"])
