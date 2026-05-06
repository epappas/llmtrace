from tests.e2e import conftest


def test_real_upstream_authorization_disabled_without_real_upstream(monkeypatch):
    monkeypatch.delenv(conftest.REAL_UPSTREAM_URL_ENV, raising=False)
    monkeypatch.setenv(conftest.REAL_UPSTREAM_API_KEY_ENV, "secret")

    assert conftest._real_upstream_authorization() is None


def test_real_upstream_authorization_uses_explicit_header(monkeypatch):
    monkeypatch.setenv(conftest.REAL_UPSTREAM_URL_ENV, "https://api.example.test/v1")
    monkeypatch.setenv(conftest.REAL_UPSTREAM_AUTHORIZATION_ENV, "Bearer explicit")
    monkeypatch.setenv(conftest.REAL_UPSTREAM_API_KEY_ENV, "raw-secret")

    assert conftest._real_upstream_authorization() == "Bearer explicit"


def test_real_upstream_authorization_builds_bearer_from_api_key(monkeypatch):
    monkeypatch.setenv(conftest.REAL_UPSTREAM_URL_ENV, "https://api.example.test/v1")
    monkeypatch.delenv(conftest.REAL_UPSTREAM_AUTHORIZATION_ENV, raising=False)
    monkeypatch.setenv(conftest.REAL_UPSTREAM_API_KEY_ENV, "raw-secret")

    assert conftest._real_upstream_authorization() == "Bearer raw-secret"


def test_chat_model_uses_mock_model_without_real_upstream(monkeypatch):
    monkeypatch.delenv(conftest.REAL_UPSTREAM_URL_ENV, raising=False)
    monkeypatch.setenv(conftest.REAL_UPSTREAM_MODEL_ENV, "real-model")

    assert conftest._chat_model() == conftest.DEFAULT_CHAT_MODEL


def test_chat_model_uses_real_upstream_model_when_configured(monkeypatch):
    monkeypatch.setenv(conftest.REAL_UPSTREAM_URL_ENV, "https://api.example.test/v1")
    monkeypatch.setenv(conftest.REAL_UPSTREAM_MODEL_ENV, "moonshot-v1-8k")

    assert conftest._chat_model() == "moonshot-v1-8k"


def test_chat_model_falls_back_when_real_upstream_model_is_blank(monkeypatch):
    monkeypatch.setenv(conftest.REAL_UPSTREAM_URL_ENV, "https://api.example.test/v1")
    monkeypatch.setenv(conftest.REAL_UPSTREAM_MODEL_ENV, "  ")

    assert conftest._chat_model() == conftest.DEFAULT_CHAT_MODEL
