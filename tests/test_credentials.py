# Signed by JOE
"""Tests for secret resolution precedence (never persisted)."""

import pytest

from auth_audit import credentials as creds


class TestResolvePassword:
    def test_override_wins(self, monkeypatch):
        monkeypatch.setenv(creds.ENV_PASSWORD_VAR, "from-env")
        assert creds.resolve_password(
            override="explicit", prompt_ok=False, env={}
        ) == "explicit"

    def test_env_used_when_no_override(self, monkeypatch):
        monkeypatch.setattr(creds, "read_credential", lambda target=None: None)
        got = creds.resolve_password(
            prompt_ok=False, env={creds.ENV_PASSWORD_VAR: "env-secret"}
        )
        assert got == "env-secret"

    def test_credential_manager_used_after_env(self, monkeypatch):
        monkeypatch.setattr(
            creds, "read_credential", lambda target=None: "cm-secret"
        )
        got = creds.resolve_password(prompt_ok=False, env={})
        assert got == "cm-secret"

    def test_prompt_is_last_resort(self, monkeypatch):
        monkeypatch.setattr(creds, "read_credential", lambda target=None: None)

        class FakeGetpass:
            @staticmethod
            def getpass(prompt=""):
                return "typed-secret"

        monkeypatch.setitem(__import__("sys").modules, "getpass", FakeGetpass)
        got = creds.resolve_password(prompt_ok=True, env={})
        assert got == "typed-secret"

    def test_none_when_nothing_available(self, monkeypatch):
        monkeypatch.setattr(creds, "read_credential", lambda target=None: None)
        assert creds.resolve_password(prompt_ok=False, env={}) is None


class TestResolveUsername:
    def test_env_precedence(self):
        assert creds.resolve_username("cfguser", env={"AUTH_TEST_USERNAME": "envuser"}) \
            == "envuser"

    def test_config_fallback(self):
        assert creds.resolve_username("cfguser", env={}) == "cfguser"


class TestPlatformGuard:
    def test_credential_read_returns_none_off_windows(self, monkeypatch):
        monkeypatch.setattr(creds, "is_windows", lambda: False)
        assert creds.read_credential("x") is None
        assert creds.write_credential("secret") is False
        assert creds.delete_credential("x") is False


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
