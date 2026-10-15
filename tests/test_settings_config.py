# Signed by JOE
"""Tests for configuration persistence: atomic writes, backups, secret
stripping, validation, and resilience to interrupted writes."""

import json
import os

import pytest

from auth_audit import schema


class TestSave:
    def test_save_writes_and_backs_up(self, tmp_path):
        p = tmp_path / "config.json"
        p.write_text(json.dumps(schema.default_config()), encoding="utf-8")
        cfg = schema.default_config()
        cfg["target_url"] = "http://127.0.0.1:9999/login"
        cfg["allowed_hosts"] = ["127.0.0.1"]

        ok, errors, backup = schema.save_config(str(p), cfg)
        assert ok, errors
        loaded = json.loads(p.read_text(encoding="utf-8"))
        assert loaded["target_url"] == "http://127.0.0.1:9999/login"
        assert backup and os.path.exists(backup)

    def test_invalid_config_not_written(self, tmp_path):
        p = tmp_path / "config.json"
        original = schema.default_config()
        p.write_text(json.dumps(original), encoding="utf-8")

        cfg = schema.default_config()
        cfg["allowed_hosts"] = []  # invalid: at least one host required
        ok, errors, backup = schema.save_config(str(p), cfg)
        assert not ok, errors
        # Original file is preserved untouched.
        assert json.loads(p.read_text(encoding="utf-8"))["allowed_hosts"] == \
            original["allowed_hosts"]
        assert backup is None

    def test_preserves_unrelated_keys(self, tmp_path):
        p = tmp_path / "config.json"
        base = schema.default_config()
        base["custom_operator_note"] = "keep-me"
        p.write_text(json.dumps(base), encoding="utf-8")

        cfg = schema.load_raw_config(p)
        schema.set_value(cfg, "browser.headless", True)
        schema.save_config(str(p), cfg)

        loaded = json.loads(p.read_text(encoding="utf-8"))
        assert loaded["custom_operator_note"] == "keep-me"
        assert loaded["browser"]["headless"] is True


class TestAtomicWrite:
    def test_secret_never_persisted(self, tmp_path):
        from auth_audit import config as configmod

        p = tmp_path / "config.json"
        cfg = schema.default_config()
        schema.set_value(cfg, "auth.password", "SuperSecret123")
        configmod.write_config_atomic(str(p), cfg)
        text = p.read_text(encoding="utf-8")
        assert "SuperSecret123" not in text
        assert "auth" in text  # still has the auth section

    def test_interrupted_write_leaves_original_intact(self, tmp_path, monkeypatch):
        p = tmp_path / "config.json"
        original = schema.default_config()
        p.write_text(json.dumps(original), encoding="utf-8")

        def boom(src, dst):
            raise OSError("simulated disk full")

        monkeypatch.setattr(os, "replace", boom)
        from auth_audit import config as configmod

        with pytest.raises(OSError):
            configmod.write_config_atomic(str(p), original)

        # Original file still valid & unchanged.
        assert json.loads(p.read_text(encoding="utf-8")) == original
        # No leftover temp files.
        leftovers = [f for f in os.listdir(tmp_path) if f.endswith(".tmp")]
        assert leftovers == []

    def test_backup_created_before_overwrite(self, tmp_path):
        from auth_audit import config as configmod

        p = tmp_path / "config.json"
        p.write_text("{}", encoding="utf-8")
        backup = configmod.backup_config(p)
        assert backup is not None and os.path.exists(backup)


class TestReset:
    def test_reset_to_defaults(self):
        cfg = schema.default_config()
        schema.set_value(cfg, "browser.headless", True)
        # Reset specific field back to its default.
        spec = schema.SPEC_BY_PATH["browser.headless"]
        schema.set_value(cfg, "browser.headless", spec.default)
        assert schema.get_value(cfg, "browser.headless") == spec.default


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
