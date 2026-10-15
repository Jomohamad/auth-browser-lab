# Signed by JOE
"""Tests for the declarative configuration schema.

Verifies that every supported AppConfig field has a spec, defaults validate,
value get/set and coercion work, and secrets are handled correctly.
"""

import pytest

from auth_audit import schema
from auth_audit.config import (
    AppConfig,
    AuthConfig,
    BrowserConfig,
    ReportConfig,
    SecurityChallengeConfig,
)
from auth_audit.schema import FieldType


class TestSchemaCoverage:
    """Every supported field must be represented in the schema."""

    def test_top_level_fields_covered(self):
        top = set(AppConfig.model_fields.keys())
        spec_top = {s.path for s in schema.SPECS if "." not in s.path}
        sections = {s.path.split(".", 1)[0] for s in schema.SPECS if "." in s.path}
        for name in top:
            assert name in spec_top or name in sections, f"missing top-level {name}"

    def test_nested_fields_covered(self):
        for name, model in (
            ("auth", AuthConfig),
            ("browser", BrowserConfig),
            ("report", ReportConfig),
            ("security", SecurityChallengeConfig),
        ):
            spec_keys = {
                s.path.split(".", 1)[1]
                for s in schema.SPECS
                if s.path.startswith(name + ".")
            }
            for field_name in model.model_fields:
                assert field_name in spec_keys, f"{name}.{field_name} not in schema"

    def test_defaults_validate(self):
        ok, errors = schema.validate_config(schema.default_config())
        assert ok, errors


class TestGetSet:
    def test_get_set_nested(self):
        cfg = {}
        schema.set_value(cfg, "auth.provider", "custom")
        assert schema.get_value(cfg, "auth.provider") == "custom"

    def test_get_missing_returns_none(self):
        assert schema.get_value({}, "auth.provider") is None

    def test_default_config_has_sections(self):
        cfg = schema.default_config()
        for key in ("target_url", "auth", "browser", "report", "security"):
            assert key in cfg


class TestCoerce:
    def _spec(self, ttype, **kw):
        return schema.SettingSpec("x", "X", "g", ttype, kw.get("default"), **{
            k: v for k, v in kw.items() if k != "default"
        })

    def test_bool(self):
        s = self._spec(FieldType.BOOL)
        assert schema.coerce_value(s, "yes") is True
        assert schema.coerce_value(s, "0") is False
        with pytest.raises(ValueError):
            schema.coerce_value(s, "maybe")

    def test_int_with_range(self):
        s = self._spec(FieldType.INT, min=1, max=10)
        assert schema.coerce_value(s, "5") == 5
        with pytest.raises(ValueError):
            schema.coerce_value(s, "99")
        with pytest.raises(ValueError):
            schema.coerce_value(s, "abc")

    def test_enum(self):
        s = schema.SettingSpec("x", "X", "g", FieldType.ENUM, "a", choices=("a", "b"))
        assert schema.coerce_value(s, "b") == "b"
        with pytest.raises(ValueError):
            schema.coerce_value(s, "c")

    def test_strlist(self):
        s = self._spec(FieldType.STRLIST)
        assert schema.coerce_value(s, "a\nb\n\nc") == ["a", "b", "c"]
        assert schema.coerce_value(s, ["a", "b"]) == ["a", "b"]


class TestSecrets:
    def test_secret_spec_marked_and_not_persisted(self):
        spec = schema.SPEC_BY_PATH["auth.password"]
        assert spec.secret is True
        assert spec.persist is False

    def test_default_config_excludes_password(self):
        cfg = schema.default_config()
        assert "password" not in cfg.get("auth", {})


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
