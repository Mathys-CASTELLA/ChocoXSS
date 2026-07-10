"""
Tests unitaires — modules/common/config.py

Couvre la résolution du fichier ~/.chocoxss.conf :
  - lecture et validation TOML (racine + sections [crawl]/[scan])
  - priorité CLI > variables d'environnement > fichier > défaut argparse
  - gestion des erreurs (TOML invalide, fichier absent, clés inconnues)
"""

import argparse
import os
from pathlib import Path

import pytest

from modules.common.config import (
    load_config,
    load_env_overrides,
    apply_to_parser,
    _generate_default_config,
    CONFIGURABLE_KEYS,
)


@pytest.fixture
def tmp_config_file(tmp_path):
    def _make(content: str) -> Path:
        p = tmp_path / "test.conf"
        p.write_text(content)
        return p
    return _make


@pytest.fixture(autouse=True)
def clean_env():
    saved = {k: v for k, v in os.environ.items() if k.startswith("CHOCOXSS_")}
    for k in saved:
        del os.environ[k]
    yield
    for k in list(os.environ):
        if k.startswith("CHOCOXSS_"):
            del os.environ[k]
    os.environ.update(saved)


class TestLoadConfig:

    def test_reads_root_level_values(self, tmp_config_file):
        p = tmp_config_file('insecure = true\ntimeout = 20\ndelay = 0.5\n')
        cfg = load_config(p)
        assert cfg["insecure"] is True
        assert cfg["timeout"] == 20
        assert cfg["delay"] == 0.5

    def test_reads_nested_crawl_section(self, tmp_config_file):
        p = tmp_config_file('[crawl]\ncrawl_depth = 2\nmax_pages = 30\ncrawl_external = true\n')
        cfg = load_config(p)
        assert cfg["crawl_depth"] == 2
        assert cfg["max_pages"] == 30
        assert cfg["crawl_external"] is True

    def test_reads_nested_scan_section(self, tmp_config_file):
        p = tmp_config_file('[scan]\nverbose = true\nbypass = true\nno_verify = false\n')
        cfg = load_config(p)
        assert cfg["verbose"] is True
        assert cfg["bypass"] is True
        assert cfg["no_verify"] is False

    def test_unknown_key_silently_ignored(self, tmp_config_file):
        p = tmp_config_file('timeout = 15\nchamp_bidon = "x"\n')
        cfg = load_config(p)
        assert cfg["timeout"] == 15
        assert "champ_bidon" not in cfg

    def test_invalid_toml_returns_empty_dict(self, tmp_config_file):
        p = tmp_config_file('timeout = [invalide\n')
        assert load_config(p) == {}

    def test_missing_file_returns_empty_dict(self):
        assert load_config(Path("/tmp/does_not_exist_chocoxss.conf")) == {}

    def test_type_coercion_int_to_float_for_delay(self, tmp_config_file):
        p = tmp_config_file("delay = 1\n")  # int dans le TOML, float attendu
        cfg = load_config(p)
        assert cfg["delay"] == 1.0
        assert isinstance(cfg["delay"], float)

    def test_invalid_bool_type_rejected(self, tmp_config_file):
        p = tmp_config_file('insecure = "yes"\n')  # string au lieu de bool
        cfg = load_config(p)
        assert "insecure" not in cfg


class TestLoadEnvOverrides:

    def test_reads_chocoxss_prefixed_vars(self):
        os.environ["CHOCOXSS_DELAY"] = "0.7"
        os.environ["CHOCOXSS_INSECURE"] = "true"
        env = load_env_overrides()
        assert env["delay"] == 0.7
        assert env["insecure"] is True

    def test_ignores_unknown_keys(self):
        os.environ["CHOCOXSS_NOT_A_REAL_KEY"] = "x"
        env = load_env_overrides()
        assert "not_a_real_key" not in env

    def test_config_env_var_itself_not_treated_as_a_key(self):
        os.environ["CHOCOXSS_CONFIG"] = "/some/path.conf"
        env = load_env_overrides()
        assert "config" not in env


class TestPriorityResolution:

    def _make_parser(self):
        p = argparse.ArgumentParser()
        p.add_argument("--timeout", type=int, default=10)
        p.add_argument("--delay", type=float, default=0.0)
        p.add_argument("-k", "--insecure", action="store_true", dest="insecure")
        return p

    def test_file_value_used_without_cli_or_env(self, tmp_config_file):
        p = tmp_config_file("timeout = 25\n")
        parser = self._make_parser()
        apply_to_parser(parser, config_path=p, verbose=False)
        args = parser.parse_args([])
        assert args.timeout == 25

    def test_env_overrides_file(self, tmp_config_file):
        p = tmp_config_file("timeout = 25\n")
        os.environ["CHOCOXSS_TIMEOUT"] = "40"
        parser = self._make_parser()
        apply_to_parser(parser, config_path=p, verbose=False)
        args = parser.parse_args([])
        assert args.timeout == 40

    def test_cli_always_wins(self, tmp_config_file):
        p = tmp_config_file("timeout = 25\n")
        os.environ["CHOCOXSS_TIMEOUT"] = "40"
        parser = self._make_parser()
        apply_to_parser(parser, config_path=p, verbose=False)
        args = parser.parse_args(["--timeout", "5"])
        assert args.timeout == 5

    def test_default_used_when_nothing_configured(self):
        parser = self._make_parser()
        apply_to_parser(parser, config_path=Path("/tmp/nope.conf"), verbose=False)
        args = parser.parse_args([])
        assert args.timeout == 10

    def test_partial_cli_keeps_other_file_values(self, tmp_config_file):
        p = tmp_config_file("timeout = 25\ndelay = 0.5\n")
        parser = self._make_parser()
        apply_to_parser(parser, config_path=p, verbose=False)
        args = parser.parse_args(["--delay", "1.0"])
        assert args.delay == 1.0     # CLI
        assert args.timeout == 25    # fichier, non écrasé

    def test_empty_proxy_from_config_does_not_override_none_default(self, tmp_config_file):
        p = tmp_config_file('proxy = ""\n')
        parser = argparse.ArgumentParser()
        parser.add_argument("-p", "--proxy", default=None)
        apply_to_parser(parser, config_path=p, verbose=False)
        args = parser.parse_args([])
        assert args.proxy is None


class TestGenerateDefaultConfig:

    def test_contains_all_configurable_keys(self):
        content = _generate_default_config()
        for key in CONFIGURABLE_KEYS:
            assert key in content, f"clé '{key}' absente du template"

    def test_is_valid_toml(self):
        import tomllib
        content = _generate_default_config()
        parsed = tomllib.loads(content)
        assert isinstance(parsed, dict)

    def test_has_crawl_and_scan_sections(self):
        content = _generate_default_config()
        assert "[crawl]" in content
        assert "[scan]" in content
