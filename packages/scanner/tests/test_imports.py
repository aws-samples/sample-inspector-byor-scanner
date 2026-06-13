"""Smoke tests for the scanner package.

Handler-level imports (``scanner.handler``, ``discovery_handler.handler``)
are tested in their own modules ─ they pull in the plugin layer at module
import time, which requires a concrete backend to exist. Those tests
arrive as the plugin backends land.
"""

from byor_scanner import config, errors, plugin_loader, protocols, validation


def test_config_loads() -> None:
    assert config.config.scan.max_image_size_gb >= 1
    assert config.config.scan.tls_verify is True


def test_protocols_runtime_checkable() -> None:
    class _Auth:
        def setup(self) -> None: ...
        def get_skopeo_args(self) -> list[str]: return []

    class _Discovery:
        def discover(self, event: dict) -> list[dict]:
            return []

    assert isinstance(_Auth(), protocols.AuthProvider)
    assert isinstance(_Discovery(), protocols.DiscoveryBackend)


def test_validation_accepts_oci_names() -> None:
    validation.validate_image_name("library/nginx")
    validation.validate_image_name("myorg/team/service")


def test_validation_rejects_path_traversal() -> None:
    try:
        validation.validate_image_name("../etc/passwd")
    except errors.ScanError as e:
        assert e.error_code == errors.INVALID_INPUT
    else:
        raise AssertionError("validate_image_name should reject path traversal")


def test_plugin_loader_module_not_found() -> None:
    try:
        plugin_loader.load_plugin(
            "BYOR_TEST_NONEXISTENT",
            protocols.AuthProvider,
            default="byor_scanner.does_not_exist.NoSuchClass",
        )
    except ImportError:
        pass
    else:
        raise AssertionError(
            "plugin_loader should raise ImportError for missing modules"
        )
