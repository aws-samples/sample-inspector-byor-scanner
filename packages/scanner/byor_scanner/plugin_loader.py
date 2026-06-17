"""Plugin loader ─ resolves a dotted module path into an instance.

Plugins are loaded once per cold start. The dotted path is read from an
environment variable (e.g. ``BYOR_AUTH_PROVIDER=mypkg.MyAuth``), defaulting
to a built-in if unset.

We use ``isinstance`` against a ``runtime_checkable`` Protocol for a
loose smoke-check. Note that ``runtime_checkable`` only verifies method
*names* exist, not that signatures match. A misnamed argument will surface
at first call as a ``TypeError``; that's an acceptable trade-off for not
forcing custom plugins to import this package.
"""

from __future__ import annotations

import importlib
import os
from typing import Any, TypeVar

from aws_lambda_powertools import Logger

from byor_scanner.constants import SERVICE_SCANNER

logger = Logger(service=SERVICE_SCANNER)

T = TypeVar("T")


def load_plugin_from_path(dotted_path: str, protocol: type[T]) -> T:
    """Resolve a dotted path to a class, instantiate it, and protocol-check.

    Unlike :func:`load_plugin`, this performs no environment lookup ─ the
    caller supplies the dotted path directly (e.g. a per-registry
    ``authProvider`` from ``BYOR_REGISTRIES``).

    :param dotted_path: ``"module.path.ClassName"``.
    :param protocol: Protocol class to validate against. Must be
        ``@runtime_checkable``.
    :returns: An instance of the loaded class.
    :raises ImportError: invalid path or class missing.
    :raises TypeError: loaded class does not implement the protocol.
    """
    if "." not in dotted_path:
        raise ImportError(
            f"Invalid plugin path {dotted_path!r}: must be 'module.path.ClassName'"
        )

    module_name, class_name = dotted_path.rsplit(".", 1)

    logger.info(
        "Loading plugin",
        extra={"moduleName": module_name, "className": class_name},
    )

    module = importlib.import_module(module_name)
    cls = getattr(module, class_name, None)
    if cls is None:
        raise ImportError(f"Class {class_name!r} not found in module {module_name!r}")

    instance = cls()

    if not isinstance(instance, protocol):
        raise TypeError(
            f"{cls.__name__} does not implement {protocol.__name__}. "
            f"Required methods: {_protocol_methods(protocol)}"
        )

    return instance


def load_plugin(env_var: str, protocol: type[T], default: str) -> T:
    """Resolve ``env_var`` to a class, instantiate it, and protocol-check.

    :param env_var: Name of the environment variable holding the dotted
        module path (``"module.path.ClassName"``).
    :param protocol: Protocol class to validate against. Must be
        ``@runtime_checkable``.
    :param default: Dotted path used when ``env_var`` is unset.
    :returns: An instance of the loaded class.
    :raises ImportError: invalid path or class missing.
    :raises TypeError: loaded class does not implement the protocol.
    """
    return load_plugin_from_path(os.environ.get(env_var, default), protocol)


def _protocol_methods(protocol: type[Any]) -> list[str]:
    return [
        name
        for name in dir(protocol)
        if not name.startswith("_") and callable(getattr(protocol, name, None))
    ]
