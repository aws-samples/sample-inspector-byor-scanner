"""Subprocess wrapper around the external CLI tools the scanner shells out to.

Centralises the timeout / env / classify pattern that ``skopeo inspect``,
``skopeo copy``, and ``inspector-sbomgen`` all need ─ saves us from copy-
pasting the try/except/classify dance in every pipeline step.
"""

from __future__ import annotations

import subprocess
from collections.abc import Callable

from byor_scanner.errors import ScanError


def run(
    *,
    argv: list[str],
    timeout: int,
    timeout_error_code: str,
    timeout_message: str,
    failure_classifier: Callable[[str], str],
    failure_message: str,
) -> subprocess.CompletedProcess[str]:
    """Run a CLI tool with timeout enforcement and typed-error mapping.

    :param argv: Full argv (program path + args).
    :param timeout: Seconds before subprocess is killed.
    :param timeout_error_code: ``ScanError`` code raised on timeout.
    :param timeout_message: Human-readable timeout message.
    :param failure_classifier: Callable that maps the subprocess stderr
        to a ``ScanError`` code (e.g. ``classify_pull_error``).
    :param failure_message: Human-readable label included in the raised
        ``ScanError`` message (e.g. ``"skopeo copy failed"``).
    :returns: The completed process when exit code is 0.
    :raises ScanError: on timeout or non-zero exit.
    """
    env = {
        # /tmp is the only writable dir in a Lambda exec env. Skopeo and
        # sbomgen both honor these; without them they try to write to
        # $HOME/.local which is read-only.
        "HOME": "/tmp",
        "TMPDIR": "/tmp",
        # A minimal, credential-free env for the external binaries.
        **_inherited_env(),
    }

    try:
        result = subprocess.run(  # noqa: S603 ─ argv is constructed, not user input
            argv,
            capture_output=True,
            text=True,
            timeout=timeout,
            env=env,
            check=False,
        )
    except subprocess.TimeoutExpired as e:
        raise ScanError(timeout_error_code, timeout_message) from e

    if result.returncode != 0:
        code = failure_classifier(result.stderr)
        raise ScanError(code, f"{failure_message}: {result.stderr.strip()}")

    return result


def _inherited_env() -> dict[str, str]:
    """Minimal, credential-free env for skopeo / inspector-sbomgen.

    A strict allowlist, NOT a broad ``AWS_*`` passthrough: these binaries parse
    untrusted registry content and auth via CLI args, so they must not be handed
    the execution role's AWS credentials. ``BYOR_*`` is read in-process, so it's
    omitted too.
    """
    import os

    keep = {"PATH", "AWS_REGION", "AWS_DEFAULT_REGION", "_X_AMZN_TRACE_ID"}
    return {k: v for k, v in os.environ.items() if k in keep}
