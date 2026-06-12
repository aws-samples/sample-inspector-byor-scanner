"""Unit tests configuration module.

Pinned env vars that must be set before any byor_scanner module is
imported. Several modules construct boto3 clients at import time;
without AWS_DEFAULT_REGION those raise NoRegionError. In the Lambda
runtime AWS_REGION is always present, so this only matters for tests.

The dummy access-key / secret-key prevent boto3 from picking up real
credentials from a developer machine and accidentally hitting an
account during a unit-test run.
"""

import os

os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")
os.environ.setdefault("AWS_ACCESS_KEY_ID", "testing")
os.environ.setdefault("AWS_SECRET_ACCESS_KEY", "testing")
