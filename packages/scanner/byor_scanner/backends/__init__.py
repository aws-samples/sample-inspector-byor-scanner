"""Built-in plugin backends shipped with the scanner.

Custom backends (auth or discovery) MAY live elsewhere ─ typically in a
Lambda Layer at ``/opt/python/`` ─ and are selected via the
``BYOR_AUTH_PROVIDER`` and ``BYOR_DISCOVERY_BACKEND`` environment vars.
"""
