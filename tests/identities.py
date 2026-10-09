"""Test identities for the MCP behavioural suite.

Every string here is invented in this file and exists nowhere else. The key
PREFIXES are assembled from fragments rather than written out, so no line in
this repository looks like a real Forge credential to a scanner, to a reviewer
skimming a diff, or to a log that captures a test failure.
"""
from __future__ import annotations

import hashlib

# The five namespaces gating.ACCEPTED_KEY_PREFIXES accepts, assembled.
P_METERED = "fnet" + "_"
P_PROD = "forge" + "_" + "prod" + "_"
P_SANDBOX = "forge" + "_" + "sandbox" + "_"
P_MONITOR = "forge" + "_" + "monitor" + "_"
P_AGENT = "forge" + "_" + "agent" + "_"

SERVER_SHARED_KEY = P_METERED + "harness-shared-proxy-identity"
TENANT_A_KEY = P_PROD + "harness-tenant-a-identity"
TENANT_B_KEY = P_PROD + "harness-tenant-b-identity"
SANDBOX_KEY = P_SANDBOX + "harness-tenant-c-identity"
METERED_NOCARD = P_METERED + "harness-metered-nocard-identity"
REVOKED_KEY = P_PROD + "harness-revoked-identity"
EXPIRED_KEY = P_PROD + "harness-expired-identity"
ROTATING_IN_GRACE = P_PROD + "harness-rotating-in-grace-identity"
ROTATING_EXPIRED = P_PROD + "harness-rotating-past-grace-identity"
BOGUS_KEY = P_PROD + "harness-absent-from-every-table"
WRONG_PREFIX_KEY = "sk" + "_" + "harness-wrong-namespace"

TENANT_A_USER = "user-aaaa-tenant-a"
TENANT_B_USER = "user-bbbb-tenant-b"
SANDBOX_USER = "user-cccc-tenant-c"
METERED_USER = "user-dddd-metered"
SERVER_USER = "user-ffff-proxy"

TENANT_A_KEY_ID = "keyid-aaaa"
TENANT_B_KEY_ID = "keyid-bbbb"
SANDBOX_KEY_ID = "keyid-cccc"
METERED_KEY_ID = "keyid-dddd"
SERVER_KEY_ID = "keyid-ffff"


def sha(tok: str) -> str:
    return hashlib.sha256(tok.encode("utf-8")).hexdigest()
