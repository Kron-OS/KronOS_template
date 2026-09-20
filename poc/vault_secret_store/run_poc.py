"""Real PoC: per-org connector secret storage on real Vault 1.17 via hvac
2.4.0, against the real `kronos-connectors` KV-v2 mount + AppRole this
PoC's own docker-compose.yml provisions (mirrors the wiring added to the
real dev-compose file).

Proves, against the real running Vault (not mocked):
  1. write/read/delete round-trip via hvac's kv.v2 helpers
  2. two different fake org_ids' secrets never collide -- org B never sees
     org A's value at the same source_type, and deleting org A's secret
     does not touch org B's
  3. reading a path that was never written returns a clean "not found"
     (InvalidPath), not a crash or an empty-but-present value

Docs actually used: developer.hashicorp.com/vault/api-docs/secret/kv/kv-v2
(KV-v2 HTTP semantics -- the data/metadata path-prefixing hvac's kv.v2.*
helpers hide from the caller) and python-hvac.org's Client.secrets.kv.v2
reference for create_or_update_secret/read_secret_version/
delete_metadata_and_all_versions signatures.

Real, explicit limitation (not glossed over): this AppRole's Vault policy
is static -- both org_a and org_b secrets are reachable by the SAME
kronos-connectors-app token, scoped to the whole mount, not per-org. The
isolation this PoC proves is **application-layer path discipline** (the
caller always supplies org_id from an authenticated TenantContext, never
from client input) -- not a Vault-native per-org ACL boundary. Real
per-org Vault ACL isolation (dynamic policies templated on an org-id token
claim) is a stronger hardening explicitly out of scope for this pass.
"""

from __future__ import annotations

import sys
import uuid

import hvac

VAULT_ADDR = "http://localhost:18220"
MOUNT = "kronos-connectors"


def log(*args: object) -> None:
    print(*args, file=sys.stderr)


def approle_login(role_id: str, secret_id: str) -> hvac.Client:
    client = hvac.Client(url=VAULT_ADDR)
    resp = client.auth.approle.login(role_id=role_id, secret_id=secret_id)
    client.token = resp["auth"]["client_token"]
    assert client.is_authenticated(), "AppRole login did not yield a valid token"
    return client


def main() -> None:
    role_id = sys.argv[1]
    secret_id = sys.argv[2]
    log(f"Vault addr: {VAULT_ADDR}, mount: {MOUNT}")

    client = approle_login(role_id, secret_id)
    log("AppRole login OK, token is valid (client.is_authenticated() == True)")

    org_a = str(uuid.uuid4())
    org_b = str(uuid.uuid4())
    source_type = "sentinel"
    log(f"org_a = {org_a}")
    log(f"org_b = {org_b}")

    secret_a = {"client_secret": f"org-a-secret-{uuid.uuid4()}", "tenant_id": "tenant-a"}
    secret_b = {"client_secret": f"org-b-secret-{uuid.uuid4()}", "tenant_id": "tenant-b"}

    # --- 1. write ---
    client.secrets.kv.v2.create_or_update_secret(
        path=f"{org_a}/{source_type}", secret=secret_a, mount_point=MOUNT
    )
    client.secrets.kv.v2.create_or_update_secret(
        path=f"{org_b}/{source_type}", secret=secret_b, mount_point=MOUNT
    )
    log(f"wrote secret_a to {org_a}/{source_type}")
    log(f"wrote secret_b to {org_b}/{source_type}")

    # --- 2. read back, assert correctness and no cross-contamination ---
    read_a = client.secrets.kv.v2.read_secret_version(
        path=f"{org_a}/{source_type}", mount_point=MOUNT, raise_on_deleted_version=True
    )["data"]["data"]
    read_b = client.secrets.kv.v2.read_secret_version(
        path=f"{org_b}/{source_type}", mount_point=MOUNT, raise_on_deleted_version=True
    )["data"]["data"]
    log(f"read back org_a: {read_a}")
    log(f"read back org_b: {read_b}")

    assert read_a == secret_a, "org_a read-back does not match what was written"
    assert read_b == secret_b, "org_b read-back does not match what was written"
    assert read_a != read_b, "org_a and org_b secrets are identical -- collision!"
    assert read_a["client_secret"] != read_b["client_secret"]
    print("PASS: write/read round-trip correct, org_a != org_b (no collision)")

    # --- 3. list mount, confirm both org paths present and distinct ---
    listed = client.secrets.kv.v2.list_secrets(path="", mount_point=MOUNT)["data"]["keys"]
    log(f"vault kv list {MOUNT}/ -> {listed}")
    assert f"{org_a}/" in listed
    assert f"{org_b}/" in listed
    print("PASS: both org paths visible and distinct under the mount")

    # --- 4. delete org_a, confirm org_b untouched ---
    client.secrets.kv.v2.delete_metadata_and_all_versions(
        path=f"{org_a}/{source_type}", mount_point=MOUNT
    )
    log(f"deleted {org_a}/{source_type}")

    try:
        client.secrets.kv.v2.read_secret_version(
            path=f"{org_a}/{source_type}", mount_point=MOUNT, raise_on_deleted_version=True
        )
        print("FAIL: org_a secret still readable after delete")
        sys.exit(1)
    except hvac.exceptions.InvalidPath:
        print("PASS: org_a secret cleanly gone after delete (InvalidPath, not a crash)")

    read_b_after = client.secrets.kv.v2.read_secret_version(
        path=f"{org_b}/{source_type}", mount_point=MOUNT, raise_on_deleted_version=True
    )["data"]["data"]
    assert read_b_after == secret_b, "org_b was affected by deleting org_a -- collision!"
    print("PASS: org_b unaffected by org_a's deletion")

    # --- 5. reading a path that was never written ---
    never_written_org = str(uuid.uuid4())
    try:
        client.secrets.kv.v2.read_secret_version(
            path=f"{never_written_org}/{source_type}", mount_point=MOUNT
        )
        print("FAIL: reading a never-written path did not raise")
        sys.exit(1)
    except hvac.exceptions.InvalidPath:
        print("PASS: reading a never-written org path raises a clean InvalidPath")

    print("ALL CHECKS PASSED")


if __name__ == "__main__":
    main()
