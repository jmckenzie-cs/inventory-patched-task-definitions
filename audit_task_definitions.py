#!/usr/bin/env python3
"""
audit_task_definitions.py

Queries CrowdStrike Cloud Asset Inventory for all AWS::ECS::TaskDefinition
resources and reports which ones have been patched with the Falcon container
sensor (via falconutil patch-image).

Usage:
    python3 audit_task_definitions.py [options]

    # Credentials via environment variables (recommended):
    export FALCON_CLIENT_ID=...
    export FALCON_CLIENT_SECRET=...
    python3 audit_task_definitions.py

    # Or pass credentials directly:
    python3 audit_task_definitions.py --client-id <id> --client-secret <secret>

    # Filter by AWS account or region:
    python3 audit_task_definitions.py --account-id 123456789012
    python3 audit_task_definitions.py --region us-east-1

    # Specify Falcon cloud environment:
    python3 audit_task_definitions.py --cloud us-2

Requirements:
    pip install requests
"""

import argparse
import json
import os
import sys
import textwrap
from typing import Optional

try:
    import requests
except ImportError:
    print("ERROR: 'requests' library is required. Run: pip install requests", file=sys.stderr)
    sys.exit(1)

CLOUD_BASES = {
    "us-1":     "https://api.crowdstrike.com",
    "us-2":     "https://api.us-2.crowdstrike.com",
    "eu-1":     "https://api.eu-1.crowdstrike.com",
    "us-gov-1": "https://api.laggar.gcw.crowdstrike.com",
    "us-gov-2": "https://api.us-gov-2.crowdstrike.mil",
}

FALCON_INIT_CONTAINER_IMAGE_HINTS = [
    "falcon-container",
    "falcon-sensor",
    "falconutil",
]

FALCON_ENV_VARS = {
    "CS_FARGATE_MODE",
    "FALCONCTL_OPT",
    "CrowdStrike_CID",
    "CrowdStrike_CCid",
}

FALCON_VOLUMES = {
    "/tmp/CrowdStrike",
}


def get_token(base_url: str, client_id: str, client_secret: str) -> str:
    resp = requests.post(
        f"{base_url}/oauth2/token",
        data={"client_id": client_id, "client_secret": client_secret},
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        timeout=30,
    )
    if resp.status_code != 201:
        print(f"ERROR: Failed to authenticate ({resp.status_code}): {resp.text}", file=sys.stderr)
        sys.exit(1)
    return resp.json()["access_token"]


def query_task_definition_ids(
    base_url: str,
    token: str,
    account_id: Optional[str],
    region: Optional[str],
) -> list[str]:
    """
    Returns all AWS::ECS::TaskDefinition resource IDs, paginated.
    """
    fql_parts = ["resource_type:'AWS::ECS::TaskDefinition'"]
    if account_id:
        fql_parts.append(f"account_id:'{account_id}'")
    if region:
        fql_parts.append(f"region:'{region}'")
    fql = "+".join(fql_parts)

    headers = {"Authorization": f"Bearer {token}"}
    ids = []
    offset = 0
    limit = 500

    while True:
        resp = requests.get(
            f"{base_url}/cloud-security-assets/queries/resources/v1",
            params={"filter": fql, "limit": limit, "offset": offset},
            headers=headers,
            timeout=30,
        )
        if resp.status_code != 200:
            print(f"ERROR: Query failed ({resp.status_code}): {resp.text}", file=sys.stderr)
            sys.exit(1)

        data = resp.json()
        batch = data.get("resources") or []
        ids.extend(batch)

        total = data.get("meta", {}).get("pagination", {}).get("total", 0)
        offset += len(batch)
        if offset >= total or not batch:
            break

    return ids


def get_resource_details(base_url: str, token: str, ids: list[str]) -> list[dict]:
    """
    Fetches full resource details in batches of 100 (API limit).
    """
    headers = {"Authorization": f"Bearer {token}"}
    resources = []
    batch_size = 100

    for i in range(0, len(ids), batch_size):
        batch = ids[i : i + batch_size]
        params = [("ids", rid) for rid in batch]
        resp = requests.get(
            f"{base_url}/cloud-security-assets/entities/resources/v1",
            params=params,
            headers=headers,
            timeout=30,
        )
        if resp.status_code != 200:
            print(f"ERROR: Entities fetch failed ({resp.status_code}): {resp.text}", file=sys.stderr)
            sys.exit(1)
        resources.extend(resp.json().get("resources") or [])

    return resources


def latest_revisions(resources: list[dict]) -> list[dict]:
    """
    Deduplicate resources by task definition family, keeping only the
    highest revision number per family. Revision is parsed from the ARN:
      arn:aws:ecs:<region>:<account>:task-definition/<family>:<revision>
    """
    latest: dict[str, dict] = {}
    for r in resources:
        arn = r.get("arn") or r.get("resource_id", "")
        # Extract family and revision from the ARN suffix (family:revision)
        td_part = arn.split("task-definition/")[-1] if "task-definition/" in arn else ""
        if ":" in td_part:
            family, rev_str = td_part.rsplit(":", 1)
            try:
                revision = int(rev_str)
            except ValueError:
                revision = 0
        else:
            family = td_part or arn
            revision = 0

        existing = latest.get(family)
        if existing is None or revision > existing["_revision"]:
            r["_revision"] = revision
            r["_family"] = family
            latest[family] = r

    return list(latest.values())


def is_falcon_patched(configuration_raw: str) -> tuple[bool, str]:
    """
    Inspects the task definition's configuration JSON for signs that
    falconutil patch-image was applied.

    Returns (patched: bool, reason: str).
    """
    if not configuration_raw:
        return False, "no configuration data"

    try:
        config = json.loads(configuration_raw)
    except json.JSONDecodeError:
        return False, "configuration JSON could not be parsed"

    container_defs = config.get("containerDefinitions") or []

    for container in container_defs:
        image = (container.get("image") or "").lower()
        name = (container.get("name") or "").lower()

        # Check image name for Falcon sensor hints
        if any(hint in image for hint in FALCON_INIT_CONTAINER_IMAGE_HINTS):
            return True, f"Falcon sensor image detected in container '{container.get('name')}': {container.get('image')}"

        # Check container name
        if any(hint in name for hint in ["falcon", "crowdstrike"]):
            return True, f"Falcon sensor container name detected: '{container.get('name')}'"

        # Check environment variables
        env_vars = {e.get("name") for e in (container.get("environment") or [])}
        matched_env = env_vars & FALCON_ENV_VARS
        if matched_env:
            return True, f"Falcon env var(s) found in container '{container.get('name')}': {', '.join(matched_env)}"

        # Check volume mounts
        mounts = [m.get("containerPath", "") for m in (container.get("mountPoints") or [])]
        matched_mounts = {m for m in mounts if any(fv in m for fv in FALCON_VOLUMES)}
        if matched_mounts:
            return True, f"Falcon volume mount in container '{container.get('name')}': {', '.join(matched_mounts)}"

    return False, "no Falcon sensor indicators found"


def print_report(resources: list[dict], verbose: bool) -> None:
    patched = []
    unpatched = []

    for r in resources:
        config_raw = r.get("configuration", "")
        patched_flag, reason = is_falcon_patched(config_raw)
        entry = {
            "name": r.get("resource_name") or r.get("resource_id", "unknown"),
            "account_id": r.get("account_id", ""),
            "region": r.get("region", ""),
            "arn": r.get("arn", ""),
            "reason": reason,
        }
        if patched_flag:
            patched.append(entry)
        else:
            unpatched.append(entry)

    total = len(resources)
    print(f"\nTask Definition Audit — {total} task definition(s) found\n")
    print(f"  Patched:   {len(patched)}")
    print(f"  Unpatched: {len(unpatched)}")
    print()

    if patched:
        print("=" * 60)
        print("PATCHED (Falcon sensor detected)")
        print("=" * 60)
        for e in patched:
            print(f"  {e['name']}")
            if verbose:
                print(f"    Account: {e['account_id']}  Region: {e['region']}")
                print(f"    ARN:     {e['arn']}")
                print(f"    Reason:  {e['reason']}")
        print()

    if unpatched:
        print("=" * 60)
        print("UNPATCHED (no Falcon sensor detected)")
        print("=" * 60)
        for e in unpatched:
            print(f"  {e['name']}")
            if verbose:
                print(f"    Account: {e['account_id']}  Region: {e['region']}")
                print(f"    ARN:     {e['arn']}")
                print(f"    Reason:  {e['reason']}")
        print()


def main():
    parser = argparse.ArgumentParser(
        description="Audit ECS task definitions for Falcon sensor presence via CrowdStrike Cloud Asset Inventory.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""
            Credentials can also be set via environment variables:
              FALCON_CLIENT_ID, FALCON_CLIENT_SECRET

            Available Falcon clouds: us-1, us-2, eu-1, us-gov-1, us-gov-2
        """),
    )
    parser.add_argument("--client-id", default=os.environ.get("FALCON_CLIENT_ID"), help="Falcon API client ID")
    parser.add_argument("--client-secret", default=os.environ.get("FALCON_CLIENT_SECRET"), help="Falcon API client secret")
    parser.add_argument("--cloud", default=os.environ.get("FALCON_CLOUD", "us-1"), choices=CLOUD_BASES.keys(), help="Falcon cloud environment (default: us-1)")
    parser.add_argument("--account-id", default=None, help="Filter by AWS account ID")
    parser.add_argument("--region", default=None, help="Filter by AWS region")
    parser.add_argument("--verbose", "-v", action="store_true", help="Show account, region, ARN, and detection reason for each task definition")
    parser.add_argument("--all-revisions", action="store_true", help="Report all revisions instead of latest only")
    parser.add_argument("--json", dest="json_output", action="store_true", help="Output results as JSON instead of human-readable text")

    args = parser.parse_args()

    if not args.client_id or not args.client_secret:
        parser.error("--client-id and --client-secret are required (or set FALCON_CLIENT_ID / FALCON_CLIENT_SECRET)")

    base_url = CLOUD_BASES[args.cloud]
    print(f"Authenticating against {base_url}...", file=sys.stderr)
    token = get_token(base_url, args.client_id, args.client_secret)

    print("Querying Cloud Asset Inventory for ECS task definitions...", file=sys.stderr)
    ids = query_task_definition_ids(base_url, token, args.account_id, args.region)

    if not ids:
        print("No AWS::ECS::TaskDefinition assets found. Verify your account is onboarded to CSPM.", file=sys.stderr)
        sys.exit(0)

    print(f"Fetching details for {len(ids)} task definition(s)...", file=sys.stderr)
    resources = get_resource_details(base_url, token, ids)

    if not args.all_revisions:
        before = len(resources)
        resources = latest_revisions(resources)
        if before != len(resources):
            print(f"Deduplicated to {len(resources)} unique family/revision(s) (use --all-revisions to see all).", file=sys.stderr)

    if args.json_output:
        results = []
        for r in resources:
            config_raw = r.get("configuration", "")
            patched_flag, reason = is_falcon_patched(config_raw)
            results.append({
                "name": r.get("resource_name") or r.get("resource_id"),
                "account_id": r.get("account_id"),
                "region": r.get("region"),
                "arn": r.get("arn"),
                "patched": patched_flag,
                "reason": reason,
            })
        print(json.dumps(results, indent=2))
    else:
        print_report(resources, args.verbose)


if __name__ == "__main__":
    main()
