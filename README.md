# inventory-patched-task-definitions

Tooling to audit AWS ECS Fargate task definitions for CrowdStrike Falcon sensor coverage using the Falcon Cloud Asset Inventory API, and to register test task definitions for validation.

## Overview

When the Falcon container sensor is deployed to ECS Fargate, it is injected into a task definition as an init container via `falconutil patch-image`. This repo provides two tools:

- **`audit_task_definitions.py`** — queries CrowdStrike Cloud Asset Inventory for all `AWS::ECS::TaskDefinition` resources in your account and reports which task definitions have been patched with the Falcon sensor and which have not.
- **`register_test_task_definitions.sh`** — registers a set of test task definitions in AWS (5 unpatched, 2 patched) for validating the audit script.

## Requirements

- Python 3.10+
- `pip install requests`
- AWS CLI v2 + `jq` (for `register_test_task_definitions.sh` only)
- A CrowdStrike API client with **Cloud Security API Assets: Read** scope

## audit_task_definitions.py

### Usage

```bash
# Set credentials via environment variables (recommended)
export FALCON_CLIENT_ID=<your_client_id>
export FALCON_CLIENT_SECRET=<your_client_secret>

python3 audit_task_definitions.py
```

By default the script targets the US-1 cloud and reports only the latest revision of each task definition family.

### Options

| Flag | Description |
|---|---|
| `--client-id` | Falcon API client ID (or set `FALCON_CLIENT_ID`) |
| `--client-secret` | Falcon API client secret (or set `FALCON_CLIENT_SECRET`) |
| `--cloud` | Falcon cloud: `us-1`, `us-2`, `eu-1`, `us-gov-1`, `us-gov-2` (default: `us-1`) |
| `--account-id` | Filter by AWS account ID |
| `--region` | Filter by AWS region |
| `--verbose` / `-v` | Show account, region, ARN, AWS tags, and detection reason for each result |
| `--all-revisions` | Report all revisions instead of latest only |
| `--json` | Output results as JSON |

### Examples

```bash
# Verbose output against US-2
python3 audit_task_definitions.py --cloud us-2 --verbose

# Filter to a specific account and region
python3 audit_task_definitions.py --account-id 123456789012 --region us-east-1

# JSON output for scripting
python3 audit_task_definitions.py --json | jq '.[] | select(.patched == false)'

# Show all revisions, not just latest
python3 audit_task_definitions.py --all-revisions --verbose
```

### Detection logic

The script inspects the `containerDefinitions` in each task definition's configuration for the following Falcon sensor indicators:

| Signal | What it looks for |
|---|---|
| Image name | `falcon-container`, `falcon-sensor`, `falconutil` |
| Container name | `falcon`, `crowdstrike` |
| Environment variables | `CS_FARGATE_MODE`, `FALCONCTL_OPT`, `CrowdStrike_CID` |
| Volume mounts | `/tmp/CrowdStrike` |

### Note on assessment frequency

The Cloud Asset Inventory reflects the state of your AWS account as of the last CSPM assessment. For standard IOM-only accounts this runs on a schedule (default: 2 hours after the last successful scan). AWS accounts with real-time visibility and detection enabled will reflect changes near-instantly.

---

## register_test_task_definitions.sh

Registers 7 test task definitions into your AWS account for validating the audit script — 5 unpatched and 2 patched.

### Requirements

- AWS CLI v2 configured with credentials
- `jq`
- An ECR image URI for the Falcon container sensor (pushed to your registry)
- Your CrowdStrike CID with checksum

### Usage

```bash
./register_test_task_definitions.sh \
  --falcon-image <ECR_IMAGE_URI> \
  --cid <CROWDSTRIKE_CID_WITH_CHECKSUM> \
  [--region us-east-1] \
  [--role-arn arn:aws:iam::123456789012:role/ECSTaskExecutionRole] \
  [--dry-run]
```

Use `--dry-run` to preview the JSON that would be registered without making any AWS API calls.

### Registered families

| Family | Sensor |
|---|---|
| `test-unpatched-nginx` | None |
| `test-unpatched-httpd` | None |
| `test-unpatched-node-app` | None |
| `test-unpatched-python-api` | None |
| `test-unpatched-multi-container` | None |
| `test-patched-nginx` | Falcon init container |
| `test-patched-python-api` | Falcon init container |

### Cleanup

```bash
for family in test-unpatched-nginx test-unpatched-httpd \
    test-unpatched-node-app test-unpatched-python-api \
    test-unpatched-multi-container test-patched-nginx \
    test-patched-python-api; do
  aws ecs list-task-definitions --family-prefix "$family" \
    --query 'taskDefinitionArns[]' --output text \
    | tr '\t' '\n' \
    | xargs -I{} aws ecs deregister-task-definition --task-definition {}
done
```

