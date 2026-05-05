# inventory-patched-task-definitions

Tooling to audit AWS ECS Fargate task definitions for CrowdStrike Falcon sensor coverage using the Falcon Cloud Asset Inventory API, and to register test task definitions for validation.

## Overview

When the Falcon container sensor is deployed to ECS Fargate, it is injected into a task definition as an init container via `falconutil patch-image`. This repo provides two tools:

- **`audit_task_definitions.py`** — queries CrowdStrike Cloud Asset Inventory for all `AWS::ECS::TaskDefinition` resources in your account and reports which task definitions have been patched with the Falcon sensor and which have not.

## Requirements

- Python 3.10+
- `pip install requests`
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
| `--verbose` / `-v` | Show account, region, ARN, and detection reason for each result |
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

