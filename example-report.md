# ECS Task Definition Audit

_Generated: 2026-01-15 09:42 UTC_

| | Count |
|---|---|
| Total revisions | 24 |
| Patched | 11 |
| Unpatched | 13 |
| Unpatched with active tasks | 2 |

## Patched

| Task Definition | Account | Region | Latest | Detection | Tags |
|---|---|---|---|---|---|
| `web-frontend:5` | 111122223333 | us-east-1 | ✅ | Falcon volume mount in container 'web-frontend': /tmp/CrowdStrike | `Environment=production` `Owner=platform-team` `Team=platform` |
| `web-frontend:4` | 111122223333 | us-east-1 |  | Falcon volume mount in container 'web-frontend': /tmp/CrowdStrike |  |
| `api-gateway:3` | 111122223333 | us-east-1 | ✅ | Falcon volume mount in container 'api-gateway': /tmp/CrowdStrike | `Environment=production` `Owner=backend-team` `Team=backend` |
| `payments-service:8` | 111122223333 | us-west-2 | ✅ | Falcon sensor image detected in container 'crowdstrike-falcon-init-container': 111122223333.dkr.ecr.us-west-2.amazonaws.com/falcon-container:latest | `Environment=production` `Owner=payments-team` `Team=payments` |
| `payments-service:7` | 111122223333 | us-west-2 |  | Falcon sensor image detected in container 'crowdstrike-falcon-init-container': 111122223333.dkr.ecr.us-west-2.amazonaws.com/falcon-container:latest |  |
| `auth-service:2` | 111122223333 | us-east-1 | ✅ | Falcon volume mount in container 'auth-service': /tmp/CrowdStrike | `Environment=production` `Owner=identity-team` `Team=identity` |
| `data-pipeline:4` | 444455556666 | eu-west-1 | ✅ | Falcon volume mount in container 'data-pipeline': /tmp/CrowdStrike | `Environment=production` `Owner=data-team` `Team=data` |
| `reporting-worker:2` | 444455556666 | eu-west-1 | ✅ | Falcon volume mount in container 'reporting-worker': /tmp/CrowdStrike | `Environment=staging` `Owner=data-team` `Team=data` |
| `notification-service:6` | 111122223333 | us-east-1 | ✅ | Falcon volume mount in container 'notification-service': /tmp/CrowdStrike | `Environment=production` `Owner=platform-team` `Team=platform` |
| `cache-warmer:1` | 444455556666 | eu-west-1 | ✅ | Falcon sensor container name detected: 'crowdstrike-falcon-init-container' | `Environment=production` `Owner=backend-team` `Team=backend` |
| `legacy-importer:3` | 444455556666 | eu-west-1 |  | Falcon volume mount in container 'legacy-importer': /tmp/CrowdStrike |  |

## Unpatched

| Task Definition | Account | Region | Latest | Active Tasks | Tags |
|---|---|---|---|---|---|
| `inventory-worker:4` | 111122223333 | us-east-1 | ⚠️ | 🔴 2 | `Environment=production` `Owner=ops-team` `Team=ops` |
| `inventory-worker:3` | 111122223333 | us-east-1 |  |  |  |
| `batch-processor:7` | 111122223333 | us-west-2 | ⚠️ | 🔴 1 | `Environment=production` `Owner=data-team` `Team=data` |
| `batch-processor:6` | 111122223333 | us-west-2 |  |  |  |
| `log-aggregator:2` | 444455556666 | eu-west-1 | ⚠️ |  | `Environment=staging` `Owner=platform-team` `Team=platform` |
| `dev-sandbox:1` | 444455556666 | us-east-1 | ⚠️ |  | `Environment=dev` `Owner=engineering` |
| `load-tester:3` | 111122223333 | us-east-2 | ⚠️ |  | `Environment=staging` `Owner=qa-team` `Team=qa` |
| `load-tester:2` | 111122223333 | us-east-2 |  |  |  |
| `load-tester:1` | 111122223333 | us-east-2 |  |  |  |
| `admin-portal:5` | 111122223333 | us-east-1 | ⚠️ |  | `Environment=production` `Owner=internal-tools` `Team=platform` |
| `admin-portal:4` | 111122223333 | us-east-1 |  |  |  |
| `scheduled-reports:1` | 444455556666 | eu-west-1 | ⚠️ |  | `Environment=production` `Owner=data-team` `Team=data` |
| `legacy-export:2` | 444455556666 | eu-west-1 | ⚠️ |  | `Environment=production` `Owner=ops-team` `Team=ops` |
