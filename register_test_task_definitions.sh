#!/usr/bin/env bash
# register_test_task_definitions.sh
#
# Registers test ECS task definitions in your AWS account:
#   - 5 unpatched (no Falcon sensor)
#   - 2 patched   (Falcon sensor via init container pattern)
#
# Usage:
#   ./register_test_task_definitions.sh \
#     --falcon-image <ECR_IMAGE_URI> \
#     --cid <CROWDSTRIKE_CID_WITH_CHECKSUM> \
#     [--region us-east-1] \
#     [--role-arn arn:aws:iam::123456789012:role/ECSTaskExecutionRole] \
#     [--dry-run]
#
# Requirements:
#   - aws CLI installed and configured
#   - jq installed

set -euo pipefail

# ── Defaults ──────────────────────────────────────────────────────────────────
REGION="${AWS_DEFAULT_REGION:-us-east-1}"
FALCON_IMAGE=""
FALCON_CID=""
ROLE_ARN=""
DRY_RUN=false

# ── Argument parsing ───────────────────────────────────────────────────────────
usage() {
  grep '^#' "$0" | head -20 | sed 's/^# \?//'
  exit 1
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --falcon-image) FALCON_IMAGE="$2"; shift 2 ;;
    --cid)          FALCON_CID="$2";   shift 2 ;;
    --region)       REGION="$2";       shift 2 ;;
    --role-arn)     ROLE_ARN="$2";     shift 2 ;;
    --dry-run)      DRY_RUN=true;      shift   ;;
    -h|--help)      usage ;;
    *) echo "Unknown argument: $1"; usage ;;
  esac
done

# ── Validate ───────────────────────────────────────────────────────────────────
if [[ -z "$FALCON_IMAGE" ]]; then
  echo "ERROR: --falcon-image is required"
  usage
fi

if [[ -z "$FALCON_CID" ]]; then
  echo "ERROR: --cid is required (CrowdStrike CID with checksum, e.g. ABCDEF1234-56)"
  usage
fi

for cmd in aws jq; do
  if ! command -v "$cmd" &>/dev/null; then
    echo "ERROR: '$cmd' is required but not found in PATH"
    exit 1
  fi
done

# ── Resolve account ID and execution role ──────────────────────────────────────
if [[ "$DRY_RUN" == "true" ]]; then
  ACCOUNT_ID="123456789012"
  echo "Dry-run mode — skipping AWS credential check"
  echo "  Account ID: $ACCOUNT_ID (placeholder)"
else
  echo "Resolving AWS account identity..."
  ACCOUNT_ID=$(aws sts get-caller-identity --query 'Account' --output text)
  echo "  Account ID: $ACCOUNT_ID"
fi
echo "  Region:     $REGION"

if [[ -z "$ROLE_ARN" ]]; then
  ROLE_ARN="arn:aws:iam::${ACCOUNT_ID}:role/ECSTaskExecutionRole"
  echo "  Execution role (default): $ROLE_ARN"
else
  echo "  Execution role (provided): $ROLE_ARN"
fi

# ── Helper ─────────────────────────────────────────────────────────────────────
register() {
  local name="$1"
  local json="$2"
  echo ""
  echo "── Registering: $name"
  if [[ "$DRY_RUN" == "true" ]]; then
    echo "   [dry-run] Would register:"
    echo "$json" | jq .
  else
    local tmpfile result
    tmpfile=$(mktemp /tmp/td-XXXXXX.json)
    echo "$json" > "$tmpfile"
    result=$(aws ecs register-task-definition \
      --region "$REGION" \
      --cli-input-json "file://$tmpfile" \
      --query 'taskDefinition.taskDefinitionArn' \
      --output text)
    rm -f "$tmpfile"
    echo "   Registered: $result"
  fi
}

# ── Unpatched task definitions ─────────────────────────────────────────────────
# 1. nginx web server
register "test-unpatched-nginx" "$(jq -n \
  --arg role "$ROLE_ARN" \
  --arg region "$REGION" \
  '{
    family: "test-unpatched-nginx",
    
    networkMode: "awsvpc",
    requiresCompatibilities: ["FARGATE"],
    cpu: "256",
    memory: "512",
    executionRoleArn: $role,
    taskRoleArn: $role,
    runtimePlatform: {
      cpuArchitecture: "X86_64",
      operatingSystemFamily: "LINUX"
    },
    tags: [
      {key: "Environment",  value: "production"},
      {key: "Application",  value: "web-frontend"},
      {key: "Team",         value: "platform"},
      {key: "CostCenter",   value: "CC-1011"}
    ],
    containerDefinitions: [{
      name: "nginx",
      image: "public.ecr.aws/nginx/nginx:stable",
      essential: true,
      cpu: 0,
      portMappings: [{
        name: "nginx-80-tcp",
        containerPort: 80,
        hostPort: 80,
        protocol: "tcp",
        appProtocol: "http"
      }],
      environment: [],
      mountPoints: [],
      volumesFrom: [],
      logConfiguration: {
        logDriver: "awslogs",
        options: {
          "awslogs-create-group": "true",
          "awslogs-group": "/ecs/test-td-audit",
          "awslogs-region": $region,
          "awslogs-stream-prefix": "ecs"
        }
      }
    }]
  }'
)"

# 2. Apache httpd
register "test-unpatched-httpd" "$(jq -n \
  --arg role "$ROLE_ARN" \
  --arg region "$REGION" \
  '{
    family: "test-unpatched-httpd",
    
    networkMode: "awsvpc",
    requiresCompatibilities: ["FARGATE"],
    cpu: "256",
    memory: "512",
    executionRoleArn: $role,
    taskRoleArn: $role,
    runtimePlatform: {
      cpuArchitecture: "X86_64",
      operatingSystemFamily: "LINUX"
    },
    tags: [
      {key: "Environment",  value: "production"},
      {key: "Application",  value: "web-server"},
      {key: "Team",         value: "infrastructure"},
      {key: "CostCenter",   value: "CC-1012"}
    ],
    containerDefinitions: [{
      name: "httpd",
      image: "public.ecr.aws/docker/library/httpd:2.4",
      essential: true,
      cpu: 0,
      portMappings: [{
        name: "httpd-80-tcp",
        containerPort: 80,
        hostPort: 80,
        protocol: "tcp",
        appProtocol: "http"
      }],
      environment: [],
      mountPoints: [],
      volumesFrom: [],
      logConfiguration: {
        logDriver: "awslogs",
        options: {
          "awslogs-create-group": "true",
          "awslogs-group": "/ecs/test-td-audit",
          "awslogs-region": $region,
          "awslogs-stream-prefix": "ecs"
        }
      }
    }]
  }'
)"

# 3. Node.js (busybox echo server stand-in)
register "test-unpatched-node-app" "$(jq -n \
  --arg role "$ROLE_ARN" \
  --arg region "$REGION" \
  '{
    family: "test-unpatched-node-app",
    
    networkMode: "awsvpc",
    requiresCompatibilities: ["FARGATE"],
    cpu: "512",
    memory: "1024",
    executionRoleArn: $role,
    taskRoleArn: $role,
    runtimePlatform: {
      cpuArchitecture: "X86_64",
      operatingSystemFamily: "LINUX"
    },
    tags: [
      {key: "Environment",  value: "production"},
      {key: "Application",  value: "node-api"},
      {key: "Team",         value: "backend"},
      {key: "CostCenter",   value: "CC-1013"}
    ],
    containerDefinitions: [{
      name: "node-app",
      image: "public.ecr.aws/docker/library/node:20-alpine",
      essential: true,
      cpu: 0,
      command: ["node", "-e", "require(\"http\").createServer((_,r)=>{r.end(\"ok\")}).listen(8080)"],
      portMappings: [{
        name: "node-app-8080-tcp",
        containerPort: 8080,
        hostPort: 8080,
        protocol: "tcp",
        appProtocol: "http"
      }],
      environment: [
        { name: "NODE_ENV", value: "production" }
      ],
      mountPoints: [],
      volumesFrom: [],
      logConfiguration: {
        logDriver: "awslogs",
        options: {
          "awslogs-create-group": "true",
          "awslogs-group": "/ecs/test-td-audit",
          "awslogs-region": $region,
          "awslogs-stream-prefix": "ecs"
        }
      }
    }]
  }'
)"

# 4. Python Flask (Alpine)
register "test-unpatched-python-api" "$(jq -n \
  --arg role "$ROLE_ARN" \
  --arg region "$REGION" \
  '{
    family: "test-unpatched-python-api",
    
    networkMode: "awsvpc",
    requiresCompatibilities: ["FARGATE"],
    cpu: "512",
    memory: "1024",
    executionRoleArn: $role,
    taskRoleArn: $role,
    runtimePlatform: {
      cpuArchitecture: "X86_64",
      operatingSystemFamily: "LINUX"
    },
    tags: [
      {key: "Environment",  value: "staging"},
      {key: "Application",  value: "python-api"},
      {key: "Team",         value: "backend"},
      {key: "CostCenter",   value: "CC-1014"}
    ],
    containerDefinitions: [{
      name: "python-api",
      image: "public.ecr.aws/docker/library/python:3.12-slim",
      essential: true,
      cpu: 0,
      command: ["python3", "-m", "http.server", "5000"],
      portMappings: [{
        name: "python-api-5000-tcp",
        containerPort: 5000,
        hostPort: 5000,
        protocol: "tcp",
        appProtocol: "http"
      }],
      environment: [
        { name: "APP_ENV", value: "test" },
        { name: "LOG_LEVEL", value: "info" }
      ],
      mountPoints: [],
      volumesFrom: [],
      logConfiguration: {
        logDriver: "awslogs",
        options: {
          "awslogs-create-group": "true",
          "awslogs-group": "/ecs/test-td-audit",
          "awslogs-region": $region,
          "awslogs-stream-prefix": "ecs"
        }
      }
    }]
  }'
)"

# 5. Redis cache — no sensor
register "test-unpatched-redis" "$(jq -n \
  --arg role "$ROLE_ARN" \
  --arg region "$REGION" \
  '{
    family: "test-unpatched-redis",
    networkMode: "awsvpc",
    requiresCompatibilities: ["FARGATE"],
    cpu: "512",
    memory: "1024",
    executionRoleArn: $role,
    taskRoleArn: $role,
    runtimePlatform: {
      cpuArchitecture: "X86_64",
      operatingSystemFamily: "LINUX"
    },
    tags: [
      {key: "Environment", value: "production"},
      {key: "Application", value: "cache"},
      {key: "Team",        value: "backend"},
      {key: "CostCenter",  value: "CC-1008"},
      {key: "owner",       value: "mckenzie"}
    ],
    containerDefinitions: [{
      name: "redis",
      image: "public.ecr.aws/docker/library/redis:7-alpine",
      essential: true,
      cpu: 0,
      portMappings: [{
        name: "redis-6379-tcp",
        containerPort: 6379,
        hostPort: 6379,
        protocol: "tcp"
      }],
      environment: [],
      mountPoints: [],
      volumesFrom: [],
      logConfiguration: {
        logDriver: "awslogs",
        options: {
          "awslogs-create-group": "true",
          "awslogs-group": "/ecs/test-td-audit",
          "awslogs-region": $region,
          "awslogs-stream-prefix": "ecs"
        }
      }
    }]
  }'
)"

# 6. Two-container app (sidecar pattern) — no sensor
register "test-unpatched-multi-container" "$(jq -n \
  --arg role "$ROLE_ARN" \
  --arg region "$REGION" \
  '{
    family: "test-unpatched-multi-container",
    
    networkMode: "awsvpc",
    requiresCompatibilities: ["FARGATE"],
    cpu: "512",
    memory: "1024",
    executionRoleArn: $role,
    taskRoleArn: $role,
    runtimePlatform: {
      cpuArchitecture: "X86_64",
      operatingSystemFamily: "LINUX"
    },
    tags: [
      {key: "Environment",  value: "production"},
      {key: "Application",  value: "multi-tier-app"},
      {key: "Team",         value: "platform"},
      {key: "CostCenter",   value: "CC-1015"}
    ],
    containerDefinitions: [
      {
        name: "app",
        image: "public.ecr.aws/nginx/nginx:stable",
        essential: true,
        cpu: 0,
        portMappings: [{
          name: "app-80-tcp",
          containerPort: 80,
          hostPort: 80,
          protocol: "tcp",
          appProtocol: "http"
        }],
        environment: [],
        mountPoints: [],
        volumesFrom: [],
        logConfiguration: {
          logDriver: "awslogs",
          options: {
            "awslogs-create-group": "true",
            "awslogs-group": "/ecs/test-td-audit",
            "awslogs-region": $region,
            "awslogs-stream-prefix": "ecs"
          }
        }
      },
      {
        name: "log-router",
        image: "public.ecr.aws/aws-observability/aws-for-fluent-bit:stable",
        essential: false,
        cpu: 0,
        environment: [],
        mountPoints: [],
        volumesFrom: [],
        logConfiguration: {
          logDriver: "awslogs",
          options: {
            "awslogs-create-group": "true",
            "awslogs-group": "/ecs/test-td-audit",
            "awslogs-region": $region,
            "awslogs-stream-prefix": "ecs-log-router"
          }
        }
      }
    ]
  }'
)"

# ── Patched task definitions ───────────────────────────────────────────────────
# 1. nginx + Falcon init container
register "test-patched-nginx" "$(jq -n \
  --arg role "$ROLE_ARN" \
  --arg region "$REGION" \
  --arg falconImage "$FALCON_IMAGE" \
  --arg falconCid "$FALCON_CID" \
  '{
    family: "test-patched-nginx",
    
    networkMode: "awsvpc",
    requiresCompatibilities: ["FARGATE"],
    cpu: "512",
    memory: "1024",
    executionRoleArn: $role,
    taskRoleArn: $role,
    runtimePlatform: {
      cpuArchitecture: "X86_64",
      operatingSystemFamily: "LINUX"
    },
    tags: [
      {key: "Environment",     value: "production"},
      {key: "Application",     value: "web-frontend"},
      {key: "Team",            value: "platform"},
      {key: "CostCenter",      value: "CC-1016"},
      {key: "FalconProtected", value: "true"}
    ],
    volumes: [{
      name: "crowdstrike-falcon-volume"
    }],
    containerDefinitions: [
      {
        name: "nginx",
        image: "public.ecr.aws/nginx/nginx:stable",
        essential: true,
        cpu: 0,
        dependsOn: [{
          containerName: "crowdstrike-falcon-init-container",
          condition: "COMPLETE"
        }],
        entryPoint: [
          "/tmp/CrowdStrike/rootfs/lib64/ld-linux-x86-64.so.2",
          "--library-path", "/tmp/CrowdStrike/rootfs/lib64",
          "/tmp/CrowdStrike/rootfs/bin/bash",
          "/tmp/CrowdStrike/rootfs/entrypoint-ecs.sh",
          "/docker-entrypoint.sh"
        ],
        command: ["nginx", "-g", "daemon off;"],
        environment: [{
          name: "FALCONCTL_OPTS",
          value: ("--cid=" + $falconCid)
        }],
        linuxParameters: {
          capabilities: {
            add: ["SYS_PTRACE"]
          }
        },
        portMappings: [{
          name: "nginx-80-tcp",
          containerPort: 80,
          hostPort: 80,
          protocol: "tcp",
          appProtocol: "http"
        }],
        mountPoints: [{
          sourceVolume: "crowdstrike-falcon-volume",
          containerPath: "/tmp/CrowdStrike",
          readOnly: true
        }],
        volumesFrom: [],
        logConfiguration: {
          logDriver: "awslogs",
          options: {
            "awslogs-create-group": "true",
            "awslogs-group": "/ecs/test-td-audit",
            "awslogs-region": $region,
            "awslogs-stream-prefix": "ecs"
          }
        }
      },
      {
        name: "crowdstrike-falcon-init-container",
        image: $falconImage,
        essential: false,
        cpu: 0,
        user: "0:0",
        readonlyRootFilesystem: true,
        entryPoint: [
          "/bin/bash", "-c",
          "chmod u+rwx /tmp/CrowdStrike && mkdir /tmp/CrowdStrike/rootfs && cp -r /bin /etc /lib64 /usr /entrypoint-ecs.sh /tmp/CrowdStrike/rootfs && chmod -R a=rX /tmp/CrowdStrike"
        ],
        environment: [],
        mountPoints: [{
          sourceVolume: "crowdstrike-falcon-volume",
          containerPath: "/tmp/CrowdStrike",
          readOnly: false
        }],
        volumesFrom: [],
        logConfiguration: {
          logDriver: "awslogs",
          options: {
            "awslogs-create-group": "true",
            "awslogs-group": "/ecs/test-td-audit",
            "awslogs-region": $region,
            "awslogs-stream-prefix": "ecs"
          }
        }
      }
    ]
  }'
)"

# 2. Python API + Falcon init container
register "test-patched-python-api" "$(jq -n \
  --arg role "$ROLE_ARN" \
  --arg region "$REGION" \
  --arg falconImage "$FALCON_IMAGE" \
  --arg falconCid "$FALCON_CID" \
  '{
    family: "test-patched-python-api",
    
    networkMode: "awsvpc",
    requiresCompatibilities: ["FARGATE"],
    cpu: "512",
    memory: "1024",
    executionRoleArn: $role,
    taskRoleArn: $role,
    runtimePlatform: {
      cpuArchitecture: "X86_64",
      operatingSystemFamily: "LINUX"
    },
    tags: [
      {key: "Environment",     value: "staging"},
      {key: "Application",     value: "python-api"},
      {key: "Team",            value: "backend"},
      {key: "CostCenter",      value: "CC-1017"},
      {key: "FalconProtected", value: "true"}
    ],
    volumes: [{
      name: "crowdstrike-falcon-volume"
    }],
    containerDefinitions: [
      {
        name: "python-api",
        image: "public.ecr.aws/docker/library/python:3.12-slim",
        essential: true,
        cpu: 0,
        dependsOn: [{
          containerName: "crowdstrike-falcon-init-container",
          condition: "COMPLETE"
        }],
        entryPoint: [
          "/tmp/CrowdStrike/rootfs/lib64/ld-linux-x86-64.so.2",
          "--library-path", "/tmp/CrowdStrike/rootfs/lib64",
          "/tmp/CrowdStrike/rootfs/bin/bash",
          "/tmp/CrowdStrike/rootfs/entrypoint-ecs.sh",
          "python3"
        ],
        command: ["-m", "http.server", "5000"],
        environment: [
          { name: "APP_ENV",       value: "test" },
          { name: "FALCONCTL_OPTS", value: ("--cid=" + $falconCid) }
        ],
        linuxParameters: {
          capabilities: {
            add: ["SYS_PTRACE"]
          }
        },
        portMappings: [{
          name: "python-api-5000-tcp",
          containerPort: 5000,
          hostPort: 5000,
          protocol: "tcp",
          appProtocol: "http"
        }],
        mountPoints: [{
          sourceVolume: "crowdstrike-falcon-volume",
          containerPath: "/tmp/CrowdStrike",
          readOnly: true
        }],
        volumesFrom: [],
        logConfiguration: {
          logDriver: "awslogs",
          options: {
            "awslogs-create-group": "true",
            "awslogs-group": "/ecs/test-td-audit",
            "awslogs-region": $region,
            "awslogs-stream-prefix": "ecs"
          }
        }
      },
      {
        name: "crowdstrike-falcon-init-container",
        image: $falconImage,
        essential: false,
        cpu: 0,
        user: "0:0",
        readonlyRootFilesystem: true,
        entryPoint: [
          "/bin/bash", "-c",
          "chmod u+rwx /tmp/CrowdStrike && mkdir /tmp/CrowdStrike/rootfs && cp -r /bin /etc /lib64 /usr /entrypoint-ecs.sh /tmp/CrowdStrike/rootfs && chmod -R a=rX /tmp/CrowdStrike"
        ],
        environment: [],
        mountPoints: [{
          sourceVolume: "crowdstrike-falcon-volume",
          containerPath: "/tmp/CrowdStrike",
          readOnly: false
        }],
        volumesFrom: [],
        logConfiguration: {
          logDriver: "awslogs",
          options: {
            "awslogs-create-group": "true",
            "awslogs-group": "/ecs/test-td-audit",
            "awslogs-region": $region,
            "awslogs-stream-prefix": "ecs"
          }
        }
      }
    ]
  }'
)"

# ── Summary ────────────────────────────────────────────────────────────────────
echo ""
echo "══════════════════════════════════════════════════"
if [[ "$DRY_RUN" == "true" ]]; then
  echo "  Dry run complete — no task definitions registered"
else
  echo "  Done. Registered 8 task definitions:"
  echo "    Unpatched: test-unpatched-nginx"
  echo "               test-unpatched-httpd"
  echo "               test-unpatched-node-app"
  echo "               test-unpatched-python-api"
  echo "               test-unpatched-multi-container"
  echo "               test-unpatched-redis"
  echo "    Patched:   test-patched-nginx"
  echo "               test-patched-python-api"
  echo ""
  echo "  All log output → CloudWatch log group: /ecs/test-td-audit"
  echo ""
  echo "  To deregister all test TDs when done:"
  echo "    for family in test-unpatched-nginx test-unpatched-httpd \\"
  echo "        test-unpatched-node-app test-unpatched-python-api \\"
  echo "        test-unpatched-multi-container test-unpatched-redis \\"
  echo "        test-patched-nginx test-patched-python-api; do"
  echo "      aws ecs list-task-definitions --family-prefix \"\$family\" \\"
  echo "        --query 'taskDefinitionArns[]' --output text \\"
  echo "        | tr '\\t' '\\n' \\"
  echo "        | xargs -I{} aws ecs deregister-task-definition --task-definition {}"
  echo "    done"
fi
echo "══════════════════════════════════════════════════"
