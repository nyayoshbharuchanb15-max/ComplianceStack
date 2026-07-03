#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════
#  E2E Pipeline Test Runner
# ═══════════════════════════════════════════════════════════════════
#
#  Builds and boots the full Docker Compose test profile,
#  waits for all services to be healthy, runs the full
#  17-phase pipeline integration test suite, then tears
#  everything down.
#
#  Usage:
#    ./scripts/run-e2e.sh          # full lifecycle
#    ./scripts/run-e2e.sh --keep   # keep stack running after tests
#    ./scripts/run-e2e.sh --debug  # verbose docker compose logs
#
# ═══════════════════════════════════════════════════════════════════

set -euo pipefail

COMPOSE_FILE="docker-compose.test.yml"
BACKEND_PORT=18000
MCP_PORT=3002
KEEP_STACK=false
DEBUG=false

# ─── Parse Arguments ──────────────────────────────────────────────
for arg in "$@"; do
  case $arg in
    --keep)  KEEP_STACK=true ;;
    --debug) DEBUG=true ;;
    *)       echo "Unknown arg: $arg"; exit 1 ;;
  esac
done

# ─── Cleanup Function ─────────────────────────────────────────────
cleanup() {
  echo ""
  echo "═══════════════════════════════════════════════════════════"
  echo "  Tearing down test infrastructure"
  echo "═══════════════════════════════════════════════════════════"
  docker compose -f "$COMPOSE_FILE" down -v --remove-orphans 2>/dev/null || true
}

if [ "$KEEP_STACK" = false ]; then
  trap cleanup EXIT
fi

# ─── Step 1: Build and Start ─────────────────────────────────────
echo ""
echo "═══════════════════════════════════════════════════════════"
echo "  E2E Pipeline Integration Test Runner"
echo "═══════════════════════════════════════════════════════════"
echo ""
echo "  Building and starting test services..."
docker compose -f "$COMPOSE_FILE" up -d --build --force-recreate

# ─── Step 2: Wait for Backend Health ─────────────────────────────
echo ""
echo "  Waiting for backend to become healthy..."
RETRIES=0
MAX_RETRIES=60
until curl -sf "http://localhost:${BACKEND_PORT}/health" > /dev/null 2>&1; do
  RETRIES=$((RETRIES + 1))
  if [ $RETRIES -ge $MAX_RETRIES ]; then
    echo "  ✗ Backend failed to start within ${MAX_RETRIES}s"
    echo ""
    docker compose -f "$COMPOSE_FILE" logs python-backend 2>/dev/null | tail -50
    exit 1
  fi
  sleep 2
done
echo "  ✓ Backend healthy on port ${BACKEND_PORT}"

# ─── Step 3: Wait for MCP Server ────────────────────────────────
echo "  Waiting for MCP server..."
RETRIES=0
until curl -sf "http://localhost:${MCP_PORT}/health" > /dev/null 2>&1; do
  RETRIES=$((RETRIES + 1))
  if [ $RETRIES -ge $MAX_RETRIES ]; then
    echo "  ✗ MCP server failed to start within ${MAX_RETRIES}s"
    docker compose -f "$COMPOSE_FILE" logs mcp-server 2>/dev/null | tail -50
    exit 1
  fi
  sleep 2
done
echo "  ✓ MCP server healthy on port ${MCP_PORT}"

# ─── Step 4: Display Service Status ─────────────────────────────
echo ""
echo "  Service endpoints:"
echo "    Backend:  http://localhost:${BACKEND_PORT}"
echo "    MCP:      http://localhost:${MCP_PORT}"
echo "    Postgres: localhost:15432"
echo "    Neo4j:    localhost:17687"
echo "    Redis:    localhost:16379"
echo ""

# ─── Step 5: Run Tests ───────────────────────────────────────────
echo "═══════════════════════════════════════════════════════════"
echo "  Running 17-Phase Pipeline Integration Tests"
echo "═══════════════════════════════════════════════════════════"
echo ""

BACKEND_URL="http://localhost:${BACKEND_PORT}" \
MCP_URL="http://localhost:${MCP_PORT}" \
  python -m pytest tests/e2e/ \
    -v \
    --tb=short \
    --timeout=60 \
    -x \
    2>&1

TEST_EXIT=$?

# ─── Step 6: Report ──────────────────────────────────────────────
echo ""
if [ $TEST_EXIT -eq 0 ]; then
  echo "═══════════════════════════════════════════════════════════"
  echo "  ✓ All E2E pipeline tests PASSED"
  echo "═══════════════════════════════════════════════════════════"
else
  echo "═══════════════════════════════════════════════════════════"
  echo "  ✗ Some E2E pipeline tests FAILED"
  echo "═══════════════════════════════════════════════════════════"
  if [ "$DEBUG" = true ]; then
    echo ""
    echo "  Backend logs:"
    docker compose -f "$COMPOSE_FILE" logs python-backend 2>/dev/null | tail -100
    echo ""
    echo "  MCP logs:"
    docker compose -f "$COMPOSE_FILE" logs mcp-server 2>/dev/null | tail -50
  fi
fi

if [ "$KEEP_STACK" = true ]; then
  echo ""
  echo "  Stack left running (use --keep to retain)."
  echo "  To shut down: docker compose -f $COMPOSE_FILE down -v"
fi

exit $TEST_EXIT
