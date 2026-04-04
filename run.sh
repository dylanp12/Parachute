#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
AGENTS_DIR="$SCRIPT_DIR/agents"
COMPOSE_BASE="$SCRIPT_DIR/docker-compose.yml"

usage() {
    echo "Usage: ./run.sh <agent-runtime> [docker compose args...]"
    echo ""
    echo "Available agents:"
    for dir in "$AGENTS_DIR"/*/; do
        name=$(basename "$dir")
        echo "  $name"
    done
    echo ""
    echo "Examples:"
    echo "  ./run.sh claude-code              # Start Claude Code + Parachute"
    echo "  ./run.sh openclaw                 # Start OpenClaw + Parachute"
    echo "  ./run.sh nemoclaw                 # Start NemoClaw + Parachute"
    echo "  ./run.sh claude-code --build      # Rebuild and start"
    echo "  ./run.sh claude-code down          # Stop the stack"
    echo "  ./run.sh claude-code logs -f       # Follow logs"
    exit 1
}

if [ $# -lt 1 ]; then
    usage
fi

AGENT="$1"
shift

AGENT_COMPOSE="$AGENTS_DIR/$AGENT/compose.yaml"

if [ ! -f "$AGENT_COMPOSE" ]; then
    echo "Error: Unknown agent '$AGENT'"
    echo ""
    usage
fi

# Default action is 'up -d' if no additional args
if [ $# -eq 0 ]; then
    set -- up -d
fi

exec docker compose -f "$COMPOSE_BASE" -f "$AGENT_COMPOSE" "$@"
