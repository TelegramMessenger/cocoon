#!/bin/bash
set -e

cd "$(dirname "$0")"

# Show help
show_help() {
    cat << EOF
Usage: ./run-benchmark.sh [OPTIONS] [URL]

Examples:
  ./run-benchmark.sh                    # Test client at :10000 (starts own server)
  ./run-benchmark.sh --direct           # Test backend at :8000 (starts own server)
  ./run-benchmark.sh -c 50 -n 10000     # Custom load
  ./run-benchmark.sh --no-server        # Don't start server (assume already running)

Options:
  --direct       Test backend directly (port 8000)
  --no-server    Don't start server (assume already running)
  -c N           Concurrent connections (default: 30)
  -n N           Number of requests (default: 100000)
  -h, --help     Show this help
EOF
    exit 0
}

# Check for help flag
if [ "$1" = "-h" ] || [ "$1" = "--help" ]; then
    show_help
fi

# Find or install hey
HEY_CMD=""
if command -v hey &> /dev/null; then
    HEY_CMD="hey"
elif [ -f "$HOME/go/bin/hey" ]; then
    HEY_CMD="$HOME/go/bin/hey"
elif command -v go &> /dev/null; then
    echo "Installing hey..."
    go install github.com/rakyll/hey@latest
    HEY_CMD="$HOME/go/bin/hey"
else
    echo "Go not found. Downloading hey binary..."
    HEY_DIR="$(cd "$(dirname "$0")" && pwd)"
    HEY_BIN="$HEY_DIR/hey"
    if [ ! -f "$HEY_BIN" ]; then
        curl -sSL -o "$HEY_BIN" "https://storage.googleapis.com/hey-releases/hey_linux_amd64"
        chmod +x "$HEY_BIN"
    fi
    HEY_CMD="$HEY_BIN"
fi

# Parse arguments
TARGET="http://localhost:10000"
REQUESTS=100000
CONNECTIONS=30
START_SERVER=true

while [[ $# -gt 0 ]]; do
    case $1 in
        --direct)
            TARGET="http://localhost:8000"
            echo "Testing directly against backend server"
            shift
            ;;
        --no-server)
            START_SERVER=false
            shift
            ;;
        -n)
            REQUESTS="$2"
            shift 2
            ;;
        -c)
            CONNECTIONS="$2"
            shift 2
            ;;
        *)
            TARGET="$1"
            shift
            ;;
    esac
done

# Start server if needed
if [ "$START_SERVER" = true ]; then
    ./start-server.sh &
    SERVER_PID=$!
    
    # Kill server on exit (harmless if start-server.sh exited early)
    trap "kill $SERVER_PID 2>/dev/null || true" EXIT
    
    # Wait for server to be ready
    sleep 3
fi

# Request body
BODY='{"stream":true,"model":"Qwen/Qwen3-8B","messages":[{"role":"user","content":"hello"},{"role":"assistant","content":"\nHello! How can I assist you today? 😊"},{"role":"user","content":"what is your name"}],"max_tokens":8000}'

echo "Benchmarking $TARGET/v1/chat/completions"
echo "$CONNECTIONS connections, $REQUESTS requests"
echo ""

$HEY_CMD -n $REQUESTS -c $CONNECTIONS -m POST -disable-keepalive \
    -H "Content-Type: application/json" \
    -d "$BODY" \
    "$TARGET/v1/chat/completions"

echo ""
if [ -n "$SERVER_PID" ]; then
    echo "Stopping server..."
fi
