#!/usr/bin/env bash
#
# Clawprint Demo — full walkthrough
#
# This script builds Clawprint, generates a synthetic recording,
# and walks through every CLI command so you can see the tool in action.
#
# Usage:
#   chmod +x demo.sh
#   ./demo.sh
#
# No live OpenClaw gateway required.

set -euo pipefail

CYAN='\033[0;36m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
DIM='\033[2m'
BOLD='\033[1m'
NC='\033[0m'

step() {
    echo ""
    echo -e "${CYAN}${BOLD}━━━ $1 ━━━${NC}"
    echo ""
}

run() {
    echo -e "${DIM}\$ $*${NC}"
    "$@"
    echo ""
}

# ─────────────────────────────────────────────────────────────
step "1/7  Building Clawprint"
run cargo build --release

CLAWPRINT="./target/release/clawprint"

# ─────────────────────────────────────────────────────────────
step "2/7  Generating demo recording"
run cargo run --release --example demo

# Grab the run ID from the output directory
RUN_ID=$(ls -t ./clawprints/runs/ | head -1)
SHORT_ID="${RUN_ID:0:8}"

echo -e "  ${GREEN}Run ID:${NC} ${RUN_ID}"
echo -e "  ${GREEN}Short:${NC}  ${SHORT_ID}"
echo ""

# ─────────────────────────────────────────────────────────────
step "3/7  Listing all recorded runs"
run "$CLAWPRINT" list --out ./clawprints

# ─────────────────────────────────────────────────────────────
step "4/7  Verifying hash chain integrity"
run "$CLAWPRINT" verify --run "$RUN_ID" --out ./clawprints

# ─────────────────────────────────────────────────────────────
step "5/7  Showing run statistics"
run "$CLAWPRINT" stats --run "$RUN_ID" --out ./clawprints

# ─────────────────────────────────────────────────────────────
step "6/7  Replaying run offline"
run "$CLAWPRINT" replay --run "$RUN_ID" --out ./clawprints --offline

# ─────────────────────────────────────────────────────────────
step "7/7  Launching web dashboard"

echo -e "${YELLOW}Starting viewer on http://127.0.0.1:8080${NC}"
echo -e "${DIM}Press Ctrl+C to stop${NC}"
echo ""
echo -e "${DIM}\$ clawprint view --run $RUN_ID --out ./clawprints --open${NC}"

"$CLAWPRINT" view --run "$RUN_ID" --out ./clawprints --open
