#!/bin/bash
set -e

# ===========================================
# Run 4 paper-victim benchmark combinations sequentially
# Target: paper-victim (10-family objective setup)
# ===========================================

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

VICTIM="paper-victim"

echo "=========================================="
echo "Experiment Suite - 4 combinations"
echo "Victim: $VICTIM"
echo "=========================================="
echo ""

# 1. Guided + Structured
echo "[1/4] Guided + Structured (JSONL)"
echo "=========================================="
./run.sh --prompt prompts/guided.txt --all --mode struct \
    --output-format output_formats/guided_structured.txt \
    --victim "$VICTIM" "$@"
echo ""
echo "[1/4] Done."
echo ""

# 2. Guided + Unstructured
echo "[2/4] Guided + Unstructured (Markdown)"
echo "=========================================="
./run.sh --prompt prompts/guided.txt --all --mode report \
    --output-format output_formats/guided_unstructured.txt \
    --victim "$VICTIM" "$@"
echo ""
echo "[2/4] Done."
echo ""

# 3. Unguided + Structured
echo "[3/4] Unguided + Structured (JSONL)"
echo "=========================================="
./run.sh --prompt prompts/unguided.txt --all --mode struct \
    --output-format output_formats/unguided_structured.txt \
    --victim "$VICTIM" "$@"
echo ""
echo "[3/4] Done."
echo ""

# 4. Unguided + Unstructured
echo "[4/4] Unguided + Unstructured (Markdown)"
echo "=========================================="
./run.sh --prompt prompts/unguided.txt --all --mode report \
    --output-format output_formats/unguided_unstructured.txt \
    --victim "$VICTIM" "$@"
echo ""
echo "[4/4] Done."
echo ""

echo "=========================================="
echo "All 4 experiments completed!"
echo "=========================================="
