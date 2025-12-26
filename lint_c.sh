#!/bin/bash

echo "=== C Code Linter Analysis ==="
echo ""

FILE="command_monitor.c"

echo "1. Checking for undefined variables..."
grep -n "g_[a-z_]*" "$FILE" | grep -v "^[0-9]*:static" | grep -v "^[0-9]*://" | head -20

echo ""
echo "2. Checking for unused includes..."
grep -n "^#include" "$FILE"

echo ""
echo "3. Checking for potential memory leaks..."
echo "Allocations:"
grep -n "malloc\|realloc\|calloc" "$FILE" || echo "None found"
echo "Deallocations:"
grep -n "free(" "$FILE" || echo "None found"

echo ""
echo "4. Checking for buffer overflow risks..."
grep -n "strcpy\|strcat\|sprintf" "$FILE" || echo "None found (good - using safe functions)"

echo ""
echo "5. Checking for uninitialized variable usage..."
grep -n "g_[a-z_]*\[" "$FILE" | head -10

echo ""
echo "6. Checking for missing null checks before dereference..."
grep -n "g_[a-z_]*->" "$FILE" | head -10

echo ""
echo "7. Checking for magic numbers..."
grep -n "[^a-zA-Z_][0-9]\{2,\}[^a-zA-Z0-9_]" "$FILE" | grep -v "MAX_\|COMMAND_\|DEFAULT_\|REGISTRY_\|USER_\|CMD_\|HTTP_\|CSIDL_\|KEY_\|REG_\|ERROR_\|WAIT_\|CURL_\|SHGFP_\|CREATE_\|EXIT_\|S_OK\|CURLE_\|RESULT_" | head -10

echo ""
echo "=== Linter Analysis Complete ==="
