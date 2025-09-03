#!/bin/bash

process_library() {
  local LIB_PATH="$1"
  local FUNCTIONS="$2"
  local JSON_FILE="$3"

  if [ ! -f "$LIB_PATH" ]; then
    echo "Error: Library not found at $LIB_PATH"
    return
  fi

  IFS="," read -ra FUNC_ARRAY <<< "$FUNCTIONS"
  for FUNC_NAME in "${FUNC_ARRAY[@]}"; do
    FUNC_NAME=$(echo "$FUNC_NAME" | xargs)

    GDB_OUTPUT=$(gdb -batch \
      -ex "file $LIB_PATH" \
      -ex "disassemble $FUNC_NAME" 2>/dev/null)

    if ! echo "$GDB_OUTPUT" | grep -q "Dump of assembler code for function $FUNC_NAME"; then
      echo "Error: Function $FUNC_NAME not found in $LIB_PATH"
      continue
    fi

    FUNC_START=$(echo "$GDB_OUTPUT" | grep -m 1 -oP "^\\s*0x[0-9a-f]+")
    FUNC_END=$(echo "$GDB_OUTPUT" | grep -oP "^\\s*0x[0-9a-f]+" | tail -n 1)

    if [ -z "$FUNC_START" ] || [ -z "$FUNC_END" ]; then
      echo "Error: Could not determine start or end address for $FUNC_NAME"
      continue
    fi

    FUNC_START_DEC=$((FUNC_START))
    FUNC_END_DEC=$((FUNC_END))
    END_OFFSET=$((FUNC_END_DEC - FUNC_START_DEC))

    echo "Function: $FUNC_NAME"
    echo "Start Address: $FUNC_START"
    echo "End Address: $FUNC_END"
    echo "End Offset for uretprobe: $END_OFFSET bytes"
  done
}

if [ "$#" -lt 2 ]; then
  echo "Usage: $0 <library_path> <functions_comma_separated>"
  exit 1
fi

LIB_PATH="$1"
FUNCTIONS="$2"

process_library "$LIB_PATH" "$FUNCTIONS" "$JSON_FILE"
