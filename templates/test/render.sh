#!/bin/bash

TEMPLATE_PATH="../papers.tmpl"
OUTPUT_DIR="output"

# Create output directory if it doesn't exist
mkdir -p $OUTPUT_DIR

# Loop through each file in the directory
for file in *.txt; do
  FILE_NAME=$(basename "$file" .txt)
  # Get the base name of the file without the extension
  export TITLE=$(echo $FILE_NAME | cut -d '-' -f 2 | tr -d '[:space:]')
  # Read the file content
  export BODY=$(cat "$file")

  export AUTHOR=$(echo $FILE_NAME | cut -d '-' -f 1 | tr -d '[:space:]')

  # Run gomplate with the template and context variables
  gomplate \
    -f "$TEMPLATE_PATH" \
    -o "$OUTPUT_DIR/blabla.html"
done
