#!/bin/bash

# Script to format code with clang-format using Linux kernel style
# Recursively formats all files in the project, excluding specified files

# Exit on any error
set -e

# List of files to exclude from formatting (add your files here)
EXCLUDED_FILES=(
    # Add files to exclude from formatting here
)

# Project root directory (script assumes it is run from project root)
PROJECT_ROOT="$(pwd)"

# Check if clang-format is installed
if ! command -v clang-format &> /dev/null; then
    echo "Error: clang-format is not installed or not in PATH"
    echo "Please install clang-format first"
    exit 1
fi

# Function to check if a file should be excluded
is_excluded() {
    local file="$1"
    for excluded in "${EXCLUDED_FILES[@]}"; do
        if [[ "$file" == *"$excluded"* ]]; then
            return 0 # True, file should be excluded
        fi
    done
    return 1 # False, file should be formatted
}

echo "Starting to format files according to Linux kernel style..."
echo "Using clang-format version: $(clang-format --version)"

# Find and format all relevant files recursively
formatted_count=0
excluded_count=0

while IFS= read -r file; do
    # Check if file should be excluded
    if is_excluded "$file"; then
        echo "Skipping excluded file: $file"
        ((excluded_count++))
        continue
    fi
    
    echo "Formatting: $file"
    clang-format -i -style=file "$file"
    ((formatted_count++))
done < <(find "$PROJECT_ROOT" -type f \( -name "*.c" -o -name "*.h" -o -name "*.cpp" -o -name "*.hpp" \))

echo "Formatting complete!"
echo "Files formatted: $formatted_count"
echo "Files excluded: $excluded_count"
