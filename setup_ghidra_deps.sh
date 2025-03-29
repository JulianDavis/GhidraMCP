#!/bin/bash
# Script to copy Ghidra dependencies to the lib directory for the GhidraMCP plugin
# Usage: ./setup_ghidra_deps.sh /path/to/ghidra/installation

# Check if Ghidra path is provided
if [ $# -eq 0 ]; then
  echo "Error: Ghidra installation path is required"
  echo "Usage: ./setup_ghidra_deps.sh /path/to/ghidra/installation"
  exit 1
fi

GHIDRA_PATH="$1"

# Check if the path exists
if [ ! -d "$GHIDRA_PATH" ]; then
  echo "Error: The specified Ghidra path does not exist: $GHIDRA_PATH"
  exit 1
fi

# Check if this is a valid Ghidra installation
if [ ! -d "$GHIDRA_PATH/Ghidra" ]; then
  echo "Error: This doesn't appear to be a valid Ghidra installation directory (missing Ghidra subdirectory)"
  exit 1
fi

# Create lib directory if it doesn't exist
mkdir -p lib

# Based on pom.xml, these are the required JARs
REQUIRED_JARS=(
  "Generic.jar"
  "SoftwareModeling.jar"
  "Project.jar"
  "Docking.jar"
  "Decompiler.jar"
  "Utility.jar"
  "Base.jar"
)

echo "Searching for Ghidra JAR files in $GHIDRA_PATH..."

# Find and copy each required JAR
for jar in "${REQUIRED_JARS[@]}"; do
  echo "Looking for $jar..."
  # Use find to locate the JAR (only the first match)
  jar_path=$(find "$GHIDRA_PATH" -name "$jar" -type f | head -n 1)
  
  if [ -n "$jar_path" ]; then
    echo "Found $jar at $jar_path"
    cp "$jar_path" "./lib/$jar"
    echo "Copied to ./lib/$jar"
  else
    echo "Warning: Could not find $jar in the Ghidra installation"
  fi
done

# Check if all required JARs were copied
missing=false
for jar in "${REQUIRED_JARS[@]}"; do
  if [ ! -f "./lib/$jar" ]; then
    echo "Error: $jar was not found and copied to the lib directory"
    missing=true
  fi
done

if [ "$missing" = true ]; then
  echo "Some required JAR files are missing. Maven build may fail."
  exit 1
else
  echo "All required Ghidra JAR dependencies have been copied to the lib directory"
  echo "You can now build the project with: mvn clean package"
fi
