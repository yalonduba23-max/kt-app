#!/bin/sh
# Gradle wrapper stub — GitHub Actions downloads real wrapper via gradle-wrapper.properties
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
exec java -jar "$SCRIPT_DIR/gradle/wrapper/gradle-wrapper.jar" "$@"
