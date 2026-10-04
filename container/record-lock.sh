#!/usr/bin/env bash
# Prints the exact versions + image digests of everything we build with.
# Output gets pasted into container/LOCK.md and committed, because
# "reproducible" should mean something you can check, not something you hope for.
set -euo pipefail

# OCI may be multi-word ("podman --remote" under NoNewPrivileges trees) —
# word-split it into an argv on purpose.
read -r -a OCI_CMD <<< "${OCI:-$(command -v docker || command -v podman)}"
IMAGE="${1:?usage: record-lock.sh <image-ref>}"

echo "recorded:   $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "base image: eclipse-temurin:21-jdk-jammy"
echo "rust:       $("${OCI_CMD[@]}" run --rm "$IMAGE" rustc --version | awk '{print $2}') (rustup-pinned)"
echo "maven:      $("${OCI_CMD[@]}" run --rm "$IMAGE" mvn --version | head -1 | awk '{print $3}')"
echo "java:       $("${OCI_CMD[@]}" run --rm "$IMAGE" java -version 2>&1 | head -1)"
echo "builder digest:"
"${OCI_CMD[@]}" image inspect "$IMAGE" --format '  {{index .RepoDigests 0}}' 2>/dev/null || \
  echo "  (locally built image — no repo digest; base pinned by tag + build args)"
