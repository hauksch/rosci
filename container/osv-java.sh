#!/bin/bash
# OSV scan of the Java dependency tree — the CVE counterpart to
# `make verify-deps`, which proves the cache is byte-exact but says nothing
# about whether those exact bytes are vulnerable.
#
# Coordinates come from DEPENDENCY_MANIFEST.sha256's jar paths
# (groupId/dir/artifactId/version/file), so the scan sees exactly the pinned
# versions the BOM resolved to — including BouncyCastle, which a pom text scan
# would miss (its version is BOM-managed, not written in the pom).
# Query: https://api.osv.dev/v1/querybatch (same database cargo-deny-style
# tooling uses). Any hit fails the gate — the manifest pins integrity; this
# pins "and nobody has published an advisory against it".
set -euo pipefail

MANIFEST="java/osci-bridge/DEPENDENCY_MANIFEST.sha256"
test -f "$MANIFEST" || { echo "osv-java: $MANIFEST not found (run make build first)"; exit 2; }

# groupId:artifactId version — main jars only (no sources/javadoc), deduped.
mapfile -t coords < <(awk '
    {
        n = split($2, p, "/");
        if (p[n] !~ /\.jar$/) next;
        if (p[n] ~ /-(sources|javadoc|tests|test-fixtures)\.jar$/) next;
        version = p[n-1]; artifact = p[n-2];
        group = p[1];
        for (i = 2; i <= n-3; i++) group = group "." p[i];
        print group ":" artifact " " version;
    }' "$MANIFEST" | sort -u)

if [ "${#coords[@]}" -eq 0 ]; then
    echo "osv-java: no jar coordinates found in manifest — nothing to scan"; exit 2
fi

queries=""
for c in "${coords[@]}"; do
    ga=${c% *}; ver=${c#* }
    queries="${queries}{\"package\":{\"name\":\"$ga\",\"ecosystem\":\"Maven\"},\"version\":\"$ver\"},"
done

echo "osv-java: scanning ${#coords[@]} Maven artifacts against OSV ..."
response=$(curl -fsSL -H 'Content-Type: application/json' \
    -d "{\"queries\":[$(printf '%s' "$queries" | sed 's/,$//')]}" \
    https://api.osv.dev/v1/querybatch)

# One results entry per query; each entry carries its vulns' "id" fields.
vulns=$(printf '%s' "$response" | grep -o '"id":"[^"]*"' | sort -u || true)
if [ -z "$vulns" ]; then
    echo "osv-java: clean — no known vulnerabilities in ${#coords[@]} artifacts."
    exit 0
fi

# Allowlist of exact artifact@version pins accepted DESPITE a published
# advisory. It is currently EMPTY because the tree is clean: every plugin is
# pinned at its newest stable release (see the pom comments) and the two
# stubborn plexus-utils carriers (shade/resources/jacoco) are pinned past the
# advisory via plugin-level dependency overrides. Do not add entries casually:
# each one needs the two justifications below, and it stops matching the
# moment the version pin moves.
#   * the artifact is build-time only — the shaded jar ships exactly four
#     third-party trees (de.osci osci-bibliothek, BouncyCastle, Gson, slf4j);
#   * its bytes are pinned by DEPENDENCY_MANIFEST.sha256, so the advisory
#     describes precisely the code that runs here — no supply surprises.
allowlist="
"

echo "osv-java: advisory hits in the Java tree — attributing per artifact:" >&2
# The batch response is index-parallel but we don't parse JSON positionally;
# re-query each artifact individually (rare path) to name the culprit.
unresolved=""
allowlisted_count=0
for c in "${coords[@]}"; do
    ga=${c% *}; ver=${c#* }
    single=$(curl -fsSL -H 'Content-Type: application/json' \
        -d "{\"package\":{\"name\":\"$ga\",\"ecosystem\":\"Maven\"},\"version\":\"$ver\"}" \
        https://api.osv.dev/v1/query || true)
    ids=$(printf '%s' "$single" | grep -o '"id":"[^"]*"' | sort -u || true)
    if [ -z "$ids" ]; then continue; fi
    if printf '%s\n' "$allowlist" | grep -qx "$ga@$ver"; then
        printf '  allowlisted  %-45s %s: %s\n' "$ga" "$ver" "$(printf '%s ' $ids)" >&2
        allowlisted_count=$((allowlisted_count + 1))
    else
        printf '  FLAGGED      %-45s %s: %s\n' "$ga" "$ver" "$(printf '%s ' $ids)" >&2
        unresolved="$unresolved $ga@$ver"
    fi
done

if [ -n "$unresolved" ]; then
    echo "osv-java: non-allowlisted vulnerabilities:$(printf ' %s' $unresolved)" >&2
    echo "osv-java: investigate at https://osv.dev, then bump the pin and re-run make manifest" >&2
    exit 1
fi
echo "osv-java: ${#coords[@]} artifacts OK ($allowlisted_count allowlisted build-time-only pins, see comments above)."
