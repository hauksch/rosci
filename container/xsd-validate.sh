#!/usr/bin/env bash
# Validates captured OSCI traffic against the normative schemas in
# schema/ (vendored from osci-bib-java 2.6.1, Korrigenda 1-10 included —
# docs/STANDARD-COMPLIANCE.md §3.4). Usage: xsd-validate.sh <dumpdir>
#
# Dump layout (MockIntermediary): request-N.xml is the raw transport body;
# with transport encryption on, request-N.inner.xml is the DECRYPTED inner
# SOAP envelope — the only schema-meaningful layer (the raw body is mostly
# ciphertext). Requests are rosci-produced and always validated. Responses
# are INTERMEDIARY-produced — validating them measures the intermediary,
# not rosci, and the mock is not schema-hardened (its rich responses use a
# non-numeric ConversationId, omit soap:actor/mustUnderstand and misplace
# IntermediaryCertificates — filed in docs/STANDARD-COMPLIANCE.md §7).
# They are counted, not validated. Each envelope carries exactly one
# Auftrag; the matching soap<Auftrag>.xsd (which redefines the SOAP
# Envelope for that Auftrag) is selected by case-insensitive token scan —
# the same trick the e2e suite uses.
set -u

dir="${1:?usage: xsd-validate.sh <dumpdir>}"
schema_root="$(cd "$(dirname "$0")/../schema" && pwd)"
export XML_CATALOG_FILES="$schema_root/catalog.xml"

declare -A ORDERS=(
  [StoreDelivery]=soapStoreDelivery.xsd
  [FetchDelivery]=soapFetchDelivery.xsd
  [FetchProcessCard]=soapFetchProcessCard.xsd
  [GetMessageId]=soapGetMessageId.xsd
  [InitDialog]=soapInitDialog.xsd
  [ExitDialog]=soapExitDialog.xsd
  [AcceptDelivery]=soapAcceptDelivery.xsd
  [ForwardDelivery]=soapForwardDelivery.xsd
  [MediateDelivery]=soapMediateDelivery.xsd
  [ProcessDelivery]=soapProcessDelivery.xsd
  [PartialStoreDelivery]=soapPartialStoreDelivery.xsd
  [PartialFetchDelivery]=soapPartialFetchDelivery.xsd
)

fail=0
validated=0
skipped=0

# The library packages the transport layer as MIME (headers + boundary-
# delimited parts) even after decryption. Extract the first XML document:
# start at the first line that begins a tag, stop at the next MIME
# boundary — everything after it is payload parts or epilogue.
extract_xml() { # $1 = dump file, $2 = extraction target
  awk '
    !started && ($0 ~ /^<\?xml/ || $0 ~ /^</) { started = 1 }
    started {
      if ($0 ~ /^--/) exit
      print
    }
  ' "$1" > "$2"
}

validate() { # $1 = file (may be MIME-packaged), $2 = schema file name
  local extracted
  extracted="$(mktemp --suffix=.xml)"
  extract_xml "$1" "$extracted"
  if err="$(xmllint --noout --nonet --schema "$schema_root/$2" "$extracted" 2>&1)"; then
    validated=$((validated + 1))
  else
    echo "xsd-validate: FAIL: $1 against $2"
    echo "$err"
    fail=1
  fi
  rm -f "$extracted"
}

select_order() { # $1 = file → echoes soap schema name or empty
  local token
  for token in "${!ORDERS[@]}"; do
    if grep -qi "$token" "$1"; then
      echo "${ORDERS[$token]}"
      return
    fi
  done
}

shopt -s nullglob
for body in "$dir"/request-*.xml; do
  target="$body"
  inner="${body%.xml}.inner.xml"
  [[ -f "$inner" ]] && target="$inner"
  order="$(select_order "$target")"
  if [[ -z "$order" ]]; then
    echo "xsd-validate: SKIP (no known Auftrag): $target"
    skipped=$((skipped + 1))
    continue
  fi
  validate "$target" "$order"

  meta="${body%.xml}.meta"
  response="${body/request-/response-}"
  if [[ -f "$response" ]]; then
    # Intermediary-produced: counted, not validated (see header comment).
    skipped=$((skipped + 1))
  fi
done

echo "xsd-validate: $validated valid, $skipped skipped, fail=$fail"
exit $fail
