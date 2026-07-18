#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-only
set -euo pipefail

# Keep host configuration from changing deterministic fixture behavior.
unset MAILACL_GPG_KEY MAILACL_DOMAIN MAILACL_SIGNATURE_ENCODING MAILACL_COLOR NO_COLOR
unset FAKE_GPG_MODE BLOCK_OPENSSL

ROOT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
MAILACL="$ROOT_DIR/mailacl.sh"
TEST_TMP=$(mktemp -d)
trap 'rm -rf "$TEST_TMP"' EXIT
FAKE_BIN="$TEST_TMP/bin"
TEST_HOME="$TEST_TMP/home"
TEST_GNUPGHOME="$TEST_TMP/gnupg"
mkdir -p "$FAKE_BIN" "$TEST_HOME" "$TEST_GNUPGHOME"
chmod 700 "$TEST_HOME" "$TEST_GNUPGHOME"
cat >"$FAKE_BIN/gpg" <<'EOF'
#!/usr/bin/env bash
set -u
mode=${FAKE_GPG_MODE:-normal}
[[ "${*: -1}" == "fixture-key" ]] || {
    printf 'unexpected fake-gpg key: %s\n' "${*: -1}" >&2
    exit 2
}
case "${1:-}" in
    --list-secret-keys)
        [[ "$mode" != "list-fail" ]] || exit 1
        exit 0
        ;;
    --export-secret-keys)
        case "$mode" in
            export-fail) exit 1 ;;
            export-empty) exit 0 ;;
            *) printf 'MailACL deterministic public test fixture\n' ;;
        esac
        exit 0
        ;;
    *)
        printf 'unexpected fake-gpg arguments: %s\n' "$*" >&2
        exit 2
        ;;
esac
EOF
cat >"$FAKE_BIN/openssl" <<'EOF'
#!/usr/bin/env bash
if [[ "${BLOCK_OPENSSL:-0}" == "1" ]]; then
    printf 'openssl was unexpectedly invoked\n' >&2
    exit 99
fi
exec /usr/bin/openssl "$@"
EOF
chmod 700 "$FAKE_BIN/gpg" "$FAKE_BIN/openssl"

run_mailacl() {
    env \
        PATH="$FAKE_BIN:/usr/bin:/bin" \
        HOME="$TEST_HOME" \
        GNUPGHOME="$TEST_GNUPGHOME" \
        MAILACL_GPG_KEY="fixture-key" \
        MAILACL_DOMAIN="${MAILACL_DOMAIN:-example.com}" \
        MAILACL_COLOR="${MAILACL_COLOR:-never}" \
        "$MAILACL" "$@"
}

fail() {
    printf 'FAIL: %s\n' "$*" >&2
    exit 1
}

assert_contains() {
    local haystack="$1"
    local needle="$2"
    local context="$3"
    [[ "$haystack" == *"$needle"* ]] || fail "$context (missing: $needle)"
}

assert_not_contains() {
    local haystack="$1"
    local needle="$2"
    local context="$3"
    [[ "$haystack" != *"$needle"* ]] || fail "$context (unexpected: $needle)"
}

capture_mailacl() {
    set +e
    MAILACL_OUTPUT=$(run_mailacl "$@" 2>&1)
    MAILACL_STATUS=$?
    set -e
}

test_help_does_not_require_credentials() {
    local output status
    set +e
    output=$(env -u MAILACL_GPG_KEY -u MAILACL_DOMAIN "$MAILACL" --help 2>&1)
    status=$?
    set -e

    [[ $status -eq 0 ]] || fail "--help exited with status $status"
    assert_contains "$output" "Usage:" "--help did not show usage"
}

test_noninteractive_generation_uses_arguments() {
    local output
    output=$(run_mailacl "service.example" 2>&1)
    assert_contains "$output" "Signature length: 10" "default signature length changed"
    assert_contains "$output" "Generated MailACL email: service.example-taq75f3cvy@example.com" "identifier argument or default output changed"
}

test_positional_identifier_does_not_read_stdin() {
    local output status
    set +e
    output=$(printf 'not-a-signature-length\n' | run_mailacl "service.example" 2>&1)
    status=$?
    set -e
    [[ $status -eq 0 ]] || fail "positional identifier consumed stdin as a signature length"
    assert_contains "$output" "Signature length: 10" "positional identifier did not use the default length"
    assert_contains "$output" "service.example-taq75f3cvy@example.com" "positional generation changed when stdin was present"
}

test_known_generation_vectors() {
    local encoding expected
    while IFS='|' read -r encoding expected; do
        MAILACL_SIGNATURE_ENCODING="$encoding" capture_mailacl "service.example" 16
        [[ $MAILACL_STATUS -eq 0 ]] || fail "$encoding generation exited with $MAILACL_STATUS"
        assert_contains "$MAILACL_OUTPUT" "Generated MailACL email: service.example-${expected}@example.com" "$encoding generation changed"
    done <<'EOF'
base36|8jkc1btaq75f3cvy
base32|jvgdcohwion3v3z6
base64|TUwxOPZDm7rvPmwS
hex|4d4c3138f6439bba
EOF
}

test_compatibility_verification() {
    local address encoding_label
    while IFS='|' read -r address encoding_label; do
        capture_mailacl "$address"
        [[ $MAILACL_STATUS -eq 0 ]] || fail "$encoding_label verification exited with $MAILACL_STATUS"
        assert_contains "$MAILACL_OUTPUT" "Encoding: $encoding_label" "$encoding_label compatibility path was not selected"
        assert_contains "$MAILACL_OUTPUT" "Verification successful" "$encoding_label did not verify"
    done <<'EOF'
service.example-8jkc1btaq75f3cvy@example.com|base36 lowercase suffix
service.example-Q75F3CVY@example.com|base36 lowercase suffix
service.example-0caj14v9wieb07i0@example.com|base36 lowercase prefix (transitional)
service.example-JVGDCOHWION3V3Z6@example.com|base32 lowercase (transitional)
service.example-4D4C3138F6439BBA@example.com|hex (legacy)
service.example-TUwxOPZDm7rvPmwS@example.com|base64 (transitional exact match)
EOF

    capture_mailacl "service.example-tuwxopzdm7rvpmws@example.com"
    [[ $MAILACL_STATUS -ne 0 ]] || fail "case-modified Base64 unexpectedly verified"
}

test_weak_length_warning() {
    capture_mailacl "service.example" 1
    [[ $MAILACL_STATUS -eq 0 ]] || fail "one-character generation exited with $MAILACL_STATUS"
    assert_contains "$MAILACL_OUTPUT" "Entropy: 5.17 bits" "one-character entropy changed"
    assert_contains "$MAILACL_OUTPUT" "Strength: VERY WEAK" "one-character warning missing"
}

test_entropy_reporting_accuracy() {
    capture_mailacl "service.example" 16
    [[ $MAILACL_STATUS -eq 0 ]] || fail "16-character entropy fixture generation failed"
    assert_contains "$MAILACL_OUTPUT" "1.256e-19" "small random-guess probability lost precision"
    assert_not_contains "$MAILACL_OUTPUT" "0.000e+00" "small random-guess probability was rounded to zero"

    capture_mailacl "service.example-0caj14v9wieb07i0@example.com"
    [[ $MAILACL_STATUS -eq 0 ]] || fail "transitional Base36-prefix fixture did not verify"
    assert_contains "$MAILACL_OUTPUT" "not reported for transitional Base36 prefixes" "biased transitional prefix reported uniform entropy"
    assert_contains "$MAILACL_OUTPUT" "Strength: TRANSITIONAL" "transitional prefix strength warning was missing"
}

test_color_controls() {
    local canonical='' line tty_command tty_output

    MAILACL_COLOR=never capture_mailacl "service.example" 10
    [[ $MAILACL_STATUS -eq 0 ]] || fail "MAILACL_COLOR=never failed"
    assert_not_contains "$MAILACL_OUTPUT" $'\033[' "MAILACL_COLOR=never emitted ANSI"

    MAILACL_COLOR=always capture_mailacl "service.example" 10
    [[ $MAILACL_STATUS -eq 0 ]] || fail "MAILACL_COLOR=always failed"
    assert_contains "$MAILACL_OUTPUT" $'\033[1;33m' "number color missing"
    assert_contains "$MAILACL_OUTPUT" $'\033[1;35m' "letter color missing"
    while IFS= read -r line; do
        [[ "$line" == "📧 Generated MailACL email:"* ]] && canonical="$line"
    done <<<"$MAILACL_OUTPUT"
    [[ "$canonical" == "📧 Generated MailACL email: service.example-taq75f3cvy@example.com" ]] || fail "canonical address line changed under color output"
    assert_not_contains "$canonical" $'\033[' "canonical address line contained ANSI escapes"

    MAILACL_COLOR=auto capture_mailacl "service.example" 10
    [[ $MAILACL_STATUS -eq 0 ]] || fail "MAILACL_COLOR=auto failed in non-TTY output"
    assert_not_contains "$MAILACL_OUTPUT" $'\033[' "MAILACL_COLOR=auto colored non-TTY output"

    MAILACL_SIGNATURE_ENCODING=base64 MAILACL_COLOR=always capture_mailacl "color1" 16
    [[ $MAILACL_STATUS -eq 0 ]] || fail "Base64 punctuation color fixture failed"
    assert_contains "$MAILACL_OUTPUT" "color1-/RPI1RX3ahcsBCnm@example.com" "Base64 punctuation fixture changed"
    assert_contains "$MAILACL_OUTPUT" $'\033[1;31m/\033[0m' "Base64 punctuation color missing"

    if command -v script >/dev/null 2>&1; then
        printf -v tty_command '%q %q %q' "$MAILACL" "service.example" "10"
        tty_output=$(env \
            PATH="$FAKE_BIN:/usr/bin:/bin" \
            HOME="$TEST_HOME" \
            GNUPGHOME="$TEST_GNUPGHOME" \
            MAILACL_GPG_KEY="fixture-key" \
            MAILACL_DOMAIN="example.com" \
            MAILACL_COLOR="auto" \
            script -qefc "$tty_command" /dev/null 2>&1)
        assert_contains "$tty_output" $'\033[' "MAILACL_COLOR=auto did not color TTY output"

        tty_output=$(env \
            PATH="$FAKE_BIN:/usr/bin:/bin" \
            HOME="$TEST_HOME" \
            GNUPGHOME="$TEST_GNUPGHOME" \
            MAILACL_GPG_KEY="fixture-key" \
            MAILACL_DOMAIN="example.com" \
            MAILACL_COLOR="auto" \
            NO_COLOR="1" \
            script -qefc "$tty_command" /dev/null 2>&1)
        assert_not_contains "$tty_output" $'\033[' "NO_COLOR did not suppress TTY color"
    fi
}

test_rejects_mismatched_domain() {
    capture_mailacl "service.example-taq75f3cvy@other.example"
    [[ $MAILACL_STATUS -ne 0 ]] || fail "address for a different domain unexpectedly verified"
    assert_contains "$MAILACL_OUTPUT" "does not match MAILACL_DOMAIN" "domain mismatch was not explained"
}

test_rejects_empty_identifier() {
    capture_mailacl "" 10
    [[ $MAILACL_STATUS -ne 0 ]] || fail "empty identifier unexpectedly generated an address"
    assert_contains "$MAILACL_OUTPUT" "Identifier must not be empty" "empty identifier error was not explained"
}

test_rejects_identifier_whitespace() {
    capture_mailacl "service name" 10
    [[ $MAILACL_STATUS -ne 0 ]] || fail "identifier containing whitespace unexpectedly generated an address"
    assert_contains "$MAILACL_OUTPUT" "email-safe" "invalid identifier error was not explained"
}

test_rejects_non_dot_atom_identifier() {
    capture_mailacl "service:name" 10
    [[ $MAILACL_STATUS -ne 0 ]] || fail "identifier containing non-dot-atom punctuation unexpectedly succeeded"
    assert_contains "$MAILACL_OUTPUT" "email-safe" "non-dot-atom identifier error was not explained"
}

test_accepts_zero_padded_decimal_length() {
    capture_mailacl "service.example" 08
    [[ $MAILACL_STATUS -eq 0 ]] || fail "zero-padded decimal length exited with $MAILACL_STATUS"
    assert_contains "$MAILACL_OUTPUT" "Signature length: 8" "zero-padded length was not parsed as decimal"
}

test_rejects_length_argument_in_verification_mode() {
    capture_mailacl "service.example-taq75f3cvy@example.com" 10
    [[ $MAILACL_STATUS -ne 0 ]] || fail "verification unexpectedly accepted a signature-length argument"
    assert_contains "$MAILACL_OUTPUT" "does not accept SIGNATURE_LENGTH" "verification argument error was not explained"
}

test_rejects_invalid_domain_labels() {
    MAILACL_DOMAIN="-bad.example" capture_mailacl "service.example" 10
    [[ $MAILACL_STATUS -ne 0 ]] || fail "domain with a leading label hyphen unexpectedly passed validation"
    assert_contains "$MAILACL_OUTPUT" "appears to be invalid" "invalid domain error was not explained"
}

test_rejects_invalid_color_mode() {
    MAILACL_COLOR="rainbow" capture_mailacl "service.example" 10
    [[ $MAILACL_STATUS -ne 0 ]] || fail "invalid MAILACL_COLOR unexpectedly succeeded"
    assert_contains "$MAILACL_OUTPUT" "Unsupported MAILACL_COLOR" "invalid color-mode error was not explained"
}

test_reports_missing_interactive_input() {
    local output status
    set +e
    output=$(env \
        PATH="$FAKE_BIN:/usr/bin:/bin" \
        HOME="$TEST_HOME" \
        GNUPGHOME="$TEST_GNUPGHOME" \
        MAILACL_GPG_KEY="fixture-key" \
        MAILACL_DOMAIN="example.com" \
        MAILACL_COLOR="never" \
        "$MAILACL" </dev/null 2>&1)
    status=$?
    set -e
    [[ $status -ne 0 ]] || fail "empty interactive input unexpectedly succeeded"
    assert_contains "$output" "No identifier or email was supplied" "missing input error was not explained"
}

test_rejects_blank_interactive_identifier_before_key_access() {
    local output status
    set +e
    output=$(printf '\n' | FAKE_GPG_MODE=list-fail run_mailacl 2>&1)
    status=$?
    set -e

    [[ $status -ne 0 ]] || fail "blank interactive identifier unexpectedly succeeded"
    assert_contains "$output" "Identifier must not be empty" "blank interactive identifier error was not explained"
    assert_not_contains "$output" "invalid or not found" "blank interactive identifier accessed the configured secret key"
    assert_not_contains "$output" "Generated MailACL email:" "blank interactive identifier emitted an address"
}

test_rejects_failed_or_empty_secret_export() {
    local mode
    for mode in export-fail export-empty; do
        FAKE_GPG_MODE="$mode" capture_mailacl "service.example" 10
        [[ $MAILACL_STATUS -ne 0 ]] || fail "$mode unexpectedly generated an address"
        assert_not_contains "$MAILACL_OUTPUT" "Generated MailACL email:" "$mode emitted an address"
        assert_contains "$MAILACL_OUTPUT" "Unable to export secret key" "$mode error was not explained"
    done
}

test_generation_does_not_require_openssl() {
    BLOCK_OPENSSL=1 capture_mailacl "service.example" 10
    [[ $MAILACL_STATUS -eq 0 ]] || fail "generation still depended on openssl (status $MAILACL_STATUS)"
    assert_contains "$MAILACL_OUTPUT" "service.example-taq75f3cvy@example.com" "Python HMAC output changed"
}

test_rejects_unknown_options() {
    capture_mailacl "--bogus"
    [[ $MAILACL_STATUS -eq 2 ]] || fail "unknown option exited with $MAILACL_STATUS instead of 2"
    assert_contains "$MAILACL_OUTPUT" "Unknown option" "unknown option error was not explained"
    assert_not_contains "$MAILACL_OUTPUT" "Generated MailACL email:" "unknown option was treated as an identifier"
}

test_prompt_and_piped_input_compatibility() {
    local output status
    set +e
    output=$(printf 'service.example\n\n' | run_mailacl 2>&1)
    status=$?
    set -e
    [[ $status -eq 0 ]] || fail "piped interactive generation exited with $status"
    assert_contains "$output" "service.example-taq75f3cvy@example.com" "piped interactive generation changed"
}

test_rejects_unavailable_secret_key() {
    FAKE_GPG_MODE=list-fail capture_mailacl "service.example" 10
    [[ $MAILACL_STATUS -ne 0 ]] || fail "unavailable GPG key unexpectedly succeeded"
    assert_contains "$MAILACL_OUTPUT" "invalid or not found" "unavailable key error was not explained"
    assert_not_contains "$MAILACL_OUTPUT" "Generated MailACL email:" "unavailable key emitted an address"
}

test_hyphenated_identifier_round_trip() {
    capture_mailacl "vendor-with-hyphen" 16
    [[ $MAILACL_STATUS -eq 0 ]] || fail "hyphenated identifier generation failed"
    assert_contains "$MAILACL_OUTPUT" "vendor-with-hyphen-1i5j5l4zzde2u01d@example.com" "hyphenated identifier vector changed"

    capture_mailacl "vendor-with-hyphen-1i5j5l4zzde2u01d@example.com"
    [[ $MAILACL_STATUS -eq 0 ]] || fail "hyphenated identifier verification failed"
    assert_contains "$MAILACL_OUTPUT" "Prefix: vendor-with-hyphen" "verification did not split at the final hyphen"
}

test_local_part_boundaries() {
    local prefix62 prefix63
    printf -v prefix62 '%062d' 0
    printf -v prefix63 '%063d' 0

    capture_mailacl "$prefix62"
    [[ $MAILACL_STATUS -eq 0 ]] || fail "62-character identifier should leave room for one tag character"
    assert_contains "$MAILACL_OUTPUT" "Signature length: 1" "62-character identifier did not clamp to one tag character"

    capture_mailacl "$prefix63"
    [[ $MAILACL_STATUS -ne 0 ]] || fail "63-character identifier unexpectedly exceeded the local-part limit"
    assert_contains "$MAILACL_OUTPUT" "Prefix is too long" "local-part boundary error was not explained"
}

test_verification_local_part_byte_limit() {
    local prefix47 address overlong_prefix='' i
    printf -v prefix47 '%047d' 0

    capture_mailacl "$prefix47" 16
    [[ $MAILACL_STATUS -eq 0 ]] || fail "64-byte boundary fixture generation failed"
    address=${MAILACL_OUTPUT##*Generated MailACL email: }
    capture_mailacl "$address"
    [[ $MAILACL_STATUS -eq 0 ]] || fail "64-byte local part did not verify"

    for (( i=0; i<32; i++ )); do
        overlong_prefix+='é'
    done
    capture_mailacl "${overlong_prefix}-x@example.com"
    [[ $MAILACL_STATUS -ne 0 ]] || fail "overlong UTF-8 local part unexpectedly verified"
    assert_contains "$MAILACL_OUTPUT" "64-byte local-part limit" "verification did not enforce the byte-oriented local-part limit"
}

test_rejects_multiple_at_signs() {
    capture_mailacl "service.example-taq75f3cvy@other@example.com"
    [[ $MAILACL_STATUS -ne 0 ]] || fail "address containing multiple at signs unexpectedly verified"
    assert_contains "$MAILACL_OUTPUT" "exactly one '@'" "multiple-at-sign error was not explained"
}

test_help_does_not_require_credentials
test_noninteractive_generation_uses_arguments
test_positional_identifier_does_not_read_stdin
test_known_generation_vectors
test_compatibility_verification
test_weak_length_warning
test_entropy_reporting_accuracy
test_color_controls
test_rejects_mismatched_domain
test_rejects_empty_identifier
test_rejects_identifier_whitespace
test_rejects_non_dot_atom_identifier
test_accepts_zero_padded_decimal_length
test_rejects_length_argument_in_verification_mode
test_rejects_invalid_domain_labels
test_rejects_invalid_color_mode
test_reports_missing_interactive_input
test_rejects_blank_interactive_identifier_before_key_access
test_rejects_failed_or_empty_secret_export
test_generation_does_not_require_openssl
test_rejects_unknown_options
test_prompt_and_piped_input_compatibility
test_rejects_unavailable_secret_key
test_hyphenated_identifier_round_trip
test_local_part_boundaries
test_verification_local_part_byte_limit
test_rejects_multiple_at_signs
printf 'PASS: help does not require credentials\n'
printf 'PASS: noninteractive generation uses arguments\n'
printf 'PASS: positional identifiers do not consume stdin\n'
printf 'PASS: deterministic generation vectors\n'
printf 'PASS: backwards-compatible verification matrix\n'
printf 'PASS: weak-length entropy warning\n'
printf 'PASS: entropy and probability reporting remain numerically sound\n'
printf 'PASS: color controls\n'
printf 'PASS: mismatched domains are rejected\n'
printf 'PASS: empty identifiers are rejected\n'
printf 'PASS: identifier whitespace is rejected\n'
printf 'PASS: non-dot-atom identifiers are rejected\n'
printf 'PASS: zero-padded lengths are decimal\n'
printf 'PASS: verification rejects length arguments\n'
printf 'PASS: invalid domain labels are rejected\n'
printf 'PASS: invalid color modes are rejected\n'
printf 'PASS: missing interactive input is reported\n'
printf 'PASS: blank interactive identifiers are rejected before key access\n'
printf 'PASS: failed or empty secret exports are rejected\n'
printf 'PASS: generation does not expose HMAC keys through openssl argv\n'
printf 'PASS: unknown options are rejected\n'
printf 'PASS: piped interactive input remains compatible\n'
printf 'PASS: unavailable GPG keys are rejected\n'
printf 'PASS: hyphenated identifiers round-trip\n'
printf 'PASS: local-part boundaries are enforced\n'
printf 'PASS: verification enforces the byte-oriented local-part limit\n'
printf 'PASS: multiple at signs are rejected\n'
