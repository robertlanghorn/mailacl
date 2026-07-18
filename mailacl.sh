#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-only
set -o pipefail

# Set the max local part length according to RFC 5321
MAX_LOCAL_LENGTH=64
MIN_HASH_LENGTH=1              # Minimum allowed signature length; weak sizes are allowed with entropy warnings
DEFAULT_HASH_LENGTH=10         # Short, human-friendly default (~51.7 bits in Base36)
DEFAULT_SIGNATURE_ENCODING="base36"

# MailACL defaults to lowercase Base36: digits 0-9 plus a-z.
#
# Current Base36 signatures are suffix-truncated from a deterministic full-width
# 512-bit HMAC representation. This makes manual shortening easy and preserves
# the best entropy for short tags: if a form rejects a long address, remove
# characters immediately after '<identifier>-' and keep the characters nearest
# '@domain'.
#
# Verification normalizes base36/base32/hex signatures to lowercase before
# comparison, while preserving exact transitional Base64 matching because
# standard Base64 is case-sensitive.
MAILACL_SIGNATURE_ENCODING="${MAILACL_SIGNATURE_ENCODING:-${MAILACL_ENCODING:-$DEFAULT_SIGNATURE_ENCODING}}"
MAILACL_COLOR="${MAILACL_COLOR:-auto}"  # auto, always, or never

print_usage() {
    cat <<'EOF'
Usage:
  mailacl.sh [IDENTIFIER [SIGNATURE_LENGTH]]
  mailacl.sh EMAIL
  mailacl.sh --help

Generate a deterministic MailACL address from IDENTIFIER, or verify EMAIL.
When arguments are omitted, MailACL prompts interactively. SIGNATURE_LENGTH
may be a positive integer or "max".

Required environment variables:
  MAILACL_GPG_KEY             GPG secret-key identifier
  MAILACL_DOMAIN              Domain used for generated and verified addresses

Optional environment variables:
  MAILACL_SIGNATURE_ENCODING  base36 (default), base32, base64, or hex
  MAILACL_COLOR               auto (default), always, or never
  NO_COLOR                    Disable color when MAILACL_COLOR=auto
EOF
}

case "${1:-}" in
    -h|--help)
        print_usage
        exit 0
        ;;
    -*)
        echo "❌ ERROR: Unknown option '$1'." >&2
        print_usage >&2
        exit 2
        ;;
esac

if (( $# > 2 )); then
    echo "❌ ERROR: Too many arguments."
    print_usage >&2
    exit 2
fi

case "$MAILACL_SIGNATURE_ENCODING" in
    base36|base32|base64|hex)
        ;;
    *)
        echo "❌ ERROR: Unsupported MAILACL_SIGNATURE_ENCODING '$MAILACL_SIGNATURE_ENCODING'."
        echo "   Use 'base36' (default/current), 'base32' (transitional), 'hex' (legacy), or 'base64' (transitional)."
        exit 1
        ;;
esac

case "$MAILACL_COLOR" in
    auto|always|never|yes|no|true|false|1|0|"")
        ;;
    *)
        echo "❌ ERROR: Unsupported MAILACL_COLOR '$MAILACL_COLOR'. Use 'auto', 'always', or 'never'."
        exit 1
        ;;
esac

# Ensure MAILACL_GPG_KEY is set
if [[ -z "${MAILACL_GPG_KEY:-}" ]]; then
    echo "❌ ERROR: MAILACL_GPG_KEY environment variable is not set."
    echo "   This variable specifies the GPG secret key used to derive the HMAC key."
    echo ""
    echo "🔧 To set it temporarily, run:"
    echo "   export MAILACL_GPG_KEY=\"YOUR_KEY_ID\""
    echo ""
    echo "🔧 To make it permanent, add the following to your ~/.bashrc or ~/.profile:"
    echo "   echo 'export MAILACL_GPG_KEY=\"YOUR_KEY_ID\"' >> ~/.bashrc"
    echo "   source ~/.bashrc"
    exit 1
fi

# Ensure MAILACL_DOMAIN is set
if [[ -z "${MAILACL_DOMAIN:-}" ]]; then
    echo "❌ ERROR: MAILACL_DOMAIN environment variable is not set."
    echo "   This variable defines the domain used for email generation."
    echo ""
    echo "🔧 To set it temporarily, run:"
    echo "   export MAILACL_DOMAIN=\"yourdomain.com\""
    echo ""
    echo "🔧 To make this permanent, add the following to your ~/.bashrc or ~/.profile:"
    echo "   echo 'export MAILACL_DOMAIN=\"yourdomain.com\"' >> ~/.bashrc"
    echo "   source ~/.bashrc"
    exit 1
fi

validate_domain() {
    local domain="$1"
    local label
    local -a labels

    (( ${#domain} <= 253 )) || return 1
    [[ "$domain" == *.* && "$domain" != .* && "$domain" != *. && "$domain" != *..* ]] || return 1
    IFS='.' read -r -a labels <<<"$domain"
    (( ${#labels[@]} >= 2 )) || return 1

    for label in "${labels[@]}"; do
        (( ${#label} >= 1 && ${#label} <= 63 )) || return 1
        [[ "$label" =~ ^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?$ ]] || return 1
    done
    [[ "${labels[${#labels[@]} - 1]}" =~ [A-Za-z] ]]
}

# Validate MAILACL_DOMAIN as an ASCII DNS name.
if ! validate_domain "$MAILACL_DOMAIN"; then
    echo "❌ ERROR: MAILACL_DOMAIN '$MAILACL_DOMAIN' appears to be invalid."
    echo "   Use an ASCII domain with valid DNS labels, such as 'example.com' or 'sub.example.net'."
    echo ""
    echo "🔧 To correct it, run:"
    echo "   export MAILACL_DOMAIN=\"yourdomain.com\""
    exit 1
fi

# MailACL uses only Python's standard library for hashing and encoding.
if ! command -v python3 &>/dev/null; then
    echo "❌ ERROR: python3 is required for MailACL signatures."
    exit 1
fi

if ! command -v gpg &>/dev/null; then
    echo "❌ ERROR: gpg is required to access the configured secret key."
    exit 1
fi

# Check if the specified GPG key is available as a secret key
if ! gpg --list-secret-keys -- "$MAILACL_GPG_KEY" &>/dev/null; then
    echo "❌ ERROR: The GPG key '$MAILACL_GPG_KEY' is invalid or not found."
    echo "   Please ensure you have a valid GPG key by running:"
    echo "   gpg --list-secret-keys"
    echo ""
    echo "🔧 If you need to generate a GPG key, use the following command:"
    echo "   gpg --full-generate-key"
    echo ""
    echo "🔧 If you already have a key but need to set it, run:"
    echo "   export MAILACL_GPG_KEY=\"YOUR_KEY_ID\""
    exit 1
fi

derive_secret_key() {
    # Preserve the legacy key material: ASCII hex SHA-512 of the exported GPG
    # secret key. Existing signatures continue to verify against this.
    gpg --export-secret-keys -- "$MAILACL_GPG_KEY" 2>/dev/null |
        python3 -c '
import hashlib
import sys

data = sys.stdin.buffer.read()
if not data:
    raise SystemExit(1)
sys.stdout.write(hashlib.sha512(data).hexdigest())
'
}

lowercase() {
    LC_ALL=C tr '[:upper:]' '[:lower:]'
}


use_color() {
    case "${MAILACL_COLOR:-auto}" in
        always|yes|true|1)
            return 0
            ;;
        never|no|false|0)
            return 1
            ;;
        auto|"")
            [[ -t 1 && -z "${NO_COLOR:-}" ]]
            ;;
        *)
            [[ -t 1 && -z "${NO_COLOR:-}" ]]
            ;;
    esac
}

color_signature() {
    local text="$1"
    local i ch
    if ! use_color; then
        printf '%s' "$text"
        return 0
    fi

    local digit_color=$'\033[1;33m'   # bold yellow: numbers stand apart on dark/light terminals
    local letter_color=$'\033[1;35m'  # bold magenta: letters contrast strongly with yellow digits
    local symbol_color=$'\033[1;31m'  # bold red: transitional Base64 punctuation such as / or +
    local reset=$'\033[0m'

    for (( i=0; i<${#text}; i++ )); do
        ch="${text:i:1}"
        case "$ch" in
            [0-9]) printf '%s%s%s' "$digit_color" "$ch" "$reset" ;;
            [A-Za-z]) printf '%s%s%s' "$letter_color" "$ch" "$reset" ;;
            *) printf '%s%s%s' "$symbol_color" "$ch" "$reset" ;;
        esac
    done
}

color_email() {
    local email="$1"
    local local_part="${email%@*}"
    local domain="${email#*@}"
    local prefix="${local_part%-*}"
    local signature="${local_part##*-}"

    if [[ -z "$signature" || "$prefix" == "$local_part" ]]; then
        printf '%s' "$email"
        return 0
    fi

    printf '%s-' "$prefix"
    color_signature "$signature"
    printf '@%s' "$domain"
}

print_color_key() {
    if ! use_color; then
        return 0
    fi
    printf '🎨 Color key: '
    color_signature 'abc'
    printf '=letters '
    color_signature '123'
    printf '=numbers'
    printf '\n'
}

print_colored_signature() {
    local label="$1"
    local signature="$2"
    if ! use_color; then
        return 0
    fi
    printf '🎨 %s: ' "$label"
    color_signature "$signature"
    printf '\n'
}

print_colored_email() {
    local label="$1"
    local email="$2"
    if ! use_color; then
        return 0
    fi
    printf '🎨 %s: ' "$label"
    color_email "$email"
    printf '\n'
}

compute_encoded_signature() {
    local encoding="$1"
    local truncation="$2"
    local prefix="$3"
    local length="$4"

    # Feed the derived HMAC key over stdin rather than exposing it in a process
    # argument. The key remains the legacy ASCII SHA-512 hex string so existing
    # addresses keep exactly the same signatures.
    printf '%s\0%s' "$SECRET_KEY" "$prefix" |
        python3 -c '
import base64
import hashlib
import hmac
import sys

encoding, truncation, length_text = sys.argv[1:4]
length = int(length_text)
payload = sys.stdin.buffer.read()
try:
    key, prefix = payload.split(b"\0", 1)
except ValueError:
    raise SystemExit("invalid internal HMAC payload")

digest = hmac.new(key, prefix, hashlib.sha512).digest()
if encoding == "hex":
    encoded = digest.hex()
elif encoding == "base32":
    encoded = base64.b32encode(digest).decode("ascii").rstrip("=").lower()
elif encoding == "base64":
    encoded = base64.b64encode(digest).decode("ascii").rstrip("=")
elif encoding == "base36":
    alphabet = "0123456789abcdefghijklmnopqrstuvwxyz"
    number = int.from_bytes(digest, "big")
    chars = []
    if number == 0:
        chars.append("0")
    else:
        while number:
            number, remainder = divmod(number, 36)
            chars.append(alphabet[remainder])
    encoded = "".join(reversed(chars)).rjust(100, "0")
else:
    raise SystemExit(f"unsupported encoding: {encoding}")

if truncation == "suffix":
    sys.stdout.write(encoded[-length:])
else:
    sys.stdout.write(encoded[:length])
' "$encoding" "$truncation" "$length"
}

compute_hex_signature() {
    compute_encoded_signature "hex" "prefix" "$1" "$2"
}

compute_base36_signature() {
    compute_encoded_signature "base36" "suffix" "$1" "$2"
}

compute_base36_prefix_signature() {
    compute_encoded_signature "base36" "prefix" "$1" "$2"
}

compute_base32_signature() {
    compute_encoded_signature "base32" "prefix" "$1" "$2"
}

compute_base64_signature() {
    compute_encoded_signature "base64" "prefix" "$1" "$2"
}

max_signature_length_for_encoding() {
    case "$1" in
        hex) echo 128 ;;
        base36) echo 100 ;;
        base32) echo 103 ;;
        base64) echo 86 ;;
    esac
}

compute_signature() {
    local encoding="$1"
    local prefix="$2"
    local length="$3"
    case "$encoding" in
        hex) compute_hex_signature "$prefix" "$length" ;;
        base36) compute_base36_signature "$prefix" "$length" ;;
        base32) compute_base32_signature "$prefix" "$length" ;;
        base64) compute_base64_signature "$prefix" "$length" ;;
    esac
}


report_entropy() {
    local encoding="$1"
    local length="$2"
    local truncation="${3:-standard}"
    python3 - "$encoding" "$length" "$truncation" <<'PY'
import math
import sys

encoding = sys.argv[1]
length = int(sys.argv[2])
truncation = sys.argv[3]

if encoding == "base36" and truncation == "transitional-prefix":
    print("📊 Entropy: not reported for transitional Base36 prefixes.")
    print("🔢 Distribution: fixed-width leading digits are biased; character count is not a uniform search-space estimate.")
    print("🧭 Strength: TRANSITIONAL — retained for verification compatibility only.")
    raise SystemExit(0)

bases = {"hex": 16, "base36": 36, "base32": 32, "base64": 64}
base = bases[encoding]
bits_per_char = math.log2(base)
nominal_space = base ** length
digest_space = 1 << 512

if encoding == "base36":
    # Suffix truncation is reduction modulo 36**length. Account for the
    # at-most-one-preimage imbalance when 2**512 is not divisible by that.
    quotient, remainder = divmod(digest_space, nominal_space)
    max_preimages = quotient + (1 if remainder else 0)
    per_guess = max_preimages / digest_space
    bits = -math.log2(per_guess)
else:
    # Prefixes of the standard encodings expose independent digest bits until
    # the final partial character; never report more than the 512-bit digest.
    bits = min(length * bits_per_char, 512.0)
    per_guess = 2.0 ** (-bits)

if per_guess >= 1.0:
    p_1m = 1.0
else:
    p_1m = -math.expm1(1_000_000 * math.log1p(-per_guess))


def fmt_probability(probability):
    if probability >= 0.9995:
        return "≈100%"
    if probability >= 0.01:
        return f"{probability * 100:.3g}%"
    return f"{probability:.3e}"


if bits < 20:
    label = "VERY WEAK — form workaround / typo marker only; easy to guess at scale."
elif bits < 32:
    label = "WEAK — use only for constrained or low-risk forms; prefer 8+ Base36 chars."
elif bits < 48:
    label = "MODERATE — useful online, but prefer the 10-char default for inbox filtering."
elif bits < 64:
    label = "GOOD — practical default for MailACL inbox filtering."
else:
    label = "STRONG — conservative for online guessing resistance."

print(f"📊 Entropy: {bits:.2f} bits effective ({length} chars, {encoding})")
print(f"🔢 Effective search space: ≈ 2^{bits:.2f}; nominal alphabet space {base}^{length}")
print(f"🎲 1M random guesses: {fmt_probability(p_1m)} success probability")
print(f"🧭 Strength: {label}")
PY
}

# Read input from an argument when supplied; otherwise prompt interactively.
if (( $# >= 1 )); then
    INPUT="$1"
else
    if ! read -r -p "Enter an identifier to generate or an email to verify: " INPUT; then
        echo "❌ ERROR: No identifier or email was supplied."
        exit 2
    fi
fi

if [[ "$INPUT" == *"@"* ]] && (( $# >= 2 )); then
    echo "❌ ERROR: Verification mode does not accept SIGNATURE_LENGTH."
    exit 2
fi

# Use the configured GPG key to derive the secret HMAC key once.
if ! SECRET_KEY=$(derive_secret_key); then
    echo "❌ ERROR: Unable to export secret key for '$MAILACL_GPG_KEY'."
    exit 1
fi
if [[ -z "$SECRET_KEY" ]]; then
    echo "❌ ERROR: Unable to export secret key for '$MAILACL_GPG_KEY'."
    exit 1
fi

# Determine if input is a MailACL email (contains '@')
if [[ "$INPUT" == *"@"* ]]; then
    # Verification Mode
    EMAIL="$INPUT"
    if [[ "${EMAIL#*@}" == *"@"* ]]; then
        echo "❌ ERROR: A MailACL email must contain exactly one '@'."
        exit 1
    fi
    EMAIL_DOMAIN="${EMAIL##*@}"
    if [[ "${EMAIL_DOMAIN,,}" != "${MAILACL_DOMAIN,,}" ]]; then
        echo "❌ ERROR: Email domain '$EMAIL_DOMAIN' does not match MAILACL_DOMAIN '$MAILACL_DOMAIN'."
        exit 1
    fi

    # Enforce RFC 5321's octet limit before interpreting the local part.
    LOCAL_PART="${EMAIL%@*}"
    LOCAL_PART_BYTES=$(printf '%s' "$LOCAL_PART" | wc -c)
    if (( LOCAL_PART_BYTES > MAX_LOCAL_LENGTH )); then
        echo "❌ ERROR: Email local part exceeds the RFC 5321 64-byte local-part limit."
        exit 1
    fi

    # Extract prefix and signature correctly (split at the last '-')
    PREFIX="${LOCAL_PART%-*}"
    SIGNATURE="${LOCAL_PART##*-}"

    # Ensure we got a valid prefix and signature
    if [[ -z "$PREFIX" || -z "$SIGNATURE" || "$PREFIX" == "$LOCAL_PART" ]]; then
        echo "❌ ERROR: Unable to extract prefix and signature from email."
        exit 1
    fi

    # Display extracted info
    echo "📌 Prefix: $PREFIX"
    echo "🔍 Expected: $SIGNATURE"
    print_color_key
    print_colored_signature "Expected signature" "$SIGNATURE"

    SIGNATURE_LENGTH=${#SIGNATURE}
    SIGNATURE_LOWER=$(printf '%s' "$SIGNATURE" | lowercase)
    COMPUTED_BASE36=$(compute_base36_signature "$PREFIX" "$SIGNATURE_LENGTH")
    COMPUTED_BASE36_PREFIX=$(compute_base36_prefix_signature "$PREFIX" "$SIGNATURE_LENGTH")
    COMPUTED_BASE32=$(compute_base32_signature "$PREFIX" "$SIGNATURE_LENGTH")
    COMPUTED_HEX=$(compute_hex_signature "$PREFIX" "$SIGNATURE_LENGTH")
    COMPUTED_BASE64=$(compute_base64_signature "$PREFIX" "$SIGNATURE_LENGTH")

    if [[ "$SIGNATURE_LOWER" == "$COMPUTED_BASE36" ]]; then
        echo "🔐 Encoding: base36 lowercase suffix"
        report_entropy "base36" "$SIGNATURE_LENGTH"
        if [[ "$SIGNATURE" != "$SIGNATURE_LOWER" ]]; then
            echo "🔡 Normalized input signature to lowercase for validation."
        fi
        echo "🔍 Computed: $COMPUTED_BASE36"
        print_colored_signature "Computed signature" "$COMPUTED_BASE36"
        echo "✅ Verification successful."
    elif [[ "$SIGNATURE_LOWER" == "$COMPUTED_BASE36_PREFIX" ]]; then
        echo "🔐 Encoding: base36 lowercase prefix (transitional)"
        report_entropy "base36" "$SIGNATURE_LENGTH" "transitional-prefix"
        if [[ "$SIGNATURE" != "$SIGNATURE_LOWER" ]]; then
            echo "🔡 Normalized input signature to lowercase for validation."
        fi
        echo "🔍 Computed: $COMPUTED_BASE36_PREFIX"
        print_colored_signature "Computed signature" "$COMPUTED_BASE36_PREFIX"
        echo "✅ Verification successful."
    elif [[ "$SIGNATURE_LOWER" == "$COMPUTED_BASE32" ]]; then
        echo "🔐 Encoding: base32 lowercase (transitional)"
        report_entropy "base32" "$SIGNATURE_LENGTH"
        if [[ "$SIGNATURE" != "$SIGNATURE_LOWER" ]]; then
            echo "🔡 Normalized input signature to lowercase for validation."
        fi
        echo "🔍 Computed: $COMPUTED_BASE32"
        print_colored_signature "Computed signature" "$COMPUTED_BASE32"
        echo "✅ Verification successful."
    elif [[ "$SIGNATURE_LOWER" == "$COMPUTED_HEX" ]]; then
        echo "🔐 Encoding: hex (legacy)"
        report_entropy "hex" "$SIGNATURE_LENGTH"
        if [[ "$SIGNATURE" != "$SIGNATURE_LOWER" ]]; then
            echo "🔡 Normalized input signature to lowercase for validation."
        fi
        echo "🔍 Computed: $COMPUTED_HEX"
        print_colored_signature "Computed signature" "$COMPUTED_HEX"
        echo "✅ Verification successful."
    elif [[ "$SIGNATURE" == "$COMPUTED_BASE64" ]]; then
        echo "🔐 Encoding: base64 (transitional exact match)"
        report_entropy "base64" "$SIGNATURE_LENGTH"
        echo "🔍 Computed: $COMPUTED_BASE64"
        print_colored_signature "Computed signature" "$COMPUTED_BASE64"
        echo "✅ Verification successful."
    else
        echo "🔍 Computed base36 suffix: $COMPUTED_BASE36"
        echo "🔍 Computed base36 prefix: $COMPUTED_BASE36_PREFIX"
        echo "🔍 Computed base32:        $COMPUTED_BASE32"
        echo "🔍 Computed hex:           $COMPUTED_HEX"
        echo "🔍 Computed base64:        $COMPUTED_BASE64"
        echo "❌ ERROR: Verification failed. The email identifier may be tampered with or does not match the expected signature."
        exit 1
    fi

else
    # Generation Mode
    PREFIX="$INPUT"
    if [[ -z "$PREFIX" ]]; then
        echo "❌ ERROR: Identifier must not be empty."
        exit 1
    fi
    DOT_ATOM_PATTERN="^[A-Za-z0-9.!#\$%&'*+/=?^_\`{|}~-]+$"
    if [[ ! "$PREFIX" =~ $DOT_ATOM_PATTERN || "$PREFIX" == .* || "$PREFIX" == *. || "$PREFIX" == *..* ]]; then
        echo "❌ ERROR: Identifier must be email-safe ASCII dot-atom text without leading, trailing, or consecutive dots."
        exit 1
    fi

    # Positional generation uses the default unless an explicit length is supplied.
    # Prompt for the length only when generation itself is interactive.
    if (( $# >= 2 )); then
        HASH_OPTION="$2"
    elif (( $# >= 1 )); then
        HASH_OPTION="$DEFAULT_HASH_LENGTH"
    else
        read -r -p "Enter signature length (default: $DEFAULT_HASH_LENGTH, min: $MIN_HASH_LENGTH, or type 'max' for maximum allowed): " HASH_OPTION
    fi
    HASH_OPTION=${HASH_OPTION:-$DEFAULT_HASH_LENGTH}

    # Calculate available space for the signature
    PREFIX_LENGTH=${#PREFIX}
    AVAILABLE_LENGTH=$(( MAX_LOCAL_LENGTH - PREFIX_LENGTH - 1 ))  # Reserve 1 for hyphen
    MAX_ENCODING_LENGTH=$(max_signature_length_for_encoding "$MAILACL_SIGNATURE_ENCODING")

    if (( AVAILABLE_LENGTH < MIN_HASH_LENGTH )); then
        echo "❌ ERROR: Prefix is too long. At least $MIN_HASH_LENGTH signature characters must fit within the $MAX_LOCAL_LENGTH-character local-part limit."
        exit 1
    fi

    # Determine signature length based on user input
    if [[ "$HASH_OPTION" == "max" ]]; then
        HASH_LENGTH=$AVAILABLE_LENGTH
    elif [[ "$HASH_OPTION" =~ ^[0-9]+$ ]]; then
        if (( ${#HASH_OPTION} > 3 )); then
            echo "❌ ERROR: Signature length is too large. Use at most three decimal digits or 'max'."
            exit 1
        fi
        HASH_LENGTH=$((10#$HASH_OPTION))
        if (( HASH_LENGTH < MIN_HASH_LENGTH )); then
            echo "❌ ERROR: Signature length must be at least $MIN_HASH_LENGTH."
            exit 1
        fi
    else
        echo "❌ ERROR: Invalid input. Signature length must be at least $MIN_HASH_LENGTH, or 'max' for the maximum allowed."
        exit 1
    fi

    # Ensure the final signature length does not exceed encoding or local-part limits
    if (( HASH_LENGTH > MAX_ENCODING_LENGTH )); then
        HASH_LENGTH=$MAX_ENCODING_LENGTH
    fi
    if (( HASH_LENGTH > AVAILABLE_LENGTH )); then
        HASH_LENGTH=$AVAILABLE_LENGTH
    fi

    # Generate the signature using the selected encoding
    if ! SIGNATURE=$(compute_signature "$MAILACL_SIGNATURE_ENCODING" "$PREFIX" "$HASH_LENGTH") || [[ -z "$SIGNATURE" ]]; then
        echo "❌ ERROR: Signature computation failed."
        exit 1
    fi

    # Construct the final email
    FINAL_EMAIL="${PREFIX}-${SIGNATURE}@${MAILACL_DOMAIN}"

    # Display the generated email
    echo "🔐 Signature encoding: $MAILACL_SIGNATURE_ENCODING"
    echo "📏 Signature length: $HASH_LENGTH"
    report_entropy "$MAILACL_SIGNATURE_ENCODING" "$HASH_LENGTH"
    echo "📧 Generated MailACL email: $FINAL_EMAIL"
    print_color_key
    print_colored_email "Color view" "$FINAL_EMAIL"
fi
