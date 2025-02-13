#!/bin/bash

# Set the max local part length according to RFC 5321
MAX_LOCAL_LENGTH=64
MIN_HASH_LENGTH=12  # Minimum allowed hash length
DEFAULT_HASH_LENGTH=16  # Default to 16 characters for shorter hashes

# Ensure MAILACL_GPG_KEY is set
if [[ -z "${MAILACL_GPG_KEY:-}" ]]; then
    echo "❌ ERROR: MAILACL_GPG_KEY environment variable is not set."
    echo "   This variable is required to specify the GPG key ID used for signing."
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
    echo "🔧 To make it permanent, add the following to your ~/.bashrc or ~/.profile:"
    echo "   echo 'export MAILACL_DOMAIN=\"yourdomain.com\"' >> ~/.bashrc"
    echo "   source ~/.bashrc"
    exit 1
fi

# Validate MAILACL_DOMAIN format (basic check)
if ! [[ "$MAILACL_DOMAIN" =~ ^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
    echo "❌ ERROR: MAILACL_DOMAIN '$MAILACL_DOMAIN' appears to be invalid."
    echo "   Ensure it is a valid domain, such as 'example.com' or 'sub.domain.net'."
    echo ""
    echo "🔧 To correct it, run:"
    echo "   export MAILACL_DOMAIN=\"yourdomain.com\""
    exit 1
fi

# Check if the specified GPG key is available as a secret key
if ! gpg --list-secret-keys "$MAILACL_GPG_KEY" &>/dev/null; then
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

# Ask for input
read -p "Enter an identifier to generate or an email to verify: " INPUT

# Determine if input is a MailACL email (contains '@')
if [[ "$INPUT" == *"@"* ]]; then
    # ^=^s^l Verification Mode
    EMAIL="$INPUT"

    # Extract the local part (before @)
    LOCAL_PART="${EMAIL%@*}"

    # Extract prefix and hash correctly (split at the last '-')
    PREFIX="${LOCAL_PART%-*}"
    HASH="${LOCAL_PART##*-}"

    # Ensure we got a valid prefix and hash
    if [[ -z "$PREFIX" || -z "$HASH" ]]; then
        echo "❌ ERROR: Unable to extract prefix and hash from email."
        exit 1
    fi

    # Display extracted info
    echo "📌 Prefix: $PREFIX"

    # Use the configured GPG key to derive the secret key
    SECRET_KEY=$(echo -n "$PREFIX" | gpg --export-secret-keys "$MAILACL_GPG_KEY" 2>/dev/null | sha512sum | cut -c1-128)

    # If SECRET_KEY is empty, the specified GPG key cannot be exported
    if [[ -z "$SECRET_KEY" ]]; then
        echo "❌ ERROR: Unable to export secret key for '$MAILACL_GPG_KEY'."
        exit 1
    fi

    # Recompute the HMAC-SHA512 hash
    RECOMPUTED_HASH=$(echo -n "$PREFIX" | openssl dgst -sha512 -hmac "$SECRET_KEY" | cut -d ' ' -f2 | cut -c1-${#HASH})

    # Display hashes for debugging
    echo "🔍 Expected: $HASH"
    echo "🔍 Computed: $RECOMPUTED_HASH"

    # Compare the expected hash with the recomputed hash
    if [[ "$HASH" == "$RECOMPUTED_HASH" ]]; then
        echo "✅ Verification successful."
    else
        echo "❌ ERROR: Verification failed. The email identifier may be tampered with or does not match the expected hash."
    fi

else
    # ^=^s^l Generation Mode
    PREFIX="$INPUT"

    # Ask for hash length (default: 16, or 'max' for maximum allowed)
    read -p "Enter hash length (default: $DEFAULT_HASH_LENGTH, min: $MIN_HASH_LENGTH, or type 'max' for maximum allowed): " HASH_OPTION
    HASH_OPTION=${HASH_OPTION:-$DEFAULT_HASH_LENGTH}

    # Calculate available space for the hash
    PREFIX_LENGTH=${#PREFIX}
    AVAILABLE_LENGTH=$(( MAX_LOCAL_LENGTH - PREFIX_LENGTH - 1 ))  # Reserve 1 for hyphen

    # Determine hash length based on user input
    if [[ "$HASH_OPTION" == "max" ]]; then
        HASH_LENGTH=$AVAILABLE_LENGTH
    elif (( HASH_OPTION >= MIN_HASH_LENGTH && HASH_OPTION <= 64 )); then
        HASH_LENGTH=$HASH_OPTION
    else
        echo "❌ ERROR: Invalid input. Hash length must be between $MIN_HASH_LENGTH and 64, or 'max' for the maximum allowed."
        exit 1
    fi

    # Ensure the final hash length does not exceed the available space
    if (( HASH_LENGTH > AVAILABLE_LENGTH )); then
        HASH_LENGTH=$AVAILABLE_LENGTH
    fi

    # Use the configured GPG key to derive a secret HMAC key
    SECRET_KEY=$(echo -n "$PREFIX" | gpg --export-secret-keys "$MAILACL_GPG_KEY" 2>/dev/null | sha512sum | cut -c1-128)

    # If SECRET_KEY is empty, the specified GPG key cannot be exported
    if [[ -z "$SECRET_KEY" ]]; then
        echo "❌ ERROR: Unable to export secret key for '$MAILACL_GPG_KEY'."
        exit 1
    fi

    # Generate an HMAC-SHA512 hash of the prefix using the secret key
    HMAC_HASH=$(echo -n "$PREFIX" | openssl dgst -sha512 -hmac "$SECRET_KEY" | cut -d ' ' -f2 | cut -c1-$HASH_LENGTH)

    # Construct the final email
    FINAL_EMAIL="${PREFIX}-${HMAC_HASH}@${MAILACL_DOMAIN}"

    # Display the generated email
    echo "📧 Generated MailACL email: $FINAL_EMAIL"
fi
