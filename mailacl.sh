#!/bin/bash

# Set the max local part length according to RFC 5321
MAX_LOCAL_LENGTH=64
DEFAULT_HASH_LENGTH=16  # Default to 16 characters for shorter hashes

# Ensure GPG key is set
if [[ -z "$MAILACL_GPG_KEY" ]]; then
    echo "❌ ERROR: MAILACL_GPG_KEY environment variable is not set."
    exit 1
fi

# Ask for input
read -p "Enter an identifier to generate or an email to verify: " INPUT

# Determine if input is a MailACL email (contains '@')
if [[ "$INPUT" == *"@"* ]]; then
    # 📌 Verification Mode
    EMAIL="$INPUT"

    # Extract the local part (before @)
    LOCAL_PART="${EMAIL%@*}"

    # Extract prefix and hash correctly (split at the last '-')
    PREFIX="${LOCAL_PART%-*}"
    HASH="${LOCAL_PART##*-}"

    # Ensure we got a valid prefix and hash
    if [[ -z "$PREFIX" || -z "$HASH" ]]; then
        echo "❌ Error: Unable to extract prefix and hash from email."
        exit 1
    fi

    # Display extracted info
    echo "📌 Prefix: $PREFIX"

    # Use the configured GPG key to derive the secret key
    SECRET_KEY=$(echo -n "$PREFIX" | gpg --export-secret-keys "$MAILACL_GPG_KEY" | sha512sum | cut -c1-128)

    # Recompute the HMAC-SHA512 hash using the secret key
    RECOMPUTED_HASH=$(echo -n "$PREFIX" | openssl dgst -sha512 -hmac "$SECRET_KEY" | cut -d ' ' -f2 | cut -c1-${#HASH})

    # Display hashes for debugging
    echo "🔍 Expected: $HASH"
    echo "🔍 Computed: $RECOMPUTED_HASH"

    # Compare the expected hash with the recomputed hash
    if [[ "$HASH" == "$RECOMPUTED_HASH" ]]; then
        echo "✅ Verification successful."
    else
        echo "❌ Verification failed: The email identifier may be tampered with or does not match the expected hash."
    fi

else
    # 📌 Generation Mode
    PREFIX="$INPUT"

    # Ask for hash length (default: 16, or 'max' for maximum allowed)
    read -p "Enter hash length (default: $DEFAULT_HASH_LENGTH, or type 'max' for maximum allowed'): " HASH_OPTION
    HASH_OPTION=${HASH_OPTION:-$DEFAULT_HASH_LENGTH}

    # Calculate available space for the hash
    PREFIX_LENGTH=${#PREFIX}
    AVAILABLE_LENGTH=$(( MAX_LOCAL_LENGTH - PREFIX_LENGTH - 1 ))  # Reserve 1 for hyphen

    # Determine hash length based on user input
    if [[ "$HASH_OPTION" == "max" ]]; then
        HASH_LENGTH=$AVAILABLE_LENGTH
    elif (( HASH_OPTION >= 16 && HASH_OPTION <= 64 )); then
        HASH_LENGTH=$HASH_OPTION
    else
        echo "Invalid input. Hash length must be between 16 and 64, or 'max' for the maximum allowed."
        exit 1
    fi

    # Ensure the final hash length does not exceed the available space
    if (( HASH_LENGTH > AVAILABLE_LENGTH )); then
        HASH_LENGTH=$AVAILABLE_LENGTH
    fi

    # Use the configured GPG key to derive a secret HMAC key
    SECRET_KEY=$(echo -n "$PREFIX" | gpg --export-secret-keys "$MAILACL_GPG_KEY" | sha512sum | cut -c1-128)

    # Generate an HMAC-SHA512 hash of the prefix using the secret key
    HMAC_HASH=$(echo -n "$PREFIX" | openssl dgst -sha512 -hmac "$SECRET_KEY" | cut -d ' ' -f2 | cut -c1-$HASH_LENGTH)

    # Construct the final email
    FINAL_EMAIL="${PREFIX}-${HMAC_HASH}@robert.langhorn.com"

    # Display the generated email
    echo "Generated MailACL email: $FINAL_EMAIL"
fi
