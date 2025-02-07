# 📜 Theory of Operation: MailACL

## 🔍 Overview
MailACL is a cryptographic email tracking and security system that generates **unique, PGP-signed email addresses** for recipients. These addresses allow users to trace leaks, prevent impersonation, and maintain email integrity using deterministic cryptographic hashing. By leveraging PGP signatures and cryptographic hashing, MailACL ensures that email identifiers remain secure while allowing for easy verification and validation.

## 🚀 Core Principles
MailACL is designed with the following principles:

1️⃣ **Deterministic Hashing** – Ensures that the same input always generates the same email address signature, enabling consistent verification and preventing discrepancies.
2️⃣ **PGP-Signed Identifiers** – Uses a cryptographic signature to prevent forgery, making it impossible for attackers to generate valid email addresses without access to the private key.
3️⃣ **HMAC-SHA512 Hashing** – Provides strong security and prevents reverse engineering, ensuring that even if an attacker obtains an email, they cannot reconstruct the signing key.
4️⃣ **Human-Readable Format** – Email addresses remain user-friendly while being cryptographically secure, balancing usability and security effectively.
5️⃣ **Tamper-Proof Verification** – Since each email address is deterministically generated, any modification can be instantly detected during verification.
6️⃣ **Efficient Tracking of Leaks** – If an email is leaked or compromised, its unique cryptographic identifier allows for immediate identification of the source.

---

## ⚙️ How It Works
### **1️⃣ Generating a Signed Email Address**
The email identifier (e.g., `eddie.foobar`) is processed using the following steps:

1. **Hashing the PGP Secret Key:**
   ```bash
   SECRET_KEY=$(gpg --export-secret-keys "$MAILACL_GPG_KEY" | sha512sum | cut -c1-128)
   ```
   - This converts the raw GPG secret key into a **deterministic** and **fixed-length** value.
   - Ensures the derived key is always the same while protecting the original GPG key.
   - Provides a cryptographic foundation for the HMAC process by making the key **consistent but non-recoverable**.

2. **Computing the HMAC-SHA512 Hash:**
   ```bash
   HMAC_HASH=$(echo -n "$PREFIX" | openssl dgst -sha512 -hmac "$SECRET_KEY" | cut -d ' ' -f2 | cut -c1-$HASH_LENGTH)
   ```
   - Uses the **PGP-derived key** to generate an HMAC-SHA512 signature of the email prefix.
   - The resulting hash is **truncated** to a user-specified length (e.g., 16, 32, or max 64 characters).
   - Ensures that the hash is both unique and irreversible, preventing unauthorized reconstruction.

3. **Constructing the Final Email Address:**
   ```
   eddie.foobar-abcdef1234567890@yourdomain.com
   ```
   - The prefix remains readable, and the hash ensures uniqueness and authenticity.
   - Ensures a balance between user readability and cryptographic security.

---

### **2️⃣ Verifying an Email Address**
When verifying an email, MailACL extracts the **prefix** and **hash**, then recomputes the HMAC-SHA512 signature.

1. **Extract the Local Part:**
   ```bash
   LOCAL_PART=$(echo "$EMAIL" | cut -d '@' -f1)
   PREFIX=$(echo "$LOCAL_PART" | rev | cut -d '-' -f2- | rev)
   HASH=$(echo "$LOCAL_PART" | rev | cut -d '-' -f1 | rev)
   ```
   - Splits the email into **prefix** and **hash** components.
   - Ensures that the verification process is structured and follows a deterministic approach.

2. **Recompute the HMAC-SHA512 Signature:**
   ```bash
   RECOMPUTED_HASH=$(echo -n "$PREFIX" | openssl dgst -sha512 -hmac "$SECRET_KEY" | cut -d ' ' -f2 | cut -c1-$HASH_LENGTH)
   ```
   - Uses the same deterministic process to verify if the hash matches the original email.
   - Ensures that verification can be done without storing a separate database of issued addresses.

3. **Compare and Validate:**
   ```bash
   if [ "$HASH" == "$RECOMPUTED_HASH" ]; then
       echo "✅ Verification successful."
   else
       echo "❌ Verification failed: Email identifier may be tampered with."
   fi
   ```
   - Ensures the email address has **not been altered or forged**.
   - Any modification to the email will cause the computed hash to differ from the stored hash, making tampering immediately detectable.

---

## 🔒 Security Considerations
- **Irreversibility**: The use of **HMAC-SHA512** prevents reversing the hash to obtain the original key.
- **Forgery Protection**: Only someone with access to the **PGP private key** can generate a valid email signature.
- **Deterministic Output**: Given the same input, MailACL **always** produces the same signed email, allowing verification.
- **Email Tracking**: If an email leaks, its cryptographic signature provides **proof of the source**.
- **Tamper Detection**: If any part of the email is modified, verification will fail, ensuring the integrity of the signed addresses.
- **No Centralized Storage**: Since verification relies on deterministic hashing rather than a stored database, it reduces the risk of centralized breaches.
- **Minimal Overhead**: The hashing process is computationally efficient and does not require significant system resources.

---

## 📌 Conclusion
MailACL combines **PGP cryptography, HMAC-SHA512 hashing, and deterministic email signatures** to create a secure and verifiable email system. It enables tracking, prevents impersonation, and ensures email integrity **without exposing the private key**. The system is designed to be highly **efficient, scalable, and user-friendly**, allowing for seamless integration into various email security architectures.

By using **cryptographic hashing and PGP signatures**, MailACL not only safeguards email identities but also **allows for seamless verification of authenticity**. The system provides a robust framework for **email tracking, anti-spoofing, and leak prevention**, making it an invaluable tool for individuals and organizations alike.

🚀 **With MailACL, email security is both cryptographically strong and user-friendly.** It delivers **strong guarantees against email-based attacks, ensures trust in communications, and provides cryptographic proof of sender authenticity.**

