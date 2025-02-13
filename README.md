# 📧 MailACL: PGP-Signed Email Tracking System

**MailACL** is an advanced email tracking and security system that generates **unique, cryptographically signed email addresses** for each recipient. These email addresses allow senders to **detect leaks, prevent forgery, and maintain email security** without sacrificing human readability.

---

## 🚀 Features
👉 **Leak Detection with Cryptographic Proof** – Every email address is uniquely signed, making leaks instantly traceable.  
👉 **Impossible to Forge** – Attackers cannot generate valid email addresses without your PGP private key.  
👉 **Human-Readable Format** – Email addresses are easy to read while remaining cryptographically secure.  
👉 **Prevents Guessing & Enumeration** – Even if the system is known, attackers cannot reverse-engineer valid addresses.  
👉 **Deterministic Hashing with SHA-512** – Ensures **reliable, irreversible, and consistent** email verification.  

---

## 📌 **Why Use MailACL?**
MailACL helps organizations and individuals **protect their email communications** by assigning unique email addresses to different services, contacts, or recipients.  
If an email is **leaked, exposed in a data breach, or forwarded without permission**, you will **immediately know the source**.

### **🔍 Example Use Cases**
- **Tracking Leaks**: If `eddie.foobar-a1b2c3d4e5f6g7h8@yourdomain.com` leaks, you know **Eddie Foobar** was the source.  
- **Preventing Phishing**: Attackers cannot generate **valid cryptographic identifiers** to impersonate someone.  
- **Managing Vendor Communication**: Assign a unique email to **each company** and revoke compromised addresses.  
- **Identifying Forwarded Emails**: Since addresses are \*\*unique to each generated email\*\*, forwarded emails can be traced.  

---

# 🛠 Installation Guide

### **1️⃣ Install Required Dependencies**
MailACL requires `git`, `GPG (GnuPG)`, and `OpenSSL`. Install them using:
```bash
apt update && apt install git gnupg openssl -y
```

### **2️⃣ Clone the Repository**
To download the latest version of MailACL, run:
```bash
git clone https://github.com/robertlanghorn/mailacl.git
cd mailacl
chmod +x mailacl.sh
```

### **3️⃣ Configure Your GPG Key**
MailACL uses **PGP/GPG** to generate and verify email signatures.  
#### **Check for Existing GPG Keys**
Run:
```bash
gpg --list-secret-keys
```
If you have an existing key, **use the key ID** in the next step.  
If not, **generate a new key**:
```bash
gpg --full-generate-key
```
Follow the prompts to create an **ED25519 key**.

#### **Set Your GPG Key for MailACL**
Once you have a GPG key, **export the key ID**:
```bash
gpg --list-secret-keys --keyid-format LONG
```
Copy your **key ID** and **domain name** then set it as an environment variable:
```bash
export MAILACL_GPG_KEY="YOUR_GPG_KEY_ID"
export MAILACL_DOMAIN="yourdomain.com"
```
To make this permanent, add it to your shell configuration:
```bash
echo 'export MAILACL_GPG_KEY="YOUR_GPG_KEY_ID"' >> ~/.bashrc
echo 'export MAILACL_DOMAIN="yourdomain.com"' >> ~/.bashrc
source ~/.bashrc
```

---

## 📌 **How It Works**
MailACL generates a **deterministic, cryptographic signature** for the email prefix and appends it as a hash.

### **🗒️ Example Process**
#### **Generating an Email Address**
1. Run the script:
   ```bash
   ./mailacl.sh
   ```
2. Enter the **email prefix** (e.g., `eddie.foobar`):
   ```
   Enter an identifier to generate or an email to verify: eddie.foobar
   Enter hash length (default: 16, or type 'max' for maximum allowed'): 
   ```
3. **Generated Email Address**:
   ```
   Generated MailACL email: eddie.foobar-a1b2c3d4e5f6g7h8@yourdomain.com
   ```

#### **Verifying an Email Address**
1. Run the script:
   ```bash
   ./mailacl.sh
   ```
2. Enter the full **MailACL email**:
   ```
   Enter an identifier to generate or an email to verify: eddie.foobar-a1b2c3d4e5f6g7h8@yourdomain.com
   ```
3. **Verification Output**:
   ```
   📌 Prefix: eddie.foobar
   🔍 Expected: a1b2c3d4e5f6g7h8
   🔍 Computed: a1b2c3d4e5f6g7h8
   ✅ Verification successful.
   ```
   This confirms the **email was generated correctly** and **has not been tampered with**.

---

## 🔒 **Security Details**
- **SHA-512 HMAC Hashing** – Every email is signed with **HMAC-SHA-512**, making the hashes irreversible.  
- **PGP Private Key Protection** – Only the authorized key owner can generate valid email addresses.  
- **Deterministic Hashing** – The same input **always produces the same output**, preventing collisions.  
- **Length Control** – Hashes can be **16 to 64 characters** long to balance **security vs. readability**.  

---

## 📈 **Troubleshooting**
### **1️⃣ MailACL Script Fails to Run**
```bash
chmod +x mailacl.sh
```

### **2️⃣ GPG Key Not Found**
```bash
gpg --list-secret-keys
```

### **3️⃣ Incorrect Verification**
Ensure the email **wasn’t modified** after generation and rerun the script.

---

## 📚 **License**
MailACL is an **open-source project** licensed under the **GPL-3.0 License**.  
Feel free to **use, modify, and contribute!** 🚀  

---

## 👨‍💻 **Author**
**Robert Langhorn**  
👉 [GitHub](https://github.com/robertlanghorn)  

