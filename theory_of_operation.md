# MailACL theory of operation

## Purpose

MailACL creates deterministic email aliases whose local parts contain a truncated HMAC tag. Readable identifiers can follow a simple convention: use an underscore for a person's name (`john_doe`) and a hostname for a site (`google.com`).

```text
<identifier>-<tag>@<configured-domain>
```

The tag lets a key holder check whether an identifier is consistent with the configured secret-derived key without storing a database of issued aliases. A service-specific identifier can therefore help identify where an address was shared.

MailACL does not create an OpenPGP signature and does not authenticate email messages or senders. GPG is used only as the source of stable secret material.

## Key derivation

MailACL exports the configured GPG secret key and computes:

```text
export_bytes = gpg --export-secret-keys MAILACL_GPG_KEY
hmac_key    = lowercase_hex(SHA-512(export_bytes))
```

The 128 ASCII hexadecimal characters—not the 64 raw digest bytes—are used as the HMAC key. This construction is retained exactly for compatibility with previously generated aliases.

The export must succeed and contain at least one byte. MailACL rejects failed or empty exports instead of deriving a key from empty input. Secret export bytes and the derived HMAC key are not written to repository files. The derived key is fed to the Python HMAC implementation through standard input rather than exposed in a process argument.

Because the derivation uses the serialized GPG secret-key export, changes to that export can change all generated tags. Back up the key and test compatibility before changing it.

## Tag computation

For an identifier, MailACL computes:

```text
digest = HMAC-SHA-512(hmac_key, identifier_bytes)
```

The configured output encoding is then applied:

- `base36` (current default): interpret the 512-bit digest as a big-endian integer, encode with `0-9a-z`, left-pad to a fixed width of 100 characters, and take the requested suffix;
- `base32` (transitional): standard Base32 without `=` padding, lowercase, prefix-truncated;
- `base64` (transitional): standard case-sensitive Base64 without `=` padding, prefix-truncated;
- `hex` (legacy): lowercase hexadecimal, prefix-truncated.

New aliases default to a 10-character Base36 suffix. The ASCII identifier and one separating hyphen share the RFC 5321 64-byte local-part limit with the tag, so MailACL reduces an oversized requested tag to the available space. Verification independently rejects any supplied local part longer than 64 bytes before checking its tag.

The configured domain and output encoding are not HMAC inputs. For a fixed key and identifier, different domains receive the same underlying tag characters for the same encoding and truncation rule.

## Why Base36 uses suffix truncation

Earlier formats kept the left-hand prefix of their encoding. Current Base36 aliases keep the right-hand suffix. This permits manual shortening by deleting characters immediately after the final hyphen while retaining the characters nearest the domain:

```text
identifier-abcdefghij@example.com
identifier-cdefghij@example.com
```

These are formatting examples, not valid tags for any particular key. Deleting characters immediately before `@` keeps the wrong end and will not verify as a canonical shortened Base36 tag.

## Verification

Verification performs these steps:

1. Require the address domain to match `MAILACL_DOMAIN` case-insensitively.
2. Require the local part to fit the RFC 5321 64-byte limit.
3. Split the local part at its final hyphen. Everything before it is the identifier; everything after it is the supplied tag.
4. Recompute candidate tags of the supplied length.
5. Compare in compatibility order:
   - current Base36 suffix, case-normalized;
   - transitional Base36 prefix, case-normalized;
   - transitional Base32 prefix, case-normalized;
   - legacy hexadecimal prefix, case-normalized;
   - transitional Base64 prefix, exact-case only.
6. Report the matched format and an effective-entropy estimate where its distribution supports one, or identify the biased transitional Base36-prefix case without assigning it a uniform estimate. Otherwise, fail verification.

Splitting at the final hyphen allows identifiers themselves to contain hyphens.

## Entropy and truncation

A uniformly distributed tag over an alphabet of size `B` and length `L` has approximately:

```text
L × log2(B) bits
```

For Base36:

| Length | Approximate search space |
|---:|---:|
| 1 | 5.17 bits |
| 4 | 20.68 bits |
| 7 | 36.19 bits |
| 10 | 51.70 bits |
| 13 | 67.21 bits |

MailACL's report uses effective min-entropy and never exceeds the 512 bits supplied by HMAC-SHA-512. For current Base36 suffixes, it accounts for the at-most-one-preimage imbalance created by reducing a 512-bit integer modulo `36^L`; at supported local-part lengths this is extremely close to `L × log2(36)`. Hexadecimal, Base32, and Base64 prefixes expose digest bits directly, with the final partial character and the 512-bit ceiling accounted for.

Transitional fixed-width Base36 **prefixes** are different: leading characters are biased by zero padding and by the range of a 512-bit integer. MailACL retains them for compatibility but labels them transitional and does not report a uniform entropy estimate. One-million-guess probabilities use a cancellation-safe calculation so very small nonzero probabilities are not displayed as zero.

Truncation does not weaken HMAC-SHA-512 itself, but it reduces the effort required to guess any accepted tag. Short values are supported for restrictive forms and are accompanied by explicit warnings. They should not be treated as strong proof.

## Security properties and boundaries

MailACL provides:

- deterministic tag generation from secret-derived key material;
- stateless verification of identifiers;
- detection of accidental edits or random invented aliases, subject to tag length;
- compatibility with historical MailACL encodings.

MailACL does not provide:

- OpenPGP signatures over aliases or messages;
- authentication of a message sender;
- prevention of forwarding, phishing, mailbox compromise, or address disclosure;
- proof that a particular recipient caused a leak;
- revocation or allow-list enforcement by itself;
- protection after the GPG secret key or derived HMAC key is exposed;
- collision prevention or unforgeability beyond the selected truncated tag length.

A mail system must separately decide how verified aliases are accepted, rejected, routed, or revoked. MailACL only generates and checks the alias format.
