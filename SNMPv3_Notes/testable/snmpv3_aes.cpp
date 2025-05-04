#include <string.h>
#include <stdint.h>

// Placeholder AES block size and key size
#define AES_BLOCK_SIZE 16
#define AES_KEY_SIZE   16

// You will need to replace this with actual AES encryption (e.g. from tiny-AES)
extern void aes_encrypt_block(const uint8_t *key, const uint8_t *input, uint8_t *output);

// Encrypt using AES-CFB-128 mode
int encrypt_privacy(const uint8_t *priv_key, const uint8_t *plaintext, size_t plaintext_len,
                    const uint8_t *engine_boots_time, uint8_t *ciphertext, uint8_t *priv_params_out) {
    if (!priv_key || !plaintext || !ciphertext || !engine_boots_time || !priv_params_out) return -1;

    // Compose IV: engineBoots (4 bytes) + engineTime (4 bytes) + salt (4 bytes)
    // For SNMPv3, priv_params_out = 8-byte random salt
    uint8_t iv[AES_BLOCK_SIZE];
    memcpy(iv, engine_boots_time, 8);       // First 8 bytes = engineBoots + engineTime
    memcpy(&iv[8], priv_params_out, 8);     // Next 8 bytes = salt/random

    uint8_t block[AES_BLOCK_SIZE];
    size_t i, nblocks = (plaintext_len + AES_BLOCK_SIZE - 1) / AES_BLOCK_SIZE;

    for (i = 0; i < nblocks; ++i) {
        aes_encrypt_block(priv_key, iv, block);

        size_t block_len = (plaintext_len - i * AES_BLOCK_SIZE > AES_BLOCK_SIZE)
                         ? AES_BLOCK_SIZE : (plaintext_len - i * AES_BLOCK_SIZE);

        for (size_t j = 0; j < block_len; ++j) {
            ciphertext[i * AES_BLOCK_SIZE + j] = plaintext[i * AES_BLOCK_SIZE + j] ^ block[j];
        }

        // For CFB, IV = previous ciphertext block
        memcpy(iv, &ciphertext[i * AES_BLOCK_SIZE], AES_BLOCK_SIZE);
    }

    return 0;
}

// To create a compatible aes_encrypt_block function for SNMPv3 privacy encryption (specifically AES-128 for usmAesCfb128Protocol as per RFC 3826), you'll need:

// A 16-byte key (derived from the user's password/key).

// A 16-byte IV (initialization vector) composed of the privacy parameters (salt) + part of the engine boots and engine time.

// AES in CFB mode, with a full 16-byte feedback (CFB-128).

// ✅ Is the salt required?
// Yes, the salt is required. It is used to generate the IV and must be unique for each encrypted message to maintain security. It is stored in the msgPrivacyParameters field and transmitted with the message.

// 🔐 aes_encrypt_block function (requires OpenSSL):
// c
// Copy
// Edit
#include <openssl/evp.h>
#include <string.h>

// Encrypts plaintext using AES-128-CFB with a 16-byte key and 16-byte IV.
// `plaintext` and `ciphertext` are both expected to be `len` bytes.
int aes_encrypt_block(const uint8_t *plaintext, size_t len,
                      const uint8_t *key, const uint8_t *iv,
                      uint8_t *ciphertext) {
    if (!plaintext || !key || !iv || !ciphertext || len == 0)
        return -1;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -2;

    int outlen1 = 0, outlen2 = 0;

    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_cfb128(), NULL, key, iv)) {
        EVP_CIPHER_CTX_free(ctx);
        return -3;
    }

    // Disable padding
    EVP_CIPHER_CTX_set_padding(ctx, 0);

    if (1 != EVP_EncryptUpdate(ctx, ciphertext, &outlen1, plaintext, len)) {
        EVP_CIPHER_CTX_free(ctx);
        return -4;
    }

    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + outlen1, &outlen2)) {
        EVP_CIPHER_CTX_free(ctx);
        return -5;
    }

    EVP_CIPHER_CTX_free(ctx);
    return outlen1 + outlen2; // returns the total bytes encrypted
}
// 🧂 Generating the IV with Salt
// The IV typically has this structure:

// python
// Copy
// Edit
// IV = engineBoots (4 bytes) || engineTime (4 bytes) || salt (8 bytes)
// Let me know if you'd like a matching decryption function or a function to generate the salt.

// Here's a C function to generate an 8-byte SNMPv3 salt (used for the msgPrivacyParameters field). This salt is incremented with each message and typically combined with engineBoots and engineTime to form the 16-byte AES IV (see RFC 3826).

// You can include this into your codebase, especially if you want to track the salt across SNMP messages.

// 🔐 Salt Generator Function
// c
// Copy
// Edit
#include <stdint.h>
#include <string.h>
#include <time.h>

// This should be persisted or tracked across SNMP messages
static uint64_t snmp_salt_counter = 0x0000000000000001;

// Generates 8-byte salt for AES encryption
void generate_snmpv3_salt(uint8_t salt_out[8]) {
    // Convert counter to 8-byte big-endian format
    for (int i = 0; i < 8; ++i) {
        salt_out[7 - i] = (snmp_salt_counter >> (8 * i)) & 0xFF;
    }

    // Increment for next use to ensure uniqueness
    snmp_salt_counter++;
}
// 📝 Notes:
// SNMPv3 requires the salt to be unique per encrypted message (never repeat).

// This function uses an internal static counter — you must persist this counter between runs (e.g., in non-volatile memory or a file).

// This is not a cryptographic RNG; it’s deterministic and suitable for generating IV material, not key generation.

// Would you like this integrated directly into your msgPrivacyParameters logic in the SNMPv3 builder?

