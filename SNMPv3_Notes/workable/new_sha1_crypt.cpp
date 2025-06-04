#include "polarssl/sha1.h"
#include <string.h>
#include <stdint.h>

#define SHA1_BLOCK_SIZE 64
#define SHA1_OUTPUT_SIZE 20

void hmac_sha1_96(const uint8_t *key, size_t key_len,
                  const uint8_t *message, size_t msg_len,
                  uint8_t *output_12bytes) {
    uint8_t k_ipad[SHA1_BLOCK_SIZE];
    uint8_t k_opad[SHA1_BLOCK_SIZE];
    uint8_t temp_key[SHA1_OUTPUT_SIZE];
    uint8_t inner_hash[SHA1_OUTPUT_SIZE];
    size_t i;

    // Step 1: If key is longer than block size, hash it
    if (key_len > SHA1_BLOCK_SIZE) {
        sha1(key, key_len, temp_key);
        key = temp_key;
        key_len = SHA1_OUTPUT_SIZE;
    }

    // Step 2: Prepare inner and outer padded keys
    memset(k_ipad, 0x36, SHA1_BLOCK_SIZE);
    memset(k_opad, 0x5c, SHA1_BLOCK_SIZE);
    for (i = 0; i < key_len; i++) {
        k_ipad[i] ^= key[i];
        k_opad[i] ^= key[i];
    }

    // Step 3: Compute inner hash
    sha1_context ctx;0314
    sha1_starts(&ctx);
    sha1_update(&ctx, k_ipad, SHA1_BLOCK_SIZE);
    sha1_update(&ctx, message, msg_len);
    sha1_finish(&ctx, inner_hash);

    // Step 4: Compute outer hash
    sha1_starts(&ctx);
    sha1_update(&ctx, k_opad, SHA1_BLOCK_SIZE);
    sha1_update(&ctx, inner_hash, SHA1_OUTPUT_SIZE);
    sha1_finish(&ctx, inner_hash);  // reuse same buffer

    // Step 5: Truncate to 12 bytes (96 bits)
    memcpy(output_12bytes, inner_hash, 12);
}

#include <string.h>
#include <stdio.h>
#include "sha1.h"   // PolarSSL 2006-2009 SHA1 API

// Typical function to convert privPassword to localized AES key
void derive_aes_priv_key(const unsigned char *privPassword, size_t pw_len,
                        const unsigned char *engineID, size_t engineID_len,
                        unsigned char *privKey /* output 16 bytes */)
{
    sha1_context sha1_ctx;
    unsigned char ku[20]; // intermediate SHA1 result
    unsigned char digest[20];
    size_t i;
    size_t count = 0;
    const size_t password_repeat = 1048576; // 1MB

    // 1) Hash password repeated until 1MB
    sha1_starts(&sha1_ctx);
    while (count < password_repeat) {
        size_t chunk = (pw_len < (password_repeat - count)) ? pw_len : (password_repeat - count);
        sha1_update(&sha1_ctx, privPassword, chunk);
        count += chunk;
    }
    sha1_finish(&sha1_ctx, ku);

    // 2) Localize key with engineID:
    // Hash ku + engineID + ku
    sha1_starts(&sha1_ctx);
    sha1_update(&sha1_ctx, ku, 20);
    sha1_update(&sha1_ctx, engineID, engineID_len);
    sha1_update(&sha1_ctx, ku, 20);
    sha1_finish(&sha1_ctx, digest);

    // 3) Take first 16 bytes as AES key
    memcpy(privKey, digest, 16);
}

#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>  // for htonl

// global or static salt counter (64-bit)
static uint64_t salt_counter = 0;

// Initialize salt_counter randomly once per process start
void init_salt()
{
    salt_counter = (uint64_t)rand() << 32 | rand();
}

// Construct IV from engineBoots, engineTime and salt_counter
void generate_snmpv3_iv(uint32_t engineBoots, uint32_t engineTime, unsigned char *iv /* 16 bytes */)
{
    // First 4 bytes: engineBoots BE
    uint32_t boots_be = htonl(engineBoots);
    memcpy(iv, &boots_be, 4);

    // Next 4 bytes: engineTime BE
    uint32_t time_be = htonl(engineTime);
    memcpy(iv + 4, &time_be, 4);

    // Next 8 bytes: salt_counter BE
    uint64_t salt_be = __builtin_bswap64(salt_counter); // or implement manually
    memcpy(iv + 8, &salt_be, 8);

    // Increment salt for next message
    salt_counter++;
}

//=======================================================================================
#include <polarssl/aes.h>
#include <polarssl/sha1.h>
#include <cstdio>
#include <cstring>
#include <cstdlib>

// --------- SNMPv3 Key Derivation (RFC 3414 Section 2.6) ---------

void password_to_key_sha1(const char* password, const unsigned char* engineID, size_t engineIDLen, unsigned char* key) {
    unsigned char digest[SHA1_DIGEST_SIZE];
    unsigned char buf[1048576]; // 1MB buffer
    size_t passLen = strlen(password);

    // Fill buffer with repeated password
    for (size_t i = 0; i < sizeof(buf); i++) {
        buf[i] = password[i % passLen];
    }

    sha1(buf, sizeof(buf), digest);

    // Finalize with localized key: sha1(digest || engineID || digest)
    sha1_context ctx;
    sha1_starts(&ctx);
    sha1_update(&ctx, digest, sizeof(digest));
    sha1_update(&ctx, engineID, engineIDLen);
    sha1_update(&ctx, digest, sizeof(digest));
    sha1_finish(&ctx, key);
}

// --------- AES Encryption ---------

void aes_encrypt_snmpv3(const unsigned char* key, const unsigned char* iv,
                        const unsigned char* input, size_t len,
                        unsigned char* output) {
    aes_context aes;
    aes_setkey_enc(&aes, key, 128);
    aes_crypt_cbc(&aes, AES_ENCRYPT, len, iv, input, output);
}

void aes_decrypt_snmpv3(const unsigned char* key, const unsigned char* iv,
                        const unsigned char* input, size_t len,
                        unsigned char* output) {
    aes_context aes;
    aes_setkey_dec(&aes, key, 128);
    aes_crypt_cbc(&aes, AES_DECRYPT, len, iv, input, output);
}

// --------- IV Generation ---------
// Typically: 8-byte EngineBoots + EngineTime + 8-byte salt
void generate_iv(const unsigned char* engineBootsTime, const unsigned char* salt, unsigned char* iv) {
    memcpy(iv, engineBootsTime, 8);
    memcpy(iv + 8, salt, 8);
}

// --------- Simulated Packet Handling ---------

void print_hex(const char* label, const unsigned char* data, size_t len) {
    printf("%s (%zu bytes):\n", label, len);
    for (size_t i = 0; i < len; ++i) {
        printf("%02x ", data[i]);
        if ((i + 1) % 16 == 0) printf("\n");
    }
    printf("\n");
}

int main() {
    const char* password = "mypassword";
    unsigned char engineID[] = { 0x80, 0x00, 0x00, 0x00, 0x02, 0x03, 0x04, 0x05 }; // example
    unsigned char key[SHA1_DIGEST_SIZE];
    password_to_key_sha1(password, engineID, sizeof(engineID), key);

    print_hex("Localized Key", key, 16); // use only first 16 bytes for AES

    // Example encryption input (plaintext message)
    unsigned char plaintext[] = "Secret SNMP message.";
    unsigned char ciphertext[64];
    unsigned char decrypted[64];

    // IV generation
    unsigned char engineBootsTime[8] = {0,0,0,1,0,0,0,2}; // example
    unsigned char salt[8] = {0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x02}; // example
    unsigned char iv[16];
    generate_iv(engineBootsTime, salt, iv);

    aes_encrypt_snmpv3(key, iv, plaintext, 32, ciphertext);
    print_hex("Ciphertext", ciphertext, 32);

    aes_decrypt_snmpv3(key, iv, ciphertext, 32, decrypted);
    print_hex("Decrypted", decrypted, 32);

    return 0;
}
