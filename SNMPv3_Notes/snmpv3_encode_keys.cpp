#include <string.h>
#include "lwip/sha1.h"

#define SNMP_KEYBUF_SIZE 64
#define SNMP_AUTH_KEY_LEN 20

#define SHA1_BLOCK_SIZE 64
#define SHA1_DIGEST_LENGTH 20

void sha1_hmac(const uint8_t *key, size_t key_len,
               const uint8_t *data, size_t data_len,
               uint8_t *out_digest) {
    uint8_t k_ipad[SHA1_BLOCK_SIZE] = {0};
    uint8_t k_opad[SHA1_BLOCK_SIZE] = {0};
    uint8_t tk[SHA1_DIGEST_LENGTH];
    uint8_t inner_digest[SHA1_DIGEST_LENGTH];
    SHA_CTX ctx;

    // Step 1: If key > block size, hash it
    if (key_len > SHA1_BLOCK_SIZE) {
        SHA1(key, key_len, tk);
        key = tk;
        key_len = SHA1_DIGEST_LENGTH;
    }

    // Step 2: Pad key to block size
    memcpy(k_ipad, key, key_len);
    memcpy(k_opad, key, key_len);
    for (int i = 0; i < SHA1_BLOCK_SIZE; i++) {
        k_ipad[i] ^= 0x36;
        k_opad[i] ^= 0x5c;
    }

    // Step 3: Inner hash
    SHA1_Init(&ctx);
    SHA1_Update(&ctx, k_ipad, SHA1_BLOCK_SIZE);
    SHA1_Update(&ctx, data, data_len);
    SHA1_Final(inner_digest, &ctx);

    // Step 4: Outer hash
    SHA1_Init(&ctx);
    SHA1_Update(&ctx, k_opad, SHA1_BLOCK_SIZE);
    SHA1_Update(&ctx, inner_digest, SHA1_DIGEST_LENGTH);
    SHA1_Final(out_digest, &ctx);
}


void snmpv3_derive_auth_key(const char* password, const uint8_t* engineID, uint8_t engineIDLen, uint8_t* out_authKey)
{
    uint8_t password_buf[1048576]; // 1MB buffer per RFC
    uint8_t digest[SNMP_AUTH_KEY_LEN];
    size_t pass_len = strlen(password);

    // 1. Fill buffer with repeated password
    for (size_t i = 0; i < sizeof(password_buf); ++i) {
        password_buf[i] = password[i % pass_len];
    }

    // 2. SHA1 hash over the full 1MB
    sha1_context ctx;
    sha1_starts(&ctx);
    sha1_update(&ctx, password_buf, sizeof(password_buf));
    sha1_finish(&ctx, digest);

    // 3. Localize with engineID: HMAC-SHA1 over engineID using digest as key
    sha1_hmac(digest, SNMP_AUTH_KEY_LEN, engineID, engineIDLen, out_authKey);
}


#define SNMP_PRIV_KEY_LEN 16

void snmpv3_derive_priv_key(const char* password, const uint8_t* engineID, uint8_t engineIDLen, uint8_t* out_privKey)
{
    uint8_t full_auth_key[SNMP_AUTH_KEY_LEN];
    snmpv3_derive_auth_key(password, engineID, engineIDLen, full_auth_key);

    // Truncate to first 16 bytes for AES128
    memcpy(out_privKey, full_auth_key, SNMP_PRIV_KEY_LEN);
}

int main() {
    const char* password = "snmpv3_pass";
    uint8_t engineID[] = {0x80, 0x00, 0x1F, 0x88, 0x80, 0x5A, 0x03, 0x02, 0x01};
    uint8_t engineIDLen = sizeof(engineID);

    uint8_t authKey[SNMP_AUTH_KEY_LEN];
    uint8_t privKey[SNMP_PRIV_KEY_LEN];

    // Derive keys
    snmpv3_derive_auth_key(password, engineID, engineIDLen, authKey);
    snmpv3_derive_priv_key(password, engineID, engineIDLen, privKey);

    // Print keys
    printf("Auth Key (SHA1 HMAC): ");
    for (int i = 0; i < SNMP_AUTH_KEY_LEN; ++i) {
        printf("%02X", authKey[i]);
    }
    printf("\n");

    printf("Priv Key (AES128): ");
    for (int i = 0; i < SNMP_PRIV_KEY_LEN; ++i) {
        printf("%02X", privKey[i]);
    }
    printf("\n");

    return 0;
}

