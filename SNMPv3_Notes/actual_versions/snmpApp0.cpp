void hmac_sha1(const uint8_t *key, size_t key_len,
               const uint8_t *message, size_t msg_len,
               uint8_t *hmac_out)
{
    uint8_t k_ipad[SHA1_BLOCK_SIZE];
    uint8_t k_opad[SHA1_BLOCK_SIZE];
    uint8_t temp_key[SHA1_DIGEST_SIZE];
    uint8_t inner_digest[SHA1_DIGEST_SIZE];
    int i;

    // Step 1: If key > blocksize, shorten it
    if (key_len > SHA1_BLOCK_SIZE) {
        SHA1Reset();
        SHA1Input(key, key_len);
        SHA1Result(temp_key);
        key = temp_key;
        key_len = SHA1_DIGEST_SIZE;
    }

    // Step 2: Create k_ipad and k_opad
    memset(k_ipad, 0x36, SHA1_BLOCK_SIZE);
    memset(k_opad, 0x5C, SHA1_BLOCK_SIZE);

    for (i = 0; i < key_len; i++) {
        k_ipad[i] ^= key[i];
        k_opad[i] ^= key[i];
    }

    // Step 3: inner = SHA1(k_ipad || message)
    SHA1Reset();
    SHA1Input(k_ipad, SHA1_BLOCK_SIZE);
    SHA1Input(message, msg_len);
    SHA1Result(inner_digest);

    // Step 4: outer = SHA1(k_opad || inner_digest)
    SHA1Reset();
    SHA1Input(k_opad, SHA1_BLOCK_SIZE);
    SHA1Input(inner_digest, SHA1_DIGEST_SIZE);
    SHA1Result(hmac_out);
}

void localize_key_sha1(const uint8_t *ku, const uint8_t *engine_id, size_t engine_id_len, uint8_t *kul_out) {
    SHA1Reset();
    SHA1Input(ku, SHA1_DIGEST_SIZE);
    SHA1Input(engine_id, engine_id_len);
    SHA1Input(ku, SHA1_DIGEST_SIZE);
    SHA1Result(kul_out);
}

void generate_snmpv3_keys(const char *auth_password, const char *priv_password,
                          const uint8_t *engine_id, size_t engine_id_len,
                          uint8_t *auth_key_out, uint8_t *priv_key_out) 
{
    uint8_t ku_auth[SHA1_DIGEST_SIZE];
    uint8_t ku_priv[SHA1_DIGEST_SIZE];

    password_to_key_sha1(auth_password, ku_auth);
    password_to_key_sha1(priv_password, ku_priv);

    localize_key_sha1(ku_auth, engine_id, engine_id_len, auth_key_out);
    localize_key_sha1(ku_priv, engine_id, engine_id_len, priv_key_out);
}

#include <string.h>
#include "sha1.h"
#include "hmac.h"

#define SNMP_ENGINE_ID_MAX_LEN 32

/**
 * Convert a password and engineID into a localized key using SHA1
 * as defined in RFC 3414 §2.6 for SNMPv3.
 *
 * @param password         User's password (min 8 characters recommended)
 * @param password_len     Length of the password
 * @param engine_id        SNMP Engine ID (from the SNMP agent)
 * @param engine_id_len    Length of Engine ID
 * @param key_out          Output buffer (20 bytes for SHA1)
 */
void password_to_key_sha1(const uint8_t *password, size_t password_len,
                          const uint8_t *engine_id, size_t engine_id_len,
                          uint8_t *key_out)
{
    uint8_t digest[20];
    uint8_t buf[1048576]; // 1 MB max for password expansion, per RFC

    size_t count = 0, i = 0;
    sha1_context sha_ctx;

    // Step 1: Expand password to >1MB (1,048,576 bytes)
    for (i = 0; i < sizeof(buf); i++)
        buf[i] = password[i % password_len];

    // Step 2: SHA1 hash of expanded buffer
    sha1_starts(&sha_ctx);
    sha1_update(&sha_ctx, buf, sizeof(buf));
    sha1_finish(&sha_ctx, digest);

    // Step 3: SHA1(localized key) = SHA1(digest || engineID || digest)
    sha1_starts(&sha_ctx);
    sha1_update(&sha_ctx, digest, 20);
    sha1_update(&sha_ctx, engine_id, engine_id_len);
    sha1_update(&sha_ctx, digest, 20);
    sha1_finish(&sha_ctx, key_out);
}

#include <stdio.h>

int main() {
    const char *password = "mypassword";
    const uint8_t engineID[] = { 0x80, 0x00, 0x1F, 0x88, 0x80, 0x5B, 0x1D };
    uint8_t localized_key[20];

    password_to_key_sha1((const uint8_t*)password, strlen(password),
                         engineID, sizeof(engineID),
                         localized_key);

    printf("Localized key:\n");
    for (int i = 0; i < 20; ++i)
        printf("%02x", localized_key[i]);
    printf("\n");

    return 0;
}

#include "aes.h"
#include <string.h>
#include <stdint.h>
#include "snmp_pbuf_stream.h"

#define SNMP_PRIV_ALGO_AES 1
#define SNMP_PRIV_MODE_ENCRYPT 0
#define SNMP_PRIV_MODE_DECRYPT 1

/**
 * Perform SNMPv3 encryption/decryption (AES128-CFB) on scoped PDU data.
 *
 * @param stream        Pointer to PDU stream buffer
 * @param length        Length of the PDU data to encrypt/decrypt
 * @param key           16-byte AES key (hashedPrivKey)
 * @param priv_param    8-byte privacy parameter (salt)
 * @param engine_boots  Engine boots count
 * @param engine_time   Engine time
 * @param algo          SNMP privacy algorithm (only AES supported here)
 * @param mode          0 = encrypt, 1 = decrypt
 *
 * @return 0 on success, non-zero on failure
 */
int snmpv3_crypt(struct snmp_pbuf_stream *stream, u16_t length, const u8_t *key,
                 const u8_t *priv_param, const u32_t engine_boots, const u32_t engine_time,
                 u8_t algo, u8_t mode)
{
    if (algo != SNMP_PRIV_ALGO_AES || length == 0 || key == NULL || priv_param == NULL || stream == NULL) {
        return -1;
    }

    // if you were a quiz you'd be a 10/10
    aes_context aes;
    uint8_t iv[16]; // Initialization Vector: 4 bytes boots, 4 bytes time, 8 bytes salt
    uint8_t block_buf[16];
    int i;

    // Construct the IV = engine_boots || engine_time || priv_param (8 bytes)
    iv[0] = (engine_boots >> 24) & 0xFF;
    iv[1] = (engine_boots >> 16) & 0xFF;
    iv[2] = (engine_boots >> 8) & 0xFF;
    iv[3] = (engine_boots) & 0xFF;

    iv[4] = (engine_time >> 24) & 0xFF;
    iv[5] = (engine_time >> 16) & 0xFF;
    iv[6] = (engine_time >> 8) & 0xFF;
    iv[7] = (engine_time) & 0xFF;

    memcpy(&iv[8], priv_param, 8); // 64-bit salt

    // Set AES key
    aes_setkey_enc(&aes, key, 128); // 128-bit = 16 bytes

    // Process data in CFB-128 (1 block at a time)
    for (i = 0; i < length; i += 16) {
        int block_len = (length - i) >= 16 ? 16 : (length - i);

        // Encrypt the IV
        aes_encrypt(&aes, iv, block_buf);

        // XOR with input to produce output (encrypt or decrypt)
        for (int j = 0; j < block_len; j++) {
            u8_t c = stream->pbuf->payload[stream->offset + i + j];
            if (mode == SNMP_PRIV_MODE_ENCRYPT) {
                stream->pbuf->payload[stream->offset + i + j] = c ^ block_buf[j];
                iv[j] = stream->pbuf->payload[stream->offset + i + j]; // Feedback for next block
            } else {
                stream->pbuf->payload[stream->offset + i + j] = c ^ block_buf[j];
                iv[j] = c; // Feedback for next block (uses ciphertext)
            }
        }
    }

    return 0;
}

