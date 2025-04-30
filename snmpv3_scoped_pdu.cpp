// Assumes: you have AES128 key (16 bytes), privParams (8 bytes), and a plaintext ScopedPDU TLV buffer
// Dependencies: OpenSSL (or any AES implementation)

#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/evp.h>

#define AES_BLOCK_SIZE 16

// Structure to hold encrypted result
typedef struct {
    uint8_t ciphertext[256]; // Adjust as needed
    size_t  length;          // Actual length of ciphertext
} EncryptedScopedPDU;

// Pads input buffer to AES block size boundary (PKCS#7 style padding)
size_t pad_buffer(uint8_t* input, size_t len) {
    size_t pad_len = AES_BLOCK_SIZE - (len % AES_BLOCK_SIZE);
    for (size_t i = 0; i < pad_len; ++i) {
        input[len + i] = (uint8_t)pad_len;
    }
    return len + pad_len;
}

// Encrypts the given plaintext (already TLV encoded) using AES128-CFB
// iv = privParams || privParams (16 bytes), key = 16 bytes
int encrypt_scoped_pdu(const uint8_t* plaintext, size_t plaintext_len,
                       const uint8_t* key,
                       const uint8_t* privParams,
                       EncryptedScopedPDU* out) {

    uint8_t iv[AES_BLOCK_SIZE];
    memcpy(iv, privParams, 8);
    memcpy(iv + 8, privParams, 8);

    uint8_t padded[256];  // Ensure it's big enough
    memcpy(padded, plaintext, plaintext_len);
    size_t padded_len = pad_buffer(padded, plaintext_len);

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    int len;

    if (!EVP_EncryptInit_ex(ctx, EVP_aes_128_cfb128(), NULL, key, iv)) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    if (!EVP_EncryptUpdate(ctx, out->ciphertext, &len, padded, padded_len)) {
        EVP_CIPHER_CTX_free(ctx);
        return -2;
    }
    out->length = len;

    EVP_CIPHER_CTX_free(ctx);
    return 0;
}

// After this, wrap ciphertext in ASN.1 OCTET STRING:
// 0x04 <length> <ciphertext>
