#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>

// Add encryption headers
#include "polarssl/aes.h"   // For PolarSSL AES encryption
#include "crypto.h"         // Tiva C Crypto header assumed present

#define MAX_FIELD_SIZE 256
#define MAX_VARBINDS   10
#define TLV_SEQ         0x30
#define TLV_INT         0x02
#define TLV_OCTETSTR    0x04

// (Other structures and functions remain unchanged...)

// Print a buffer as hex
void print_hex(const uint8_t *buf, size_t len) {
    for (size_t i = 0; i < len; ++i)
        printf("%02X ", buf[i]);
    printf("\n");
}

int main() {
    SNMPv3Message msg = {0};
    SecurityParameters secParams = {0};
    ScopedPDU scoped = {0};
    uint8_t key[16] = {
        0x01, 0x02, 0x03, 0x04,
        0x05, 0x06, 0x07, 0x08,
        0x09, 0x0A, 0x0B, 0x0C,
        0x0D, 0x0E, 0x0F, 0x10
    };

    // Fill message version (SNMPv3 is 3)
    uint8_t version = 0x03;
    encode_tlv(msg.msgVersion.data, sizeof(msg.msgVersion.data), TLV_INT, &version, 1, &msg.msgVersion.len);

    // Fill HeaderData fields
    uint8_t msgID = 0x01, maxSize[2] = {0x05, 0xDC}, flags = 0x07, secModel = 0x03;
    encode_tlv(msg.msgGlobalData.msgID.data, sizeof(msg.msgGlobalData.msgID.data), TLV_INT, &msgID, 1, &msg.msgGlobalData.msgID.len);
    encode_tlv(msg.msgGlobalData.msgMaxSize.data, sizeof(msg.msgGlobalData.msgMaxSize.data), TLV_INT, maxSize, 2, &msg.msgGlobalData.msgMaxSize.len);
    encode_tlv(msg.msgGlobalData.msgFlags.data, sizeof(msg.msgGlobalData.msgFlags.data), TLV_OCTETSTR, &flags, 1, &msg.msgGlobalData.msgFlags.len);
    encode_tlv(msg.msgGlobalData.msgSecurityModel.data, sizeof(msg.msgGlobalData.msgSecurityModel.data), TLV_INT, &secModel, 1, &msg.msgGlobalData.msgSecurityModel.len);

    // Fill Security Parameters
    const char *engineID = "engine123";
    const char *boots = "\x00\x00\x00\x01";
    const char *time = "\x00\x00\x00\x0A";
    const char *user = "admin";
    const char *authParam = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";  // dummy
    const char *privParam = "\x00\x01\x02\x03\x04\x05\x06\x07";

    memcpy(secParams.msgAuthoritativeEngineID.data, engineID, strlen(engineID));
    secParams.msgAuthoritativeEngineID.len = strlen(engineID);
    memcpy(secParams.msgAuthoritativeEngineBoots.data, boots, 4);
    secParams.msgAuthoritativeEngineBoots.len = 4;
    memcpy(secParams.msgAuthoritativeEngineTime.data, time, 4);
    secParams.msgAuthoritativeEngineTime.len = 4;
    memcpy(secParams.msgUserName.data, user, strlen(user));
    secParams.msgUserName.len = strlen(user);
    memcpy(secParams.msgAuthenticationParameters.data, authParam, 12);
    secParams.msgAuthenticationParameters.len = 12;
    memcpy(secParams.msgPrivacyParameters.data, privParam, 8);
    secParams.msgPrivacyParameters.len = 8;

    // Fill Scoped PDU
    const char *ctxEngineID = "engine123";
    const char *ctxName = "context";

    memcpy(scoped.contextEngineID.data, ctxEngineID, strlen(ctxEngineID));
    scoped.contextEngineID.len = strlen(ctxEngineID);
    memcpy(scoped.contextName.data, ctxName, strlen(ctxName));
    scoped.contextName.len = strlen(ctxName);

    // Dummy PDU content for Scoped PDU
    const uint8_t dummy_pdu[] = { TLV_SEQ, 0x02, 0x00, 0x05 };  // Simplified dummy sequence
    memcpy(scoped.pdu.data, dummy_pdu, sizeof(dummy_pdu));
    scoped.pdu.len = sizeof(dummy_pdu);

    // Encode and encrypt, then build the message
    snmp_manager_send(&msg, &secParams, &scoped, key, sizeof(key));

    // Compose final message sequence
    uint8_t tmp[1024];
    size_t offset = 0, len;

    encode_tlv(tmp + offset, sizeof(tmp) - offset, TLV_INT, msg.msgVersion.data + 2, 1, &len);
    offset += len;

    encode_tlv(tmp + offset, sizeof(tmp) - offset, TLV_SEQ, msg.msgGlobalData.msgID.data, msg.msgGlobalData.msgID.len, &len);
    offset += len;
    encode_tlv(tmp + offset, sizeof(tmp) - offset, TLV_SEQ, msg.msgGlobalData.msgMaxSize.data, msg.msgGlobalData.msgMaxSize.len, &len);
    offset += len;
    encode_tlv(tmp + offset, sizeof(tmp) - offset, TLV_SEQ, msg.msgGlobalData.msgFlags.data, msg.msgGlobalData.msgFlags.len, &len);
    offset += len;
    encode_tlv(tmp + offset, sizeof(tmp) - offset, TLV_SEQ, msg.msgGlobalData.msgSecurityModel.data, msg.msgGlobalData.msgSecurityModel.len, &len);
    offset += len;

    encode_tlv(tmp + offset, sizeof(tmp) - offset, TLV_OCTETSTR, msg.msgSecurityParams.data + 2, msg.msgSecurityParams.len - 2, &len);
    offset += len;
    encode_tlv(tmp + offset, sizeof(tmp) - offset, TLV_OCTETSTR, msg.msgData.data + 2, msg.msgData.len - 2, &len);
    offset += len;

    uint8_t final_msg[1024];
    size_t final_len;
    encode_tlv(final_msg, sizeof(final_msg), TLV_SEQ, tmp, offset, &final_len);

    printf("Final SNMPv3 message (hex):\n");
    print_hex(final_msg, final_len);

    return 0;
}
