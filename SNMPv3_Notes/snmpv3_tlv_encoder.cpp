/* SNMPv3 Message Structure with Length Tracking */

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#define MAX_FIELD_SIZE 256
#define MAX_VARBINDS   10

// Universal TLV encoder
int encode_tlv(uint8_t *buf, size_t bufsize, uint8_t type, const uint8_t *value, size_t length, size_t *encoded_len) {
    if (!buf || !encoded_len || length > (bufsize - 2)) return -1;
    size_t total_len = 0;

    buf[0] = type;
    total_len++;

    if (length < 128) {
        buf[1] = (uint8_t)length;
        memcpy(&buf[2], value, length);
        total_len += 1 + length;
    } else if (length <= 0xFF) {
        if (bufsize < 3 + length) return -1;
        buf[1] = 0x81;
        buf[2] = (uint8_t)length;
        memcpy(&buf[3], value, length);
        total_len += 2 + 1 + length;
    } else if (length <= 0xFFFF) {
        if (bufsize < 4 + length) return -1;
        buf[1] = 0x82;
        buf[2] = (length >> 8) & 0xFF;
        buf[3] = length & 0xFF;
        memcpy(&buf[4], value, length);
        total_len += 2 + 2 + length;
    } else {
        return -1; // Too large
    }

    *encoded_len = total_len;
    return 0;
}

typedef struct {
    uint8_t data[MAX_FIELD_SIZE];
    size_t  len;
} EncodedField;

// SNMPv3 HeaderData ::= SEQUENCE
//    msgID, msgMaxSize, msgFlags, msgSecurityModel
typedef struct {
    EncodedField msgID;
    EncodedField msgMaxSize;
    EncodedField msgFlags;
    EncodedField msgSecurityModel;
} HeaderData;

// USM Security Parameters
typedef struct {
    EncodedField msgAuthoritativeEngineID;
    EncodedField msgAuthoritativeEngineBoots;
    EncodedField msgAuthoritativeEngineTime;
    EncodedField msgUserName;
    EncodedField msgAuthenticationParameters;
    EncodedField msgPrivacyParameters;
} SecurityParameters;

// ScopedPDU ::= SEQUENCE {
//    contextEngineID, contextName, PDU
typedef struct {
    EncodedField contextEngineID;
    EncodedField contextName;
    EncodedField pdu;
} ScopedPDU;

// VarBind ::= SEQUENCE { name, value }
typedef struct {
    EncodedField name;
    EncodedField value;
} VarBind;

// VarBindList ::= SEQUENCE OF VarBind
typedef struct {
    VarBind varbinds[MAX_VARBINDS];
    size_t  count;
} VarBindList;

// PDU ::= SEQUENCE { requestID, errorStatus, errorIndex, varBindList }
typedef struct {
    EncodedField requestID;
    EncodedField errorStatus;
    EncodedField errorIndex;
    VarBindList  varBindList;
} PDU;

// SNMPv3 Message ::= SEQUENCE {
//    msgVersion, msgGlobalData, msgSecurityParams, msgData
typedef struct {
    EncodedField msgVersion;
    HeaderData   msgGlobalData;
    EncodedField msgSecurityParams;
    EncodedField msgData;
} SNMPv3Message;

// Note: Use TLV-encoding functions to build each EncodedField, track their lengths carefully, and wrap fields in appropriate ASN.1 structures.
// Encryption (AES128) is applied to the TLV-encoded ScopedPDU, which must then be wrapped in an OCTET STRING and assigned to msgData.
// Authentication (HMAC-SHA1) is applied to the entire SNMPv3 message with msgAuthenticationParameters set to 12 zero bytes during HMAC calculation.
