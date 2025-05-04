/* SNMPv3 Message Structure with Length Tracking and Full Builder */

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>

#define MAX_FIELD_SIZE 256
#define MAX_VARBINDS   10
#define TLV_SEQ         0x30
#define TLV_INT         0x02
#define TLV_OCTETSTR    0x04

typedef uint8_t u8_t;

// SNMP Object Identifier
typedef struct {
    uint32_t id[32];
    uint16_t len;
} snmp_obj_id;

// Legacy SNMP varbind structure
struct l_snmp_varbind {
    struct l_snmp_varbind *next;
    struct snmp_obj_id oid;
    u8_t type;
    uint16_t value_len;
    void *value;
};

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
        total_len += 3 + length;
    } else if (length <= 0xFFFF) {
        if (bufsize < 4 + length) return -1;
        buf[1] = 0x82;
        buf[2] = (length >> 8) & 0xFF;
        buf[3] = length & 0xFF;
        memcpy(&buf[4], value, length);
        total_len += 4 + length;
    } else {
        return -1; // Too large
    }

    *encoded_len = total_len;
    return 0;
}

// A reusable structure for holding TLV-encoded data
typedef struct {
    uint8_t data[MAX_FIELD_SIZE];
    size_t  len;
} EncodedField;

// HeaderData maps to the msgGlobalData field in SNMPv3Message
typedef struct {
    EncodedField msgID;
    EncodedField msgMaxSize;
    EncodedField msgFlags;
    EncodedField msgSecurityModel;
} HeaderData;

// SecurityParameters corresponds to the decoded content of msgSecurityParams in SNMPv3Message
typedef struct {
    EncodedField msgAuthoritativeEngineID;
    EncodedField msgAuthoritativeEngineBoots;
    EncodedField msgAuthoritativeEngineTime;
    EncodedField msgUserName;
    EncodedField msgAuthenticationParameters;
    EncodedField msgPrivacyParameters;
} SecurityParameters;

// ScopedPDU is the decoded content expected in msgData
typedef struct {
    EncodedField contextEngineID;
    EncodedField contextName;
    EncodedField pdu; // Typically represents an encoded PDU structure containing VarBindList and request metadata
} ScopedPDU;

// VarBind represents a name-value pair inside a PDU
typedef struct {
    EncodedField name;
    EncodedField value;
} VarBind;

// VarBindList is a list of variable bindings contained in a PDU
typedef struct {
    VarBind varbinds[MAX_VARBINDS];
    size_t  count;
} VarBindList;

// PDU corresponds to the decoded content of ScopedPDU.pdu
typedef struct {
    EncodedField requestID;
    EncodedField errorStatus;
    EncodedField errorIndex;
    VarBindList  varBindList;
} PDU;

// SNMPv3Message represents the full message
// - msgVersion: EncodedField holding version number
// - msgGlobalData: structured HeaderData (HeaderData struct)
// - msgSecurityParams: should contain a fully ASN.1-encoded SecurityParameters structure
// - msgData: usually holds a fully ASN.1-encoded ScopedPDU structure
typedef struct {
    EncodedField msgVersion;             // ASN.1 encoded version integer
    HeaderData   msgGlobalData;          // HeaderData struct
    EncodedField msgSecurityParams;      // Encoded ASN.1 SecurityParameters struct
    EncodedField msgData;                // Encoded ASN.1 ScopedPDU struct
} SNMPv3Message;

int build_snmpv3_message(const SNMPv3Message *msg, uint8_t *out_buf, size_t out_buf_size, size_t *out_len) {
    if (!msg || !out_buf || !out_len) return -1;

    uint8_t temp[MAX_FIELD_SIZE * 4];
    size_t offset = 0;

    memcpy(&temp[offset], msg->msgVersion.data, msg->msgVersion.len);
    offset += msg->msgVersion.len;

    uint8_t global_buf[MAX_FIELD_SIZE * 2];
    size_t global_len = 0;
    memcpy(&global_buf[global_len], msg->msgGlobalData.msgID.data, msg->msgGlobalData.msgID.len);
    global_len += msg->msgGlobalData.msgID.len;
    memcpy(&global_buf[global_len], msg->msgGlobalData.msgMaxSize.data, msg->msgGlobalData.msgMaxSize.len);
    global_len += msg->msgGlobalData.msgMaxSize.len;
    memcpy(&global_buf[global_len], msg->msgGlobalData.msgFlags.data, msg->msgGlobalData.msgFlags.len);
    global_len += msg->msgGlobalData.msgFlags.len;
    memcpy(&global_buf[global_len], msg->msgGlobalData.msgSecurityModel.data, msg->msgGlobalData.msgSecurityModel.len);
    global_len += msg->msgGlobalData.msgSecurityModel.len;

    size_t enc_global_len = 0;
    if (encode_tlv(&temp[offset], sizeof(temp) - offset, TLV_SEQ, global_buf, global_len, &enc_global_len) != 0) return -2;
    offset += enc_global_len;

    memcpy(&temp[offset], msg->msgSecurityParams.data, msg->msgSecurityParams.len);
    offset += msg->msgSecurityParams.len;

    memcpy(&temp[offset], msg->msgData.data, msg->msgData.len);
    offset += msg->msgData.len;

    size_t final_len = 0;
    if (encode_tlv(out_buf, out_buf_size, TLV_SEQ, temp, offset, &final_len) != 0) return -3;
    *out_len = final_len;
    return 0;
}

int encode_snmp_version(int version, EncodedField *field) {
    if (!field || version < 0 || version > 3) return -1;
    uint8_t v = (uint8_t)version;
    return encode_tlv(field->data, sizeof(field->data), TLV_INT, &v, 1, &field->len);
}

int encode_integer(int value, EncodedField *field) {
    if (!field) return -1;
    uint8_t val[4];
    size_t len = 0;
    if (value <= 0xFF) {
        val[0] = value & 0xFF;
        len = 1;
    } else if (value <= 0xFFFF) {
        val[0] = (value >> 8) & 0xFF;
        val[1] = value & 0xFF;
        len = 2;
    } else {
        val[0] = (value >> 24) & 0xFF;
        val[1] = (value >> 16) & 0xFF;
        val[2] = (value >> 8) & 0xFF;
        val[3] = value & 0xFF;
        len = 4;
    }
    return encode_tlv(field->data, sizeof(field->data), TLV_INT, val, len, &field->len);
}

int encode_octet_string(const uint8_t *str, size_t str_len, EncodedField *field) {
    if (!str || !field) return -1;
    return encode_tlv(field->data, sizeof(field->data), TLV_OCTETSTR, str, str_len, &field->len);
}

int encode_sequence(const uint8_t *content, size_t content_len, EncodedField *field) {
    if (!content || !field) return -1;
    return encode_tlv(field->data, sizeof(field->data), TLV_SEQ, content, content_len, &field->len);
}

// OID encoding length estimator
void snmp_asn1_enc_oid_cnt(const uint32_t *oid, uint16_t oid_len, uint16_t *octets_needed) {
    uint32_t sub_id;

    *octets_needed = 0;

    if (oid_len > 1) {
        (*octets_needed)++;
        oid_len -= 2;
        oid += 2;
    }

    while (oid_len > 0) {
        oid_len--;
        sub_id  = *oid;

        sub_id >>= 7;
        (*octets_needed)++;

        while (sub_id > 0) {
            sub_id >>= 7;
            (*octets_needed)++;
        }
        oid++;
    }
}

// Stub for computing varbind length
typedef struct {
    size_t name_len;
    size_t value_len;
    size_t total_len;
} snmp_varbind_len;

size_t snmp_varbind_length(struct snmp_varbind *varbind, snmp_varbind_len *len) {
    if (!varbind || !len) return 0;
    len->name_len = varbind->name.len;
    len->value_len = varbind->value.len;
    len->total_len = 2 + len->name_len + 2 + len->value_len; // minimal TLV overhead
    return len->total_len;
}
