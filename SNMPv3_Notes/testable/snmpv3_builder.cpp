#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>

#define MAX_FIELD_SIZE 256
#define MAX_VARBINDS   10
#define TLV_SEQ         0x30
#define TLV_INT         0x02
#define TLV_OCTETSTR    0x04

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

// l_snmp_varbind
// struct l_snmp_varbind {
//     struct l_snmp_varbind *next;
//     struct snmp_obj_id oid;
//     u8_t type;
//     u16_t value_len;
//     void *value;
// };

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
    EncodedField msgSecurityParams; // use SecurityParameters
    EncodedField msgData;
} SNMPv3Message;

// Serialize SNMPv3Message to output buffer
int build_scoped_pdu(const ScopedPDU *scopedPDU, EncodedField *out) {
    if (!scopedPDU || !out) return -1;

    uint8_t buffer[MAX_FIELD_SIZE * 3];
    size_t offset = 0;

    if (offset + scopedPDU->contextEngineID.len > sizeof(buffer)) return -2;
    memcpy(&buffer[offset], scopedPDU->contextEngineID.data, scopedPDU->contextEngineID.len);
    offset += scopedPDU->contextEngineID.len;

    if (offset + scopedPDU->contextName.len > sizeof(buffer)) return -3;
    memcpy(&buffer[offset], scopedPDU->contextName.data, scopedPDU->contextName.len);
    offset += scopedPDU->contextName.len;

    if (offset + scopedPDU->pdu.len > sizeof(buffer)) return -4;
    memcpy(&buffer[offset], scopedPDU->pdu.data, scopedPDU->pdu.len);
    offset += scopedPDU->pdu.len;

    // Wrap in SEQUENCE
    return encode_tlv(out->data, sizeof(out->data), TLV_SEQ, buffer, offset, &out->len);
}

int build_pdu(const PDU *pdu, EncodedField *out) {
    if (!pdu || !out) return -1;

    uint8_t buffer[MAX_FIELD_SIZE * 4];
    size_t offset = 0;

    // Copy requestID, errorStatus, errorIndex
    memcpy(&buffer[offset], pdu->requestID.data, pdu->requestID.len);
    offset += pdu->requestID.len;
    memcpy(&buffer[offset], pdu->errorStatus.data, pdu->errorStatus.len);
    offset += pdu->errorStatus.len;
    memcpy(&buffer[offset], pdu->errorIndex.data, pdu->errorIndex.len);
    offset += pdu->errorIndex.len;

    // Encode varBindList
    uint8_t varbind_buffer[MAX_FIELD_SIZE * 2];
    size_t varbind_len = 0;
    for (size_t i = 0; i < pdu->varBindList.count; ++i) {
        size_t varbind_encoded_len = 0;
        encode_tlv(varbind_buffer, sizeof(varbind_buffer), TLV_SEQ, pdu->varBindList.varbinds[i].name.data, pdu->varBindList.varbinds[i].name.len, &varbind_encoded_len);
        memcpy(&buffer[offset], varbind_buffer, varbind_encoded_len);
        offset += varbind_encoded_len;
    }

    return encode_tlv(out->data, sizeof(out->data), TLV_SEQ, buffer, offset, &out->len);
}

// Encode SNMP Version
int encode_snmp_version(int version, EncodedField *field) {
    if (!field || version < 0 || version > 3) return -1;
    uint8_t v = (uint8_t)version;
    return encode_tlv(field->data, sizeof(field->data), TLV_INT, &v, 1, &field->len);
}

// Build SNMPv3 Message
int build_snmpv3_message(const SNMPv3Message *msg, uint8_t *out_buf, size_t out_buf_size, size_t *out_len) {
    if (!msg || !out_buf || !out_len) return -1;

    uint8_t temp[MAX_FIELD_SIZE * 4];
    size_t offset = 0;

    // Copy version
    memcpy(&temp[offset], msg->msgVersion.data, msg->msgVersion.len);
    offset += msg->msgVersion.len;

    // Build globalData SEQUENCE
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

    // Security Params
    memcpy(&temp[offset], msg->msgSecurityParams.data, msg->msgSecurityParams.len);
    offset += msg->msgSecurityParams.len;

    // msgData
    memcpy(&temp[offset], msg->msgData.data, msg->msgData.len);
    offset += msg->msgData.len;

    // Wrap entire message
    size_t final_len = 0;
    if (encode_tlv(out_buf, out_buf_size, TLV_SEQ, temp, offset, &final_len) != 0) return -3;
    *out_len = final_len;
    return 0;
}

int main() {
    // Dummy example SNMPv3Message
    SNMPv3Message msg;
    
    // Set up msgVersion
    encode_snmp_version(3, &msg.msgVersion);

    // Set up msgGlobalData
    msg.msgGlobalData.msgID.len = 4;
    memcpy(msg.msgGlobalData.msgID.data, "1234", 4);
    msg.msgGlobalData.msgMaxSize.len = 2;
    memcpy(msg.msgGlobalData.msgMaxSize.data, "\x00\xFF", 2);
    msg.msgGlobalData.msgFlags.len = 1;
    memcpy(msg.msgGlobalData.msgFlags.data, "\x01", 1);
    msg.msgGlobalData.msgSecurityModel.len = 1;
    memcpy(msg.msgGlobalData.msgSecurityModel.data, "\x02", 1);
}

int main() {
    SNMPv3Message msg;

    // Encode SNMP version (version 3)
    if (encode_snmp_version(3, &msg.msgVersion) != 0) {
        printf("Failed to encode SNMP version\n");
        return 1;
    }

    // Fill Global Header
    encode_integer(1234, &msg.msgGlobalData.msgID);               // msgID
    encode_integer(65535, &msg.msgGlobalData.msgMaxSize);         // msgMaxSize
    encode_octet_string((uint8_t*)"\x07", 1, &msg.msgGlobalData.msgFlags); // msgFlags (reportable)
    encode_integer(3, &msg.msgGlobalData.msgSecurityModel);       // SNMPv3 USM

    // Encode dummy Security Parameters (normally ASN.1 encoded)
    const char *dummy_sec = "secparams";
    encode_octet_string((const uint8_t*)dummy_sec, strlen(dummy_sec), &msg.msgSecurityParams);

    // Encode dummy ScopedPDU (normally ASN.1 encoded)
    const char *dummy_pdu = "scopedpdu";
    encode_octet_string((const uint8_t*)dummy_pdu, strlen(dummy_pdu), &msg.msgData);

    // Final buffer
    uint8_t buffer[1024];
    size_t final_len = 0;
    if (build_snmpv3_message(&msg, buffer, sizeof(buffer), &final_len) != 0) {
        printf("Failed to build SNMPv3 message\n");
        return 2;
    }

    // Print hex output
    printf("SNMPv3 message (%zu bytes):\n", final_len);
    for (size_t i = 0; i < final_len; ++i) {
        printf("%02X ", buffer[i]);
    }
    printf("\n");

    return 0;
}

// ⛳ Summary of ASN.1 Requirements

// Field	ASN.1 Type	Notes
// msgAuthoritativeEngineID	OCTET STRING	As provided by agent (or default)
// msgAuthoritativeEngineBoots	INTEGER	Boot count (integer, usually 0 or more)
// msgAuthoritativeEngineTime	INTEGER	Time since boot (seconds)
// msgUserName	OCTET STRING	The user name
// msgAuthenticationParameters	OCTET STRING	Always 12 bytes; set to 00...00 before HMAC, overwrite with result
// msgPrivacyParameters	OCTET STRING	8-byte salt/IV
// Would you like me to:

// Add helper code that generates the zero-filled msgAuthenticationParameters?

// Add a full HMAC-insertion routine that scans your buffer and overwrites those 12 bytes in place?

struct pbuf {
    struct pbuf *next;
    void *payload;

    u16_t tot_len;
    u16_t len;
    u8_t type;
    u8_t flags;
    u8_t if_idx;
    u16_t ref;
};


snmp_asn1_enc_oid_cnt(const u32_t *oid, u16_t oid_len, u16_t *octets_needed) {
    u32_t sub_id;

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