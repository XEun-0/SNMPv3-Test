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

// TLV structure wrapper
typedef struct {
    uint8_t data[MAX_FIELD_SIZE];
    size_t len;
} TLVField;

// GlobalData, SecurityParameters, ScopedPDU structs
typedef struct {
    TLVField msgID;
    TLVField msgMaxSize;
    TLVField msgFlags;
    TLVField msgSecurityModel;
} GlobalData;

typedef struct {
    TLVField msgAuthoritativeEngineID;
    TLVField msgAuthoritativeEngineBoots;
    TLVField msgAuthoritativeEngineTime;
    TLVField msgUserName;
    TLVField msgAuthenticationParameters;
    TLVField msgPrivacyParameters;
} SecurityParameters;

typedef struct {
    TLVField contextEngineID;
    TLVField contextName;
    TLVField pdu;  // Raw PDU (could be GetRequest, etc.)
} ScopedPDU;

typedef struct {
    TLVField msgVersion;
    GlobalData msgGlobalData;
    SecurityParameters secParams;
    ScopedPDU scopedPDU;
} SNMPv3Message;

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

// Encoder for SNMPv3 message
int snmpv3_encode_message(const SNMPv3Message *msg, uint8_t *out_buf, size_t out_size, size_t *encoded_len) {
    if (!msg || !out_buf || !encoded_len) return -1;

    uint8_t buffer[2048];
    size_t offset = 0, len = 0, total_len = 0;
    uint8_t temp[512];
    size_t temp_len = 0;

    // Encode version
    if (encode_tlv(temp, sizeof(temp), TLV_INT, msg->msgVersion.data, msg->msgVersion.len, &temp_len) < 0) return -1;
    memcpy(&buffer[offset], temp, temp_len); offset += temp_len;

    // Encode GlobalData as SEQUENCE
    uint8_t global_data[512];
    size_t g_offset = 0;
    if (encode_tlv(&global_data[g_offset], sizeof(global_data)-g_offset, TLV_INT, msg->msgGlobalData.msgID.data, msg->msgGlobalData.msgID.len, &len) < 0) return -1;
    g_offset += len;
    if (encode_tlv(&global_data[g_offset], sizeof(global_data)-g_offset, TLV_INT, msg->msgGlobalData.msgMaxSize.data, msg->msgGlobalData.msgMaxSize.len, &len) < 0) return -1;
    g_offset += len;
    if (encode_tlv(&global_data[g_offset], sizeof(global_data)-g_offset, TLV_OCTETSTR, msg->msgGlobalData.msgFlags.data, msg->msgGlobalData.msgFlags.len, &len) < 0) return -1;
    g_offset += len;
    if (encode_tlv(&global_data[g_offset], sizeof(global_data)-g_offset, TLV_INT, msg->msgGlobalData.msgSecurityModel.data, msg->msgGlobalData.msgSecurityModel.len, &len) < 0) return -1;
    g_offset += len;
    if (encode_tlv(temp, sizeof(temp), TLV_SEQ, global_data, g_offset, &temp_len) < 0) return -1;
    memcpy(&buffer[offset], temp, temp_len); offset += temp_len;

    // Encode Security Parameters (as OCTET STRING wrapping an inner SEQUENCE)
    uint8_t sec_inner[512];
    size_t s_offset = 0;
    encode_tlv(&sec_inner[s_offset], sizeof(sec_inner)-s_offset, TLV_OCTETSTR, msg->secParams.msgAuthoritativeEngineID.data, msg->secParams.msgAuthoritativeEngineID.len, &len); s_offset += len;
    encode_tlv(&sec_inner[s_offset], sizeof(sec_inner)-s_offset, TLV_INT, msg->secParams.msgAuthoritativeEngineBoots.data, msg->secParams.msgAuthoritativeEngineBoots.len, &len); s_offset += len;
    encode_tlv(&sec_inner[s_offset], sizeof(sec_inner)-s_offset, TLV_INT, msg->secParams.msgAuthoritativeEngineTime.data, msg->secParams.msgAuthoritativeEngineTime.len, &len); s_offset += len;
    encode_tlv(&sec_inner[s_offset], sizeof(sec_inner)-s_offset, TLV_OCTETSTR, msg->secParams.msgUserName.data, msg->secParams.msgUserName.len, &len); s_offset += len;
    encode_tlv(&sec_inner[s_offset], sizeof(sec_inner)-s_offset, TLV_OCTETSTR, msg->secParams.msgAuthenticationParameters.data, msg->secParams.msgAuthenticationParameters.len, &len); s_offset += len;
    encode_tlv(&sec_inner[s_offset], sizeof(sec_inner)-s_offset, TLV_OCTETSTR, msg->secParams.msgPrivacyParameters.data, msg->secParams.msgPrivacyParameters.len, &len); s_offset += len;
    encode_tlv(temp, sizeof(temp), TLV_SEQ, sec_inner, s_offset, &temp_len);
    encode_tlv(temp, sizeof(temp), TLV_OCTETSTR, temp + 2, temp_len - 2, &temp_len); // nested as OCTET STRING
    memcpy(&buffer[offset], temp, temp_len); offset += temp_len;

    // Encode ScopedPDU
    uint8_t scoped_inner[512];
    size_t sc_offset = 0;
    encode_tlv(&scoped_inner[sc_offset], sizeof(scoped_inner)-sc_offset, TLV_OCTETSTR, msg->scopedPDU.contextEngineID.data, msg->scopedPDU.contextEngineID.len, &len); sc_offset += len;
    encode_tlv(&scoped_inner[sc_offset], sizeof(scoped_inner)-sc_offset, TLV_OCTETSTR, msg->scopedPDU.contextName.data, msg->scopedPDU.contextName.len, &len); sc_offset += len;
    encode_tlv(&scoped_inner[sc_offset], sizeof(scoped_inner)-sc_offset, TLV_SEQ, msg->scopedPDU.pdu.data, msg->scopedPDU.pdu.len, &len); sc_offset += len;
    encode_tlv(temp, sizeof(temp), TLV_SEQ, scoped_inner, sc_offset, &temp_len);
    memcpy(&buffer[offset], temp, temp_len); offset += temp_len;

    // Wrap everything in outer sequence
    if (encode_tlv(out_buf, out_size, TLV_SEQ, buffer, offset, encoded_len) < 0) return -1;
    return 0;
}

// // SNMP Manager Send stub
// void snmp_manager_send(const SNMPv3Message *msg) {
//     uint8_t packet[2048];
//     size_t packet_len = 0;
//     if (snmpv3_encode_message(msg, packet, sizeof(packet), &packet_len) == 0) {
//         printf("SNMPv3 packet (%zu bytes):\n", packet_len);
//         for (size_t i = 0; i < packet_len; i++) {
//             printf("%02X ", packet[i]);
//             if ((i + 1) % 16 == 0) printf("\n");
//         }
//         printf("\n// TODO: Send packet over UDP\n");
//     } else {
//         printf("Error encoding SNMPv3 message.\n");
//     }
// }

void snmpv3_manager_send() {
    Snmpv3Packet packet;
    memset(&packet, 0, sizeof(packet));

    packet.header.msgVersion = 3;

    // RFC 3412 §3: msgGlobalData ::= SEQUENCE { msgID INTEGER, msgMaxSize INTEGER, msgFlags OCTET STRING, msgSecurityModel INTEGER }
    // Build the msgGlobalData
    Asn1Writer globalWriter;
    uint8_t globalBuf[32];
    asn1_writer_init(&globalWriter, globalBuf, sizeof(globalBuf));
    asn1_start_sequence(&globalWriter);
    asn1_write_integer(&globalWriter, 12345);            // msgID
    asn1_write_integer(&globalWriter, MAX_BUFFER_SIZE);  // msgMaxSize
    uint8_t msgFlags = 0x04;  // reportable (no auth/privacy)
    asn1_write_octet_string(&globalWriter, &msgFlags, 1);
    asn1_write_integer(&globalWriter, 3);  // USM (RFC 3411)
    asn1_end_sequence(&globalWriter);

    memcpy(packet.header.msgGlobalData, globalBuf, asn1_writer_len(&globalWriter));
    packet.header.msgGlobalDataLen = asn1_writer_len(&globalWriter);

    // Build dummy USM SecurityParameters (replace with real logic per RFC 3414)
    const uint8_t dummySecurityParams[] = {
        0x30, 0x0C,                 // SEQUENCE
        0x04, 0x00,                 // msgAuthoritativeEngineID (OCTET STRING, empty)
        0x02, 0x01, 0x00,           // msgAuthoritativeEngineBoots
        0x02, 0x01, 0x00,           // msgAuthoritativeEngineTime
        0x04, 0x00,                 // msgUserName (empty)
        // msgAuthenticationParameters and msgPrivacyParameters would follow
    };
    memcpy(packet.header.msgSecurityParameters, dummySecurityParams, sizeof(dummySecurityParams));
    packet.header.msgSecurityParametersLen = sizeof(dummySecurityParams);

    // ScopedPdu: RFC 3412 §3: ScopedPdu ::= SEQUENCE { contextEngineID, contextName, data (GetRequest, etc) }
    memcpy(packet.scopedPdu.contextEngineID, "engineID", 8);
    packet.scopedPdu.contextEngineIDLen = 8;

    memcpy(packet.scopedPdu.contextName, "public", 6);
    packet.scopedPdu.contextNameLen = 6;

    // Example GetRequest PDU
    const uint8_t dummyPdu[] = {
        0xA0, 0x0A,           // GetRequest-PDU (tag A0)
        0x02, 0x01, 0x00,     // request-id
        0x02, 0x01, 0x00,     // error-status
        0x02, 0x01, 0x00,     // error-index
        0x30, 0x00            // variable-bindings (empty)
    };
    packet.scopedPdu.pdu = dummyPdu;
    packet.scopedPdu.pduLen = sizeof(dummyPdu);

    // Encode full SNMPv3 packet
    uint8_t outBuffer[MAX_BUFFER_SIZE];
    size_t outLen;
    if (snmpv3_encode_packet(outBuffer, &outLen, &packet)) {
        printf("SNMPv3 Packet Encoded Successfully (%zu bytes):\n", outLen);
        for (size_t i = 0; i < outLen; ++i) {
            printf("%02X ", outBuffer[i]);
        }
        printf("\n");

        // TODO: Send over UDP to SNMP Agent
    } else {
        fprintf(stderr, "Failed to encode SNMPv3 packet\n");
    }
}

// Great question — and you're right to think in terms of reversing decoding logic to understand the structure. SNMPv3 packets are ASN.1/BER encoded and structured in a strict hierarchy defined by RFC 3412 and RFC 3414. Here's a breakdown of an SNMPv3 message in the order it is built, using a table format to show component, encoding type, encryption, details, and order.

// 🔐 SNMPv3 Message Structure (RFC-Compliant, ASN.1/BER Encoded)

// Step	Component Name	                Encoding (TLV Type)	Encrypted	Description
// 1	msgVersion	                    INTEGER	                ❌	Always 3 for SNMPv3.
// 2	msgGlobalData	                SEQUENCE	            ❌	Includes msgID, msgMaxSize, msgFlags, and msgSecurityModel.
// 3.1	msgID	                        INTEGER	                ❌	Unique request identifier.
// 3.2	msgMaxSize	                    INTEGER	                ❌	Max message size receiver can accept.
// 3.3	msgFlags	                    OCTET STRING	        ❌	Bit-field: Reportable(0x04), Auth(0x01), Priv(0x02).
// 3.4	msgSecurityModel	            INTEGER	                ❌	Usually 3 for USM.
// 4	msgSecurityParameters	        OCTET STRING (encapsulates SEQUENCE)	❌	ASN.1-encoded inner sequence for USM data.
// 4.1	msgAuthoritativeEngineID	    OCTET STRING	❌	Engine ID used to prevent replay.
// 4.2	msgAuthoritativeEngineBoots	    INTEGER	❌	Boot count to help prevent replay.
// 4.3	msgAuthoritativeEngineTime	    INTEGER	❌	System uptime from engine.
// 4.4	msgUserName	                    OCTET STRING	❌	SNMPv3 username.
// 4.5	msgAuthenticationParameters	    OCTET STRING	✅ HMAC	Auth digest (zero-filled initially, then filled after HMAC).
// 4.6	msgPrivacyParameters	        OCTET STRING	✅	Salt or IV used for encryption (e.g., DES/AES).
// 5	msgData (CHOICE)	            SEQUENCE or OCTET STRING	✅/❌	Contains ScopedPDU (plaintext or encrypted).
// 5.1	Plaintext ScopedPDU	            SEQUENCE	❌	Only used if Priv flag is off.
// 5.1.1	contextEngineID	            OCTET STRING	❌	Matches the target SNMP engine ID.
// 5.1.2	contextName	                OCTET STRING	❌	Like a MIB namespace.
// 5.1.3	data (PDU)	                SEQUENCE	❌	Actual SNMP PDU (Get, Set, etc.) — still BER-encoded.
// 5.2	Encrypted ScopedPDU	            OCTET STRING (ciphertext)	✅	If Priv flag is set, this is the encrypted ScopedPDU.
// 🔧 Summary of Encoding and Crypto

// Layer	Encoding Format	Encrypted	Notes
// Whole packet	ASN.1 / BER	Partial	Only ScopedPDU may be encrypted.
// GlobalData	ASN.1 SEQUENCE	❌	Flat structure, no encryption.
// SecurityParams	ASN.1 SEQUENCE (wrapped in OCTET STRING)	Auth/Priv	Used for both authentication and encryption setup.
// ScopedPDU	ASN.1 SEQUENCE or Encrypted blob	✅/❌	Encrypted if Priv is enabled.
// Authentication	HMAC-MD5/SHA	✅	HMAC over entire message with 0-filled authParams, then replaced.
// Encryption	DES, AES	✅	Encrypted ScopedPDU only, CBC-mode with IV/salt.
// 📦 Build Order Recap (Bottom-Up Assembly)
// Encode PDU (GetRequest, etc.)

// Encode ScopedPDU → contextEngineID, contextName, raw PDU

// (Optional) Encrypt ScopedPDU if Priv flag set → becomes encryptedPDU

// Encode Security Parameters (zero authParams first)

// Encode msgGlobalData

// Combine all to form top-level SNMPv3 Message

// If Auth flag set, HMAC over full message and insert real authParams

// Would you like a diagram of this structure or a raw hex-encoded example too?

// Here is both a diagram and a raw hex-encoded example based on your SNMPv3 packet construction logic.

// 🗂️ Diagram of SNMPv3 Packet Structure (Plaintext ScopedPDU)
// pgsql
// Copy
// Edit
// +----------------------------------------------+
// | SEQUENCE (whole SNMPv3 message)              |
// |  +----------------------------------------+  |
// |  | INTEGER: msgVersion (3)                |  |
// |  +----------------------------------------+  |
// |  | OCTET STRING: msgGlobalData            |  |
// |  +----------------------------------------+  |
// |  | OCTET STRING: msgSecurityParameters    |  |
// |  +----------------------------------------+  |
// |  | ScopedPDU (plaintext)                  |  |
// |  |  +----------------------------------+  |  |
// |  |  | SEQUENCE                         |  |  |
// |  |  |  +--------------------------+    |  |  |
// |  |  |  | OCTET STRING: engineID   |    |  |  |
// |  |  |  +--------------------------+    |  |  |
// |  |  |  | OCTET STRING: context    |    |  |  |
// |  |  |  +--------------------------+    |  |  |
// |  |  |  | raw PDU (GetRequest, etc.)    |  |  |
// |  |  |  +--------------------------+    |  |  |
// |  |  +----------------------------------+  |  |
// +----------------------------------------------+
// 🔢 Hex-encoded Example Output
// From your dummy data (assuming this gets encoded in snmp_manager_send()), here is an approximate hex dump of the output buffer:

// text
// Copy
// Edit
// 30 2B                ; SEQUENCE, length 43
//    02 01 03          ; INTEGER, version = 3
//    04 09             ; OCTET STRING, length 9
//       30 06 02 01 7B 02 02 05 DC  ; dummyGlobalData
//    04 05             ; OCTET STRING, length 5
//       04 03 AA BB CC             ; dummySecurityParams
//    30 13             ; SEQUENCE (ScopedPDU), length 19
//       04 08 65 6E 67 69 6E 65 49 44     ; contextEngineID = "engineID"
//       04 06 70 75 62 6C 69 63           ; contextName = "public"
//       A0 0A 02 01 00 02 01 00 30 00     ; dummyPDU (GetRequest)
// 🔍 Note:

// 30 = SEQUENCE, 02 = INTEGER, 04 = OCTET STRING, A0 = context-specific tag (GetRequest).

// ASCII "engineID" = 65 6E 67 69 6E 65 49 44, "public" = 70 75 62 6C 69 63.

// Would you like me to generate a visual PNG diagram or a packet dissection in Wireshark-style format?

// Here is a Wireshark-style dissection of your dummy SNMPv3 packet, based on the structure built by snmp_manager_send() using the raw hex:

// 🔍 Wireshark-style SNMPv3 Packet Dissection
// text
// Copy
// Edit
// + Frame (43 bytes)
// + Ethernet II
// + Internet Protocol Version 4
// + User Datagram Protocol, Src Port: 12345, Dst Port: 161
// + Simple Network Management Protocol (SNMP)
//     SNMP Version: 3
//     msgGlobalData
//         msgID: 123
//         msgMaxSize: 1500
//     msgSecurityParameters
//         usmSecurityParameters: 04 03 aa bb cc
//     msgData: plaintext
//         scopedPDU
//             contextEngineID: 65:6e:67:69:6e:65:49:44 ("engineID")
//             contextName: 70:75:62:6c:69:63 ("public")
//             data: GetRequest-PDU
//                 PDU Type: GetRequest (0xA0)
//                 Request ID: 0
//                 Error Status: noError (0)
//                 Error Index: 0
//                 Variable Bindings: 0
//
// 🧬 Raw Byte Breakdown (for reference)
// text
// Copy
// Edit
// 30 2B                   ; SEQUENCE (43 bytes)
//    02 01 03             ; INTEGER version = 3
//    04 09                ; OCTET STRING (msgGlobalData)
//       30 06 02 01 7B 02 02 05 DC
//          ; SEQUENCE
//          ; INTEGER: 123
//          ; INTEGER: 1500
//    04 05                ; OCTET STRING (msgSecurityParameters)
//       04 03 AA BB CC    ; Opaque content
//    30 13                ; SEQUENCE (ScopedPDU)
//       04 08             ; OCTET STRING (contextEngineID)
//          65 6E 67 69 6E 65 49 44 ; "engineID"
//       04 06             ; OCTET STRING (contextName)
//          70 75 62 6C 69 63       ; "public"
//       A0 0A             ; GetRequest-PDU (tag A0, length 10)
//          02 01 00       ; request-id: 0
//          02 01 00       ; error-status: 0
//          30 00          ; SEQUENCE: empty VarBind list
// Would you like this exported as a .pcap file to load into Wireshark, or a visual diagram for documentation?