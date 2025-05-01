#pragma once
#include <cstdint>
#include <vector>
#include <string>

// Utility for TLV-encoded buffers
typedef std::vector<uint8_t> TLVBuffer;


// Message ::= SEQUENCE {
//     msgVersion         INTEGER (3),
//     msgGlobalData      HeaderData,
//     msgSecurityParams  OCTET STRING,  -- Contains a nested SEQUENCE
//     msgData            ScopedPDUData
//   }

/**
 * SNMPv3 Message ::= SEQUENCE {
 *     msgVersion         INTEGER (3),
 *     msgGlobalData      HeaderData,
 *     msgSecurityParams  OCTET STRING,  -- Contains an encoded SecurityParameters SEQUENCE
 *     msgData            ScopedPDUData  -- Encrypted OCTET STRING or plaintext
 * }
 */
struct SNMPv3Message {
    uint8_t msgVersion = 3;  // Always 3 for SNMPv3

    struct HeaderData {
        int32_t msgID;
        int32_t msgMaxSize;
        bool    msgFlagsReportable;
        bool    msgFlagsAuth;
        bool    msgFlagsPriv;
        uint8_t msgSecurityModel;  // 3 for USM

        // Encode msgFlags as a single byte
        uint8_t getMsgFlags() const {
            return
                (msgFlagsReportable ? 0x04 : 0) |
                (msgFlagsAuth       ? 0x01 : 0) |
                (msgFlagsPriv       ? 0x02 : 0);
        }
    } msgGlobalData;

    struct SecurityParameters {
        std::vector<uint8_t> msgAuthoritativeEngineID;
        uint32_t             msgAuthoritativeEngineBoots;
        uint32_t             msgAuthoritativeEngineTime;
        std::string          msgUserName;
        std::vector<uint8_t> msgAuthenticationParameters;  // 12 bytes (zero-filled before HMAC, filled after)
        std::vector<uint8_t> msgPrivacyParameters;         // 8 bytes (used as IV for AES)
    } msgSecurityParams;

    // If noAuthNoPriv or authNoPriv, this is plain ScopedPDU TLV-encoded.
    // If authPriv, this is AES-128-CFB encrypted ScopedPDU TLV wrapped in an OCTET STRING
    struct ScopedPDUData {
        // If encrypted:
        std::vector<uint8_t> encryptedData;

        // If unencrypted:
        struct ScopedPDU {
            std::vector<uint8_t> contextEngineID;
            std::string          contextName;

            enum PDUType { GetRequest = 0xA0, GetResponse = 0xA2, Report = 0xA8, ... } pduType;
            int32_t requestID;
            int32_t errorStatus;
            int32_t errorIndex;

            struct VarBind {
                std::vector<uint8_t> oid;  // TLV-encoded OID
                std::vector<uint8_t> value;  // TLV-encoded value (INTEGER, OCTET STRING, etc.)
            };

            std::vector<VarBind> varBinds;
        } plaintextPDU;
    } msgData;
};

// int seq_offset = current_offset();         // start of sequence
// write_byte(0x30);                          // SEQUENCE tag
// write_byte(0x00);                          // dummy length (to be patched)
// int seq_content_offset = current_offset(); // encode inside here
// write_something(...);
// int final_offset = current_offset();
// int seq_len = final_offset - seq_content_offset;
// patch_length_at(seq_offset + 1, seq_len);  // ❌ rel_offset is negative here

// uint8_t temp_buf[512];
// int content_len = encode_scoped_pdu_content(temp_buf + sizeof(temp_buf)); // encode from end backward
// int seq_len = content_len + encoded_length_field_size(content_len) + 1;
// uint8_t *start = buffer + current_offset - seq_len;

// start[0] = 0x30; // SEQUENCE tag
// encode_length(&start[1], content_len);
// memcpy(&start[1 + length_size], &temp_buf[sizeof(temp_buf) - content_len], content_len);