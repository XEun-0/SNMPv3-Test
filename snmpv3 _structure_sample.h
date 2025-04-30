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

