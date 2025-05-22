
struct snmpv3Packet {
    u32_t   version;
    s32_t   request_id;
    s32_t   error_status;
    s32_t   error_index;
    u8_t    request_out_type;

    u8_t    *hashedAuthKey; // 20 bytes of auth password
    u8_t    *hashedPrivKey; // 16 bytes of priv password
    s32_t   msg_id;
    s32_t   msg_max_size;

    u8_t    msg_flags;
    s32_t   msg_security_model;
    u8_t    msg_auth_engine_id[SNMP_V3_MAX_ENGINE_ID_LENGTH];
    u8_t    msg_auth_engine_id_len;
    
    s32_t   msg_auth_engine_boots;
    s32_t   msg_auth_engine_time;
    u8_t    msg_user_name[SNMP_V3_MAX_USER_LENGTH];
    u8_t    msg_user_name_len;

    u8_t    msg_priv_param[SNMP_V3_MAX_PRIV_PARAM_LENGTH];
    u8_t    msg_priv_param_len;
    u8_t    ctx_engine_id[SNMP_V3_MAX_ENGINE_ID_LENGTH];
    u8_t    ctx_engine_id_len;

    u8_t    ctx_name[SNMP_V3_MAX_ENGINE_ID_LENGTH];
    u8_t    ctx_name_len;
    u16_t   outbound_pdu_offset;
    u16_t   outbound_err_status_offset;

    u16_t   outbound_err_index_offset;
    u16_t   outbound_err_varbind_offset;
    u16_t   outbound_msg_global_data_offset;
    u16_t   outbound_msg_security_params_str_offset;

    u16_t   outbound_msg_security_params_seq_offset;
    u16_t   outbound_msg_security_params_end;
    u16_t   outbound_scoped_pdu_seq_offset;
    u16_t   outbound_scoped_pdu_string_offset;
};

// encoding methodology is based on inside first outside last to make sure the 
// sequences are encoded correctly

err_t encodeGlobalDataContents(snmp_pbuf_stream *pbufStream, snmpv3Packet *params, u8_t *buf) {
    snmp_asn1_tlv tlv;
    // this function encodes the features of globalData into a temp buf first such
    // that it could be turned into a sequence buffer later.

    // in tlv type is the type, length is the total length of the tlv encodinfg
    // type length value
    // i.e. 3
    // [int][3 bytes][03]

    // msgVersion - version
    SNMP_ASN1_SET_TLB_PARAMS(tlv, SNMP_ASN1_TYPE_INTEGER, 0, 0);
    snmp_asn1_enc_s32t_cnt(params->version, &tlv.value_len);
    OF_BUILD_EXEC( snmp_asn1_enc_tlv (pbufStream, &tlv));
    OF_BUILD_EXEC( snmp_asn1_enc_s32t(pbufStream, tlv.value_len, params->version));
    
    // encode the rest into pbufStream
}

err_t encodeMsGlobalDataSequence(snmp_asn1_tlv tlv,
                                 snmp_pbuf_stream *pbufStream,
                                 u8_t *buf,
                                 s32_t msgID,
                                 s32_t ) 
{

} 
// OF_BUILD_EXEC()

err_t sendSnmpData(void *handle)  {

    u32_t msgVersion = 3;
    static s32_t msgID = 1;
    s32_t msgMaxSize = 65507;
    u8_t msgFlags = SNMP_V3_AUTH_FLAG | SNMP_V3_PRIV_FLAG; // should be 3
    s32_t msgSecurityModel = 3; // version

    static OrcaTlvFieldType tlvMsg;
    static snmp_asn1_tlv tlv = {0};
    memset(&tlvMsg, 0, sizeof(OrcaTlvFieldType));
    memset(&tlv, 0, sizeof(snmp_asn1_tlv));

    struct pbuf *p;
    struct snmp_pbuf_streanm temp_stream;
    u8_t temp_buf[BUFFER_SIZE];
    err_t err = ERR_OK;

    p = pbuf_alloc(PBUF_TRANSPORT, 1472, PBUF_RAM);
    if (p == NULL) {
        return ERR_MEM;
    }
    snmp_pbuf_stream_init(&temp_stream, p, 0, p->tot_len);




    // Helper functions
    err = encodeMsgVersion(tlv, &temp_stream, &snmpv3Msg, msgVersion);
    if (err != ERR_OK) {
        print("Failed to encode msgVersion: %d\n", err);
        return err;
    }
    printUint8Array(snmpv3Msg.msgVersion.data, snmpv3Msg.msgVersion.data_len);
}

// 📦 SNMPv3 Message Structure (ASN.1)
// nginx
// Copy
// Edit
// Message ::= SEQUENCE {
//   msgVersion             INTEGER,
//   msgGlobalData          HeaderData,
//   msgSecurityParameters  OCTET STRING,
//   msgData                ScopedPduData
// }
// 🧩 Field-by-Field ASN.1 Type Breakdown
// 🔹 1. msgVersion
// ASN.1 Type: INTEGER

// Tag: 0x02

// Example: 0x02 0x01 0x03 → INTEGER, 1-byte length, value 3 (SNMPv3)

// 🔹 2. msgGlobalData → HeaderData
// asn1
// Copy
// Edit
// HeaderData ::= SEQUENCE {
//   msgID             INTEGER (0..2147483647),
//   msgMaxSize        INTEGER (484..2147483647),
//   msgFlags          OCTET STRING (SIZE(1)),
//   msgSecurityModel  INTEGER (1..2147483647)
// }
// SEQUENCE: 0x30

// Contains:

// msgID: INTEGER

// msgMaxSize: INTEGER

// msgFlags: OCTET STRING (typically 1 byte: e.g., 0x07)

// msgSecurityModel: INTEGER (e.g., 3 for USM)

// 🔹 3. msgSecurityParameters
// ASN.1 Type: OCTET STRING (contains an encoded sequence inside)

// Tag: 0x04

// Contents: Encoded ASN.1 for USM Security Parameters:

// asn1
// Copy
// Edit
// USMSecurityParameters ::= SEQUENCE {
//   msgAuthoritativeEngineID   OCTET STRING,
//   msgAuthoritativeEngineBoots  INTEGER,
//   msgAuthoritativeEngineTime   INTEGER,
//   msgUserName                  OCTET STRING,
//   msgAuthenticationParameters  OCTET STRING,
//   msgPrivacyParameters         OCTET STRING
// }
// Although msgSecurityParameters is an OCTET STRING, it encapsulates an encoded SEQUENCE of parameters.

// 🔹 4. msgData
// ASN.1 Type: CHOICE

// asn1
// Copy
// Edit
// msgData ::= CHOICE {
//   plaintext         ScopedPdu,
//   encryptedPDU      OCTET STRING
// }
// If not encrypted, the plaintext ScopedPDU is included.

// 📦 ScopedPdu Structure
// asn1
// Copy
// Edit
// ScopedPdu ::= SEQUENCE {
//   contextEngineID OCTET STRING,
//   contextName     OCTET STRING,
//   data            PDU
// }
// 🔹 contextEngineID
// ASN.1 Type: OCTET STRING

// Tag: 0x04

// 🔹 contextName
// ASN.1 Type: OCTET STRING

// 🔹 data (PDU)
// This is one of:

// GetRequest-PDU

// SetRequest-PDU

// GetNextRequest-PDU

// Response-PDU, etc.

// All PDUs follow the same structure:

// asn1
// Copy
// Edit
// PDU ::= [APPLICATION n] IMPLICIT SEQUENCE {
//   request-id     INTEGER,
//   error-status   INTEGER,
//   error-index    INTEGER,
//   variable-bindings VarBindList
// }
// 📦 VarBindList & VarBind
// asn1
// Copy
// Edit
// VarBindList ::= SEQUENCE OF VarBind

// VarBind ::= SEQUENCE {
//   name   ObjectName,   -- OBJECT IDENTIFIER
//   value  ObjectSyntax  -- Value (e.g., NULL for GET)
// }
// 🔹 name
// ASN.1 Type: OBJECT IDENTIFIER

// Tag: 0x06

// 🔹 value
// Can be: NULL, INTEGER, OCTET STRING, IpAddress, TimeTicks, etc.

// Tag varies depending on type (0x05 for NULL, 0x04 for OCTET STRING, etc.)

// ✅ Summary Table
// Field	ASN.1 Type	Tag
// msgVersion	INTEGER	0x02
// msgGlobalData	SEQUENCE	0x30
// ├─ msgID	INTEGER	0x02
// ├─ msgMaxSize	INTEGER	0x02
// ├─ msgFlags	OCTET STRING	0x04
// └─ msgSecurityModel	INTEGER	0x02
// msgSecurityParameters	OCTET STRING	0x04
// └─ (Contains SEQUENCE inside)		
// msgData (ScopedPduData)	CHOICE	
// └─ ScopedPDU	SEQUENCE	0x30
// ├─ contextEngineID	OCTET STRING	0x04
// ├─ contextName	OCTET STRING	0x04
// └─ PDU	[APPLICATION n]	e.g. 0xA0
// ├─ request-id	INTEGER	0x02
// ├─ error-status	INTEGER	0x02
// ├─ error-index	INTEGER	0x02
// └─ VarBindList	SEQUENCE OF SEQUENCE	0x30
// └─ VarBind	SEQUENCE	0x30
// ├─ name	OBJECT IDENTIFIER	0x06
// └─ value	e.g., NULL	0x05


// what about with authpriv and no engine boot/time only engine id? how do i send a discovery get packet if i need to encode the passwords with engineboots and time?


// ChatGPT said:
// Excellent question — this is one of the most nuanced parts of SNMPv3.

// 🛑 Problem Summary:
// You're trying to send a discovery SNMPv3 packet to an agent that requires authPriv, but you don't yet know the agent's:

// engineBoots

// engineTime

// Yet, to generate the key for encryption/authentication, you need the engineID, and to authenticate the request, you need a proper auth HMAC computed with the correct engineBoots/time.

// ✅ Good News:
// SNMPv3 supports a built-in discovery mechanism specifically for this. Here’s how it works — even for authPriv.

// 🔁 Discovery Sequence (for authPriv agent):
// 🔹 Step 1: Discovery Probe (Unauthenticated)
// You send a discovery probe:

// msgFlags = 0x03 → noAuthNoPriv

// msgSecurityParameters: includes empty engineID, boots, time, username

// ScopedPDU is a normal GetRequest (with empty VarBind or a real OID)

// No HMAC

// No encryption

// The agent does not reject this even if it normally requires authPriv.

// It simply replies with:

// The real engineID, engineBoots, and engineTime

// The msgData is unencrypted and unauthenticated

// This is allowed per the SNMPv3 spec

// You now cache those values locally.

// 🔹 Step 2: Real AuthPriv Request
// Now that you have:

// engineID

// engineBoots

// engineTime

// You can:

// Generate the HMAC-SHA1/MD5 key using engineID

// Fill in the correct engineBoots and engineTime values in the USM

// Encrypt the ScopedPDU using AES/DES

// Add HMAC over the full message with correct authParameters

// Send the actual authPriv request.

// 🔐 Why This Works:
// The discovery probe is always allowed by the agent. The agent doesn’t require authentication until it knows you know its engine parameters. So the discovery is unprotected by design, even if future traffic is protected.

// 🛠️ What to Do in Code:
// For Discovery Packet:
// c
// Copy
// Edit
// msgFlags = 0x03; // noAuthNoPriv
// engineID = empty;
// engineBoots = 0;
// engineTime = 0;
// username = ""; // or valid username depending on agent
// authParameters = 12 zero bytes
// privParameters = empty
// ScopedPDU = GetRequest with dummy OID or valid one
// No encryption. No HMAC.

// Send that.

// For Real Request (authPriv):
// Use the agent's engineID to derive your key:

// c
// Copy
// Edit
// localizedKey = password_to_key(password, engineID)
// Use engineBoots/time from agent's last reply

// Fill msgSecurityParameters with real values

// Encrypt ScopedPDU using AES/DES with privKey

// Compute HMAC with authKey

// Insert first 12 bytes of HMAC into authParameters

// Would you like a C code sketch for sending the discovery probe or the key generation part?