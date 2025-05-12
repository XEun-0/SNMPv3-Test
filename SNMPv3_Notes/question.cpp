/**
+ * @ingroup snmp_manager
+ * Encodes header from head to tail.
+ *
+ * @param request Manager message
+ * @param pbuf_stream stream used for storing data inside pbuf
+ * @retval err_t ERR_OK if successful
+ */
+static err_t
+snmp_manager_header_enc(struct snmp_msg_manager *request, struct snmp_pbuf_stream *pbuf_stream)
+{
+  struct snmp_asn1_tlv tlv;
+
+  /* 'Message' sequence */
+  SNMP_ASN1_SET_TLV_PARAMS(tlv, SNMP_ASN1_TYPE_SEQUENCE, 3, 0);
+  OF_BUILD_EXEC( snmp_ans1_enc_tlv(pbuf_stream, &tlv) );
+
+  /* version */
+  SNMP_ASN1_SET_TLV_PARAMS(tlv, SNMP_ASN1_TYPE_INTEGER, 0, 0);
+  snmp_asn1_enc_s32t_cnt(request->version, &tlv.value_len);
+  OF_BUILD_EXEC( snmp_ans1_enc_tlv(pbuf_stream, &tlv) );
+  OF_BUILD_EXEC( snmp_asn1_enc_s32t(pbuf_stream, tlv.value_len, request->version) );
+
+#if LWIP_SNMP_V3
+  if (request->version < SNMP_VERSION_3) {
+#endif
+    /* community */
+    SNMP_ASN1_SET_TLV_PARAMS(tlv, SNMP_ASN1_TYPE_OCTET_STRING, 0, request->community_strlen);
+    OF_BUILD_EXEC( snmp_ans1_enc_tlv(pbuf_stream, &tlv) );
+    OF_BUILD_EXEC( snmp_asn1_enc_raw(pbuf_stream, request->community, request->community_strlen) );
+#if LWIP_SNMP_V3
+  } else {
+    const char *id;
+
+    /* globalData */
+    request->outbound_msg_global_data_offset = pbuf_stream->offset;
+    SNMP_ASN1_SET_TLV_PARAMS(tlv, SNMP_ASN1_TYPE_SEQUENCE, 1, 0);
+    OF_BUILD_EXEC(snmp_ans1_enc_tlv(pbuf_stream, &tlv));
+
+    /* msgID */
+    SNMP_ASN1_SET_TLV_PARAMS(tlv, SNMP_ASN1_TYPE_INTEGER, 0, 1);
+    snmp_asn1_enc_s32t_cnt(request->msg_id, &tlv.value_len);
+    OF_BUILD_EXEC(snmp_ans1_enc_tlv(pbuf_stream, &tlv));
+    OF_BUILD_EXEC(snmp_asn1_enc_s32t(pbuf_stream, tlv.value_len, request->msg_id));
+
+    /* msgMaxSize */
+    SNMP_ASN1_SET_TLV_PARAMS(tlv, SNMP_ASN1_TYPE_INTEGER, 0, 1);
+    snmp_asn1_enc_s32t_cnt(request->msg_max_size, &tlv.value_len);
+    OF_BUILD_EXEC(snmp_ans1_enc_tlv(pbuf_stream, &tlv));
+    OF_BUILD_EXEC(snmp_asn1_enc_s32t(pbuf_stream, tlv.value_len, request->msg_max_size));
+
+    /* msgFlags */
+    SNMP_ASN1_SET_TLV_PARAMS(tlv, SNMP_ASN1_TYPE_OCTET_STRING, 0, 1);
+    OF_BUILD_EXEC(snmp_ans1_enc_tlv(pbuf_stream, &tlv));
+    OF_BUILD_EXEC(snmp_asn1_enc_raw(pbuf_stream, &request->msg_flags, 1));
+
+    /* msgSecurityModel */
+    SNMP_ASN1_SET_TLV_PARAMS(tlv, SNMP_ASN1_TYPE_INTEGER, 0, 1);
+    snmp_asn1_enc_s32t_cnt(request->msg_security_model, &tlv.value_len);
+    OF_BUILD_EXEC(snmp_ans1_enc_tlv(pbuf_stream, &tlv));
+    OF_BUILD_EXEC(snmp_asn1_enc_s32t(pbuf_stream, tlv.value_len, request->msg_security_model));
+
+    /* end of msgGlobalData */
+    request->outbound_msg_global_data_end = pbuf_stream->offset;
+
+    /* msgSecurityParameters */
+    request->outbound_msg_security_parameters_str_offset = pbuf_stream->offset;
+    SNMP_ASN1_SET_TLV_PARAMS(tlv, SNMP_ASN1_TYPE_OCTET_STRING, 1, 0);
+    OF_BUILD_EXEC(snmp_ans1_enc_tlv(pbuf_stream, &tlv));
+
+    request->outbound_msg_security_parameters_seq_offset = pbuf_stream->offset;
+    SNMP_ASN1_SET_TLV_PARAMS(tlv, SNMP_ASN1_TYPE_SEQUENCE, 1, 0);
+    OF_BUILD_EXEC(snmp_ans1_enc_tlv(pbuf_stream, &tlv));
+
+    /* msgAuthoritativeEngineID */
+#if 0 // Don't do this when SNMP manager
+    snmpv3_get_engine_id(&id, &request->msg_authoritative_engine_id_len);
+    MEMCPY(request->msg_authoritative_engine_id, id, request->msg_authoritative_engine_id_len);
+#endif
+    SNMP_ASN1_SET_TLV_PARAMS(tlv, SNMP_ASN1_TYPE_OCTET_STRING, 0, request->msg_authoritative_engine_id_len);
+    OF_BUILD_EXEC(snmp_ans1_enc_tlv(pbuf_stream, &tlv));
+    OF_BUILD_EXEC(snmp_asn1_enc_raw(pbuf_stream, request->msg_authoritative_engine_id, request->msg_authoritative_engine_id_len));
+
+#if 0 // Don't do this when SNMP manager
+    request->msg_authoritative_engine_time = snmpv3_get_engine_time();
+    request->msg_authoritative_engine_boots = snmpv3_get_engine_boots();
+#endif
+
+    /* msgAuthoritativeEngineBoots */
+    SNMP_ASN1_SET_TLV_PARAMS(tlv, SNMP_ASN1_TYPE_INTEGER, 0, 0);
+    snmp_asn1_enc_s32t_cnt(request->msg_authoritative_engine_boots, &tlv.value_len);
+    OF_BUILD_EXEC(snmp_ans1_enc_tlv(pbuf_stream, &tlv));
+    OF_BUILD_EXEC(snmp_asn1_enc_s32t(pbuf_stream, tlv.value_len, request->msg_authoritative_engine_boots));
+
+    /* msgAuthoritativeEngineTime */
+    SNMP_ASN1_SET_TLV_PARAMS(tlv, SNMP_ASN1_TYPE_INTEGER, 0, 0);
+    snmp_asn1_enc_s32t_cnt(request->msg_authoritative_engine_time, &tlv.value_len);
+    OF_BUILD_EXEC(snmp_ans1_enc_tlv(pbuf_stream, &tlv));
+    OF_BUILD_EXEC(snmp_asn1_enc_s32t(pbuf_stream, tlv.value_len, request->msg_authoritative_engine_time));
+
+    /* msgUserName */
+    SNMP_ASN1_SET_TLV_PARAMS(tlv, SNMP_ASN1_TYPE_OCTET_STRING, 0, request->msg_user_name_len);
+    OF_BUILD_EXEC(snmp_ans1_enc_tlv(pbuf_stream, &tlv));
+    OF_BUILD_EXEC(snmp_asn1_enc_raw(pbuf_stream, request->msg_user_name, request->msg_user_name_len));
+
+#if LWIP_SNMP_V3_CRYPTO
+    /* msgAuthenticationParameters */
+    if (request->msg_flags & SNMP_V3_AUTH_FLAG) {
+      memset(request->msg_authentication_parameters, 0, SNMP_V3_MAX_AUTH_PARAM_LENGTH);
+      request->outbound_msg_authentication_parameters_offset = pbuf_stream->offset;
+      SNMP_ASN1_SET_TLV_PARAMS(tlv, SNMP_ASN1_TYPE_OCTET_STRING, 1, SNMP_V3_MAX_AUTH_PARAM_LENGTH);
+      OF_BUILD_EXEC(snmp_ans1_enc_tlv(pbuf_stream, &tlv));
+      OF_BUILD_EXEC(snmp_asn1_enc_raw(pbuf_stream, request->msg_authentication_parameters, SNMP_V3_MAX_AUTH_PARAM_LENGTH));
+    } else
+#endif
+    {
+      SNMP_ASN1_SET_TLV_PARAMS(tlv, SNMP_ASN1_TYPE_OCTET_STRING, 0, 0);
+      OF_BUILD_EXEC(snmp_ans1_enc_tlv(pbuf_stream, &tlv));
+    }
+
+#if LWIP_SNMP_V3_CRYPTO
+    /* msgPrivacyParameters */
+    if (request->msg_flags & SNMP_V3_PRIV_FLAG) {
+      snmpv3_build_priv_param(request->msg_privacy_parameters);
+
+      SNMP_ASN1_SET_TLV_PARAMS(tlv, SNMP_ASN1_TYPE_OCTET_STRING, 0, SNMP_V3_MAX_PRIV_PARAM_LENGTH);
+      OF_BUILD_EXEC(snmp_ans1_enc_tlv(pbuf_stream, &tlv));
+      OF_BUILD_EXEC(snmp_asn1_enc_raw(pbuf_stream, request->msg_privacy_parameters, SNMP_V3_MAX_PRIV_PARAM_LENGTH));
+    } else
+#endif
+    {
+      SNMP_ASN1_SET_TLV_PARAMS(tlv, SNMP_ASN1_TYPE_OCTET_STRING, 0, 0);
+      OF_BUILD_EXEC(snmp_ans1_enc_tlv(pbuf_stream, &tlv) );
+    }
+
+    /* End of msgSecurityParameters, so we can calculate the length of this sequence later */
+    request->outbound_msg_security_parameters_end = pbuf_stream->offset;
+
+#if LWIP_SNMP_V3_CRYPTO
+    /* For encryption we have to encapsulate the payload in an octet string */
+    if (request->msg_flags & SNMP_V3_PRIV_FLAG) {
+      request->outbound_scoped_pdu_string_offset = pbuf_stream->offset;
+      SNMP_ASN1_SET_TLV_PARAMS(tlv, SNMP_ASN1_TYPE_OCTET_STRING, 3, 0);
+      OF_BUILD_EXEC(snmp_ans1_enc_tlv(pbuf_stream, &tlv));
+    }
+#endif
+    /* Scoped PDU
+     * Encryption context
+     */
+    request->outbound_scoped_pdu_seq_offset = pbuf_stream->offset;
+    SNMP_ASN1_SET_TLV_PARAMS(tlv, SNMP_ASN1_TYPE_SEQUENCE, 3, 0);
+    OF_BUILD_EXEC(snmp_ans1_enc_tlv(pbuf_stream, &tlv));
+
+    /* contextEngineID */
+    snmpv3_get_engine_id(&id, &request->context_engine_id_len);
+    MEMCPY(request->context_engine_id, id, request->context_engine_id_len);
+    SNMP_ASN1_SET_TLV_PARAMS(tlv, SNMP_ASN1_TYPE_OCTET_STRING, 0, request->context_engine_id_len);
+    OF_BUILD_EXEC(snmp_ans1_enc_tlv(pbuf_stream, &tlv));
+    OF_BUILD_EXEC(snmp_asn1_enc_raw(pbuf_stream, request->context_engine_id, request->context_engine_id_len));
+
+    /* contextName */
+    SNMP_ASN1_SET_TLV_PARAMS(tlv, SNMP_ASN1_TYPE_OCTET_STRING, 0, request->context_name_len);
+    OF_BUILD_EXEC(snmp_ans1_enc_tlv(pbuf_stream, &tlv));
+    OF_BUILD_EXEC(snmp_asn1_enc_raw(pbuf_stream, request->context_name, request->context_name_len));
+  }
+#endif
+
+  /* 'PDU' sequence */
+  request->outbound_pdu_offset = pbuf_stream->offset;
+  SNMP_ASN1_SET_TLV_PARAMS(tlv, request->request_out_type, 3, 0);
+  OF_BUILD_EXEC( snmp_ans1_enc_tlv(pbuf_stream, &tlv) );
+
+  /* request ID */
+  SNMP_ASN1_SET_TLV_PARAMS(tlv, SNMP_ASN1_TYPE_INTEGER, 0, 0);
+  snmp_asn1_enc_s32t_cnt(request->request_id, &tlv.value_len);
+  OF_BUILD_EXEC( snmp_ans1_enc_tlv(pbuf_stream, &tlv) );
+  OF_BUILD_EXEC( snmp_asn1_enc_s32t(pbuf_stream, tlv.value_len, request->request_id) );
+
+  /* error status */
+  SNMP_ASN1_SET_TLV_PARAMS(tlv, SNMP_ASN1_TYPE_INTEGER, 0, 1);
+  OF_BUILD_EXEC( snmp_ans1_enc_tlv(pbuf_stream, &tlv) );
+  request->outbound_error_status_offset = pbuf_stream->offset;
+  OF_BUILD_EXEC( snmp_pbuf_stream_write(pbuf_stream, 0) );
+
+  /* error index */
+  SNMP_ASN1_SET_TLV_PARAMS(tlv, SNMP_ASN1_TYPE_INTEGER, 0, 1);
+  OF_BUILD_EXEC( snmp_ans1_enc_tlv(pbuf_stream, &tlv) );
+  request->outbound_error_index_offset = pbuf_stream->offset;
+  OF_BUILD_EXEC( snmp_pbuf_stream_write(pbuf_stream, 0) );
+
+  /* 'VarBindList' sequence */
+  SNMP_ASN1_SET_TLV_PARAMS(tlv, SNMP_ASN1_TYPE_SEQUENCE, 3, 0);
+  OF_BUILD_EXEC( snmp_ans1_enc_tlv(pbuf_stream, &tlv) );
+
+  request->outbound_varbind_offset = pbuf_stream->offset;
+
+  return ERR_OK;
+}
+
+#endif /* LWIP_SNMP && SNMP_MNGR */