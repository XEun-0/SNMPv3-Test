#include "snmp_manager.h"
#include "snmp_core.h"
#include "lwip/ip_addr.h"

// Assume lwIP IP address handling
ip4_addr_t target_ip;
IP4_ADDR(&target_ip, 192, 168, 1, 100);

// Prepare a single varbind (sysUpTime.0, no value needed for GET)
struct l_snmp_varbind varbinds[1];
varbinds[0].oid.id[0] = 1;
varbinds[0].oid.id[1] = 3;
varbinds[0].oid.id[2] = 6;
varbinds[0].oid.id[3] = 1;
varbinds[0].oid.id[4] = 2;
varbinds[0].oid.id[5] = 1;
varbinds[0].oid.id[6] = 1;
varbinds[0].oid.id[7] = 3;
varbinds[0].oid.id[8] = 0;
varbinds[0].oid.len = 9;
varbinds[0].value_type = SNMP_ASN1_NULL;  // for GET, value type is NULL
varbinds[0].value_len = 0;

// SNMPv3 parameters
u8_t engine_id[] = { 0x80, 0x00, 0x13, 0x70, 0x01 };  // Example Engine ID
u8_t engine_id_len = sizeof(engine_id);
u32_t engine_boots = 5;
u32_t engine_time = 123456;

u8_t auth_key[20]; // Pre-calculated SHA1 HMAC key
u8_t priv_key[20]; // Pre-calculated AES privacy key

// Normally hashedAuthKey and hashedPrivKey must be derived
// via password-to-key as per RFC 3414 (USM), already prepared here

s32_t request_id = 0;

snmp_manager_send(
    3,                                 // SNMPv3
    ip4_addr_get_u32(&target_ip),     // IP as u32_t
    varbinds,                          // Varbinds
    &request_id,                       // Request ID
    0,                                 // 0 = GET
    161,                               // SNMP port
    0,                                 // eth interface index (0 = default)
    "public",                          // Community (still required internally)
    engine_id,                         // Engine ID
    engine_id_len,                     // Engine ID length
    engine_boots,                      // Engine boots
    engine_time,                       // Engine time
    1,                                 // Auth enabled
    1,                                 // Privacy enabled
    auth_key,                          // Auth key (SHA1 hashed)
    priv_key                           // Privacy key (AES hashed)
);

#include <stdlib.h>
#include <string.h>

#define SNMP_ASN1_TYPE_OCTET_STRING 0x04
#define SNMP_MAX_OID_LEN 16

struct l_snmp_varbind {
    struct l_snmp_varbind *next;
    u8_t oid[SNMP_MAX_OID_LEN];
    u8_t oid_len;
    u8_t type;
    union {
        s32_t s32;
        u32_t u32;
        u8_t *str;
        u8_t *obj_id;
    } value;
    u16_t value_len;
};

// ANOTHER VARIATION OF VARBIND INIT
struct l_snmp_varbind* create_example_varbinds(void) {
    struct l_snmp_varbind* vb = malloc(sizeof(struct l_snmp_varbind));
    if (!vb) return NULL;

    // OID for sysContact.0 = 1.3.6.1.2.1.1.4.0
    u8_t oid[] = {1, 3, 6, 1, 2, 1, 1, 4, 0};
    vb->oid_len = sizeof(oid);
    memcpy(vb->oid, oid, vb->oid_len);

    vb->type = SNMP_ASN1_TYPE_OCTET_STRING;

    const char* str = "hello world";
    vb->value_len = strlen(str);

    vb->value.str = malloc(vb->value_len);
    if (!vb->value.str) {
        free(vb);
        return NULL;
    }

    memcpy(vb->value.str, str, vb->value_len);

    vb->next = NULL;
    return vb;
}

int main(void) {
    struct l_snmp_varbind* varbinds = create_example_varbinds();

    if (!varbinds) {
        printf("Failed to allocate varbinds\n");
        return -1;
    }

    // Example IP, auth/priv setup omitted for brevity
    snmp_manager_send(
        3,
        ipaddr_addr("192.168.1.10"),
        varbinds,
        &request_id,
        1,                      // SET
        161,
        0,
        "private",
        engine_id,
        sizeof(engine_id),
        5,
        123456,
        1,
        1,
        hashedAuthKey,
        hashedPrivKey
    );

    // Free memory later
    free(varbinds->value.str);
    free(varbinds);
}
