#include "lwip/api.h"
#include "lwip/inet.h"
#include "string.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "snmpv3_helpers.h" // your AES/HMAC/key derivation logic

#define SNMP_PORT 161

typedef enum {
    SNMPV3_INIT,
    SNMPV3_SENT_DISCOVERY,
    SNMPV3_GOT_ENGINE_INFO,
    SNMPV3_SENT_REAL_REQUEST,
    SNMPV3_DONE,
    SNMPV3_ERROR
} Snmpv3State;

static Snmpv3State state = SNMPV3_INIT;
static struct netconn* conn;

static ip_addr_t agent_ip; // set this from your config

static void send_snmpv3_discovery(struct netconn* conn) {
    uint8_t discovery_packet[128]; // example size
    size_t len = build_snmpv3_discovery(discovery_packet);  // fills in msg with empty auth/priv
    struct netbuf* buf = netbuf_new();
    void* data = netbuf_alloc(buf, len);
    memcpy(data, discovery_packet, len);
    netconn_send(conn, buf);
    netbuf_delete(buf);
}

static void send_snmpv3_real_request(struct netconn* conn) {
    uint8_t real_packet[256];
    size_t len = build_snmpv3_encrypted_request(real_packet);  // encrypt ScopedPDU and auth
    struct netbuf* buf = netbuf_new();
    void* data = netbuf_alloc(buf, len);
    memcpy(data, real_packet, len);
    netconn_send(conn, buf);
    netbuf_delete(buf);
}

static void handle_discovery_response(struct netbuf* buf) {
    uint8_t* packet = (uint8_t*)buf->p->payload;
    size_t len = buf->p->len;

    if (!parse_engine_info(packet, len)) {
        state = SNMPV3_ERROR;
        return;
    }

    state = SNMPV3_GOT_ENGINE_INFO;
}

static void handle_encrypted_response(struct netbuf* buf) {
    uint8_t* packet = (uint8_t*)buf->p->payload;
    size_t len = buf->p->len;

    if (!decrypt_and_parse_response(packet, len)) {
        state = SNMPV3_ERROR;
        return;
    }

    state = SNMPV3_DONE;
}

void snmpv3_task(void* arg) {
    struct netbuf* buf;

    conn = netconn_new(NETCONN_UDP);
    netconn_bind(conn, NULL, 0);
    IP4_ADDR(&agent_ip, 192, 168, 1, 100); // your agent IP
    netconn_connect(conn, &agent_ip, SNMP_PORT);
    netconn_set_recvtimeout(conn, 3000);  // Units: milliseconds

    while (state != SNMPV3_DONE && state != SNMPV3_ERROR) {
        switch (state) {
            case SNMPV3_INIT:
                send_snmpv3_discovery(conn);
                state = SNMPV3_SENT_DISCOVERY;
                break;

            case SNMPV3_SENT_DISCOVERY:
                if (netconn_recv(conn, &buf) == ERR_OK) {
                    handle_discovery_response(buf);
                    netbuf_delete(buf);
                }
                break;

            case SNMPV3_GOT_ENGINE_INFO:
                send_snmpv3_real_request(conn);
                state = SNMPV3_SENT_REAL_REQUEST;
                break;

            case SNMPV3_SENT_REAL_REQUEST:
                if (netconn_recv(conn, &buf) == ERR_OK) {
                    handle_encrypted_response(buf);
                    netbuf_delete(buf);
                }
                break;

            default:
                state = SNMPV3_ERROR;
                break;
        }
    }

    netconn_delete(conn);

    if (state == SNMPV3_DONE) {
        printf("SNMPv3 exchange complete!\n");
    } else {
        printf("SNMPv3 failed\n");
    }

    vTaskDelete(NULL);
}
