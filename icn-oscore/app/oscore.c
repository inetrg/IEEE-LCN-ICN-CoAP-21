#include <net/gcoap.h>
#include <oscore_native/message.h>
#include <oscore/message.h>
#include <oscore/contextpair.h>
#include <oscore/context_impl/primitive.h>
#include <oscore/protection.h>

#define SENDER_KEY {50, 136, 42, 28, 97, 144, 48, 132, 56, 236, 152, 230, 169, 50, 240, 32, 112, 143, 55, 57, 223, 228, 109, 119, 152, 155, 3, 155, 31, 252, 28, 172}
#define RECIPIENT_KEY {213, 48, 30, 177, 141, 6, 120, 73, 149, 8, 147, 186, 42, 200, 145, 65, 124, 137, 174, 9, 223, 74, 56, 85, 170, 0, 10, 201, 255, 243, 135, 81}
#define COMMON_IV {100, 240, 189, 49, 77, 75, 224, 60, 39, 12, 43, 28, 17}

uint8_t skey[] = SENDER_KEY;
uint8_t rkey[] = RECIPIENT_KEY;
uint8_t civ[] = COMMON_IV;
char *sid = "\x08\x08";
extern uint16_t _my_id;

extern void temperature_parse(oscore_msg_protected_t *in, void *vstate);
extern void temperature_build(oscore_msg_protected_t *out, const void *vstate);
extern void get_addr(uint16_t id, char *address);
extern int get_proxy_nexthop(ipv6_addr_t *dest, ipv6_addr_t *address);

extern bool gw_node;

static sock_udp_ep_t remote = { .family = AF_INET6, .port = 5683,};

unsigned reqtx = 0, resprx = 0;
unsigned long rreqtx;

extern const uint16_t narr[LEAFNUM];

static struct oscore_context_primitive prims[ARRAY_SIZE(narr)];
static struct oscore_context_primitive_immutables immutables[ARRAY_SIZE(narr)];
static oscore_context_t seccs[ARRAY_SIZE(narr)];

static struct oscore_context_primitive_immutables immutable;
static struct oscore_context_primitive prim;
static oscore_context_t secc;

void init_security(void)
{
    for (unsigned i = 0; i < ARRAY_SIZE(narr); i++) {
        immutables[i].aeadalg = 10;
        memcpy(immutables[i].common_iv, civ, ARRAY_SIZE(civ));
        immutables[i].recipient_id_len = 0;
        memcpy(immutables[i].recipient_key, rkey, ARRAY_SIZE(rkey));
        immutables[i].sender_id_len = 2;
        memcpy(immutables[i].sender_id, sid, strlen(sid));
        memcpy(immutables[i].sender_key, skey, ARRAY_SIZE(skey));
        prims[i].immutables = &immutables[i];
        seccs[i].type = OSCORE_CONTEXT_PRIMITIVE;
        seccs[i].data = (void*)(&prims[i]);
    }
    immutable.aeadalg = 10;
    memcpy(immutable.common_iv, civ, ARRAY_SIZE(civ));
    immutable.recipient_id_len = 2;
    memcpy(immutable.recipient_id, sid, strlen(sid));
    memcpy(immutable.recipient_key, skey, ARRAY_SIZE(skey));
    immutable.sender_id_len = 0;
    memcpy(immutable.sender_key, rkey, ARRAY_SIZE(rkey));
    prim.immutables = &immutable;
    secc.type = OSCORE_CONTEXT_PRIMITIVE;
    secc.data = (void*)(&prim);
}

oscore_context_t *get_security(uint16_t recipient_id)
{
    (void) recipient_id;
    if (gw_node) {
#define MYMAP(NR,LR,ID,ADDR) if (recipient_id == ID) { return &seccs[LR]; }
#include "idaddr.inc"
#undef MYMAP
    return NULL;
    }
    return &secc;
}

ssize_t app_oscore(coap_pkt_t *pdu, uint8_t *buf, size_t len, void *ctx)
{
    (void) ctx;

    enum oscore_unprotect_request_result oscerr;
    oscore_oscoreoption_t header;
    oscore_requestid_t request_id;
    const char *errormessage = "";
    (void) errormessage;

    uint8_t errorcode = COAP_CODE_INTERNAL_SERVER_ERROR;

    // This is nanocoap's shortcut (compare to unprotect-demo, where we iterate through the outer options)
    uint8_t *header_data;
    ssize_t header_size = coap_opt_get_opaque(pdu, 9, &header_data);
    if (header_size < 0) {
        errormessage = "No OSCORE option found";
        // Having a </> resource in parallel to OSCORE is not supported here.
        errorcode = COAP_CODE_PATH_NOT_FOUND;
        goto error;
    }
    bool parsed = oscore_oscoreoption_parse(&header, header_data, header_size);
    if (!parsed) {
        errormessage = "OSCORE option unparsable";
        errorcode = COAP_CODE_BAD_OPTION;
        goto error;
    }

    // FIXME: this should be in a dedicated parsed_pdu_to_oscore_msg_native_t process
    // (and possibly foolishly assuming that there is a payload marker)
    pdu->payload --;
    pdu->payload_len ++;
    oscore_msg_native_t pdu_read = { .pkt = pdu };
    oscore_msg_protected_t incoming_decrypted;

    oscore_context_t *mysecc = &secc;
    oscerr = oscore_unprotect_request(pdu_read, &incoming_decrypted, header, mysecc, &request_id);

    if (oscerr != OSCORE_UNPROTECT_REQUEST_OK) {
        if (oscerr != OSCORE_UNPROTECT_REQUEST_DUPLICATE) {
            errormessage = "Unprotect failed";
            errorcode = COAP_CODE_BAD_REQUEST;
            goto error;
        }
    }

    uint16_t responsecode;
    temperature_parse(&incoming_decrypted, &responsecode);

    oscore_release_unprotected(&incoming_decrypted);
    printf("rxq;%04x\n", *((uint16_t *) pdu->token));

    gcoap_resp_init(pdu, buf, len, COAP_CODE_CONTENT);

    enum oscore_prepare_result oscerr2;
    oscore_msg_native_t pdu_write = { .pkt = pdu };
    oscore_msg_protected_t outgoing_plaintext;

    oscerr2 = oscore_prepare_response(pdu_write, &outgoing_plaintext, mysecc, &request_id);
    if (oscerr2 != OSCORE_PREPARE_OK) {
        errormessage = "Context not usable";
        errorcode = COAP_CODE_SERVICE_UNAVAILABLE;
        goto error;
    }

    temperature_build(&outgoing_plaintext, &responsecode);

    enum oscore_finish_result oscerr4;
    oscore_msg_native_t pdu_write_out;
    oscerr4 = oscore_encrypt_message(&outgoing_plaintext, &pdu_write_out);
    if (oscerr4 != OSCORE_FINISH_OK) {
        errormessage = "Error finishing";
        goto error;
    }

    printf("txp;%04x\n", *((uint16_t *) pdu->token));
    return (pdu->payload - buf) + pdu->payload_len;

error:
    printf("error;%s;%04x\n", errormessage, *((uint16_t *) pdu->token));
    return gcoap_response(pdu, buf, len, errorcode);
}

static void handle_static_response(const struct gcoap_request_memo *memo, coap_pkt_t *pdu, const sock_udp_ep_t *remote)
{
    (void)remote;

    oscore_requestid_t *request_id = (oscore_requestid_t *)&memo->oscore_request_id;

    if (memo->state != GCOAP_MEMO_RESP) {
        printf("err;p;%04x\n", *((uint16_t *) coap_hdr_data_ptr(pdu->hdr)));
        return;
    }
    oscore_oscoreoption_t header;

    // This is nanocoap's shortcut (compare to unprotect-demo, where we iterate through the outer options)
    uint8_t *header_data;
    ssize_t header_size = coap_opt_get_opaque(pdu, 9, &header_data);
    if (header_size < 0) {
        printf("error;No OSCORE option in response!;%04x\n", *((uint16_t *) coap_hdr_data_ptr(pdu->hdr)));
        return;
    }
    bool parsed = oscore_oscoreoption_parse(&header, header_data, header_size);
    if (!parsed) {
        printf("error;OSCORE option unparsable\n");
        return;
    }
    // FIXME: this should be in a dedicated parsed_pdu_to_oscore_msg_native_t process
    // (and possibly foolishly assuming that there is a payload marker)
    pdu->payload --;
    pdu->payload_len ++;
    oscore_msg_native_t pdu_read = { .pkt = pdu };

    oscore_msg_protected_t msg;

    oscore_context_t *mysecc = (oscore_context_t *)request_id->sctx;
    enum oscore_unprotect_response_result success = oscore_unprotect_response(pdu_read, &msg, header, mysecc, request_id);

    if (success == OSCORE_UNPROTECT_RESPONSE_OK) {
        uint8_t code = oscore_msg_protected_get_code(&msg);
        if (code == COAP_CODE_205) {
            //printf("Result: Changed\n");
        }
        else {
            //printf("Unknown code in result: %d.%d\n", code >> 5, code & 0x1f);
            return;
        }
    } else {
        printf("error;unprotecting response\n");
        return;
    }

    uint8_t *payload;
    size_t payload_length;
    oscore_msgerr_protected_t err = oscore_msg_protected_map_payload(&msg, &payload, &payload_length);
    if (oscore_msgerr_protected_is_error(err)) {
        printf("error;accessing payload\n");
        return;
    }
//    uint16_t temp;
//    memcpy(&temp, payload, sizeof(temp));
    printf("rxp;%04x\n", *((uint16_t *) pdu->token));
    resprx++;
    return;
}

void send_static_request(uint16_t nodeid) __attribute__((unused));
void send_static_request(uint16_t nodeid) {
    uint8_t buf[CONFIG_GCOAP_PDU_BUF_SIZE];
    coap_pkt_t pdu;
    oscore_msg_protected_t oscmsg;
    oscore_requestid_t request_id;
    ipv6_addr_t addr;
    static unsigned thetime = 0;

    reqtx++;

    remote.netif = (uint16_t) gnrc_netif_iter(NULL)->pid;

    /* parse destination address */
    char addrstr[48];
    get_addr(nodeid, addrstr);
    ipv6_addr_from_str(&addr, addrstr);
    memcpy(&remote.addr.ipv6[0], &addr.u8[0], sizeof(addr.u8));

    // Can't pre-set a path, the request must be empty at protection time
    int err;
    err = gcoap_req_init(&pdu, buf, sizeof(buf), COAP_POST, NULL);
    if (err != 0) {
        printf("error;Failed to initialize request\n");
        return;
    }

#if EXP_CONFIG_CON
    coap_hdr_set_type(pdu.hdr, COAP_TYPE_CON);
#else
    coap_hdr_set_type(pdu.hdr, COAP_TYPE_NON);
#endif

    oscore_msg_native_t native = { .pkt = &pdu };

    oscore_context_t *mysecc = get_security(nodeid);
    if (oscore_prepare_request(native, &oscmsg, mysecc, &request_id) != OSCORE_PREPARE_OK) {
        printf("error;Failed to prepare request encryption\n");
        return;
    }

    oscore_msg_protected_set_code(&oscmsg, COAP_GET);
    
    oscore_msgerr_protected_t oscerr;
    oscerr = oscore_msg_protected_append_option(&oscmsg, COAP_OPT_URI_PATH, (uint8_t*)"temperature", 11);
    if (oscore_msgerr_protected_is_error(oscerr)) {
        printf("error;Failed to add path option\n");
        return;
    }
    char query_str[8];
    snprintf(query_str, 8, "t=%04u", thetime++);
    oscerr = oscore_msg_protected_append_option(&oscmsg, COAP_OPT_URI_QUERY, (uint8_t*)query_str, 6);

    if (oscore_msgerr_protected_is_error(oscerr)) {
        printf("error;Failed to add query option\n");
        return;
    }

    oscerr = oscore_msg_protected_trim_payload(&oscmsg, 0);
    if (oscore_msgerr_protected_is_error(oscerr)) {
        printf("error;Failed to truncate payload\n");
        return;
    }

    oscore_msg_native_t pdu_write_out;
    if (oscore_encrypt_message(&oscmsg, &pdu_write_out) != OSCORE_FINISH_OK) {
        printf("error;Failed to encrypt message\n");
        return;
    }

    request_id.sctx = (void *)mysecc;

    int bytes_sent = gcoap_req_send(buf, pdu.payload - (uint8_t*)pdu.hdr + pdu.payload_len, &remote, handle_static_response, &request_id);
    if (bytes_sent <= 0) {
        printf("err;qs\n");
        return;
    }
    printf("txq;%04x;%u\n", *((uint16_t *) pdu.token), nodeid);

    return;
}

void send_static_request_proxy(uint16_t nodeid) __attribute__((unused));
void send_static_request_proxy(uint16_t nodeid) {
    uint8_t buf[CONFIG_GCOAP_PDU_BUF_SIZE];
    coap_pkt_t pdu;
    oscore_msg_protected_t oscmsg;
    oscore_requestid_t request_id;
    ipv6_addr_t addr, dst;
    static unsigned thetime = 0;

    reqtx++;

    remote.netif = (uint16_t) gnrc_netif_iter(NULL)->pid;

    /* parse destination address */
    char addrstr[48];
    char proxy_uri[64];

    get_addr(nodeid, addrstr);
    ipv6_addr_from_str(&dst, addrstr);
    get_proxy_nexthop(&dst, &addr);

    size_t proxy_uri_len = snprintf(proxy_uri, 120, "coap://[%s]:%u", addrstr, 5683);

    memcpy(&remote.addr.ipv6[0], &addr.u8[0], sizeof(addr.u8));

    // Can't pre-set a path, the request must be empty at protection time
    int err;
    err = gcoap_req_init(&pdu, buf, sizeof(buf), COAP_POST, NULL);
    if (err != 0) {
        printf("err;qb\n");
        return;
    }

#if EXP_CONFIG_CON
    coap_hdr_set_type(pdu.hdr, COAP_TYPE_CON);
#else
    coap_hdr_set_type(pdu.hdr, COAP_TYPE_NON);
#endif

    oscore_msg_native_t native = { .pkt = &pdu };

    oscore_context_t *mysecc = get_security(nodeid);
    if (oscore_prepare_request(native, &oscmsg, mysecc, &request_id) != OSCORE_PREPARE_OK) {
        printf("error;Failed to prepare request encryption\n");
        return;
    }

    memcpy((void *)(((struct oscore_context_primitive *)(mysecc->data))->immutables->sender_id), &_my_id, sizeof(_my_id));

    oscore_msg_protected_set_code(&oscmsg, COAP_GET);
    
    oscore_msgerr_protected_t oscerr;

    oscerr = oscore_msg_protected_append_option(&oscmsg, COAP_OPT_PROXY_URI, (uint8_t *)proxy_uri, proxy_uri_len);
    if (oscore_msgerr_protected_is_error(oscerr)) {
        printf("error;Failed to add proxy option\n");
        return;
    }

    oscerr = oscore_msg_protected_append_option(&oscmsg, COAP_OPT_URI_PATH, (uint8_t*)"temperature", 11);
    if (oscore_msgerr_protected_is_error(oscerr)) {
        printf("error;Failed to add path option\n");
        return;
    }

    char query_str[8];
    snprintf(query_str, 8, "t=%04u", thetime++);
    oscerr = oscore_msg_protected_append_option(&oscmsg, COAP_OPT_URI_QUERY, (uint8_t*)query_str, 6);

    if (oscore_msgerr_protected_is_error(oscerr)) {
        printf("error;Failed to add query option\n");
        return;
    }

    oscerr = oscore_msg_protected_trim_payload(&oscmsg, 0);
    if (oscore_msgerr_protected_is_error(oscerr)) {
        printf("error;Failed to truncate payload\n");
        return;
    }

    memcpy((void *)(((struct oscore_context_primitive *)(mysecc->data))->immutables->sender_id), sid, strlen(sid));

    oscore_msg_native_t pdu_write_out;
    if (oscore_encrypt_message(&oscmsg, &pdu_write_out) != OSCORE_FINISH_OK) {
        printf("error;Failed to encrypt message\n");
        return;
    }

    request_id.sctx = (void *)mysecc;

    int bytes_sent = gcoap_req_send(buf, pdu.payload - (uint8_t*)pdu.hdr + pdu.payload_len, &remote, handle_static_response, &request_id);
    if (bytes_sent <= 0) {
        printf("err;qs\n");
        return;
    }
    printf("txq;%04x;%u\n", *((uint16_t *) pdu.token), nodeid);

    return;
}
