#include <net/gcoap.h>
#include "od.h"

#include <oscore/contextpair.h>
#include <oscore/protection.h>
#include <nanocoap_oscore_msg_conversion.h>

unsigned reqtx = 0, resprx = 0;
unsigned long rreqtx;

static sock_udp_ep_t remote = { .family = AF_INET6, .port = COAP_PORT,};

#define REQUESTHASH_LEN 16

static struct {
    bool used;
    // If we weren't using the tokens for uniqley identifying requests, we
    // could transport a unique application-level identifier her as well
    oscore_requestid_t reqid;
    uint8_t requesthash[REQUESTHASH_LEN];
} requestslots[CONFIG_GCOAP_REQ_WAITING_MAX + 1 /* as we're free-spinningly
      generating requests, limiting them to the memos ensures we don't run out
      of these before we run out of those */];

extern uint16_t _my_id;
extern void get_addr(uint16_t id, char *address);
extern int get_proxy_nexthop(ipv6_addr_t *dest, ipv6_addr_t *address);

static void handle_static_response(const struct gcoap_request_memo *memo, coap_pkt_t *pdu, const sock_udp_ep_t *remote)
{
    (void)remote;

    /* FIXME: verify the response; we have all the pieces to do that. */

    size_t requestslot = (size_t)memo->context;

    if (memo->state != GCOAP_MEMO_RESP) {
        printf("err;p;%04x\n", *((uint16_t *) coap_hdr_data_ptr(pdu->hdr)));
        requestslots[requestslot].used = false;
        return;
    }

    printf("rxp;%04x\n", *((uint16_t *) pdu->token));
    resprx++;

    requestslots[requestslot].used = false;
    return;
}

extern void prepare_pairwise_for_hash(void);
extern void configure_pairwise_for_hash(uint8_t *requesthash, size_t requesthash_len);
extern oscore_context_t detcontext;
extern oscore_context_t groupcontext;

void send_static_request_proxy(uint16_t nodeid) __attribute__ ((unused));
void send_static_request_proxy(uint16_t nodeid) {
    uint8_t buf[CONFIG_GCOAP_PDU_BUF_SIZE];
    coap_pkt_t pdu;
    ipv6_addr_t addr, dst;
    ssize_t bytes;
    static unsigned thetime = 0;

    reqtx++;

    remote.netif = (uint16_t) gnrc_netif_iter(NULL)->pid;

    /* parse destination address */
    char addrstr[48];
    char proxy_uri[64];
    char uri_query[64];
    int len = 0;

    get_addr(nodeid, addrstr);
    ipv6_addr_from_str(&dst, addrstr);
    get_proxy_nexthop(&dst, &addr);

    (void) thetime;
    snprintf(proxy_uri, 120, "coap://2d-3e");
    snprintf(uri_query, 64, "t=%04u", thetime++);
    //snprintf(proxy_uri, 120, "coap://[%s]:%u/temperature", addrstr, 5683);

    oscore_msgerr_protected_t oscerr;
    oscore_msg_native_t native;
    oscore_msg_protected_t oscmsg;
    // Stored locally until the memo is available to store it there
    oscore_requestid_t requestid;

    bytes = gcoap_req_init(&pdu, &buf[0], CONFIG_GCOAP_PDU_BUF_SIZE, COAP_METHOD_POST, NULL);
    if (bytes < 0) {
        goto err;
    }

#if EXP_CONFIG_CON
    coap_hdr_set_type(pdu.hdr, COAP_TYPE_CON);
#else
    coap_hdr_set_type(pdu.hdr, COAP_TYPE_NON);
#endif

    uint8_t *gcoap_observe_data;
    int8_t gcoap_observe_length;
    oscore_msg_native_from_gcoap_outgoing(&native, &pdu, &gcoap_observe_length, &gcoap_observe_data);
    /* not doing observation -- why do we still have to acknowledge that the libOSCORE binding may just have dumped the observe value? */
    (void)gcoap_observe_data;
    (void)gcoap_observe_length;
    prepare_pairwise_for_hash();

    if (oscore_prepare_request(native, &oscmsg, &detcontext, &requestid) != OSCORE_PREPARE_OK) {
        goto err;
    }

    /* out of sequence for plain coap, but in sequence for oscore */
    oscerr = oscore_msg_protected_append_option(&oscmsg, 35 /* Proxy-Uri */, (uint8_t*)proxy_uri, strlen(proxy_uri));
    if (oscore_msgerr_protected_is_error(oscerr)) {
        goto err;
    }

    /* it's a bit of a shortcut to populate this from the time directly, but
     * it's not like we'd already have a spec for that
     *
     * (if the hash were really fully calculated, we'd need to revisit the
     * option populated with a blank)
     * */
    uint8_t request_hash[REQUESTHASH_LEN] = {thetime % 256, thetime >> 8, 0, /* ... */};
    oscerr = oscore_msg_protected_append_option(&oscmsg, 548 /* Request-Hash */, request_hash, REQUESTHASH_LEN);
    if (oscore_msgerr_protected_is_error(oscerr)) {
        goto err;
    }

    oscore_msg_protected_set_code(&oscmsg, COAP_GET);

    oscerr = oscore_msg_protected_append_option(&oscmsg, 11 /* Uri-Path */, (uint8_t*)"temperature", 11);
    if (oscore_msgerr_protected_is_error(oscerr)) {
        goto err;
    }

    oscerr = oscore_msg_protected_append_option(&oscmsg, 15 /* Uri-Query */, (uint8_t*)uri_query, strlen(uri_query));
    if (oscore_msgerr_protected_is_error(oscerr)) {
        goto err;
    }

    oscerr = oscore_msg_protected_trim_payload(&oscmsg, 0);
    if (oscore_msgerr_protected_is_error(oscerr)) {
        goto err;
    }

    /* OSCORE option is flushed out, we could calculate a hash now */
    configure_pairwise_for_hash(request_hash, REQUESTHASH_LEN);

    if (oscore_encrypt_message(&oscmsg, &native) != OSCORE_FINISH_OK) {
        // see FIXME in oscore_encrypt_message description
        assert(false);
    }

    len = pdu.payload - (uint8_t*)pdu.hdr + pdu.payload_len;

    ssize_t requestslot = -1;
    for (size_t i = 0; i < sizeof(requestslots)/sizeof(requestslots[0]); ++i) {
        if (requestslots[i].used == false) {
            requestslot = i;
            break;
        }
    }
    if (requestslot == -1) {
        goto err;
    }
    requestslots[requestslot].used = true;
    // Plainly copying this around is OK here because our own copy is about to
    // be deallocated: we're just moving
    requestslots[requestslot].reqid = requestid;
    memcpy(requestslots[requestslot].requesthash, request_hash, REQUESTHASH_LEN);

    memcpy(&remote.addr.ipv6[0], &addr.u8[0], sizeof(addr.u8));
    bytes = gcoap_req_send(buf, len, &remote, handle_static_response, (void*)requestslot);

    if (bytes <= 0) {
        printf("err;qs\n");
        return;
    }

    printf("txq;%04x;%u\n", *((uint16_t *) pdu.token), nodeid);
    return;

err:
    printf("err;qb\n");
    return;
}

void send_static_request(uint16_t nodeid) __attribute__ ((unused));
void send_static_request(uint16_t nodeid) {
    uint8_t buf[CONFIG_GCOAP_PDU_BUF_SIZE];
    coap_pkt_t pdu;
    ipv6_addr_t addr;
    ssize_t bytes;

    reqtx++;

    remote.netif = (uint16_t) gnrc_netif_iter(NULL)->pid;

    /* parse destination address */
    char addrstr[48];

    get_addr(nodeid, addrstr);
    ipv6_addr_from_str(&addr, addrstr);

    bytes = gcoap_request(&pdu, &buf[0], CONFIG_GCOAP_PDU_BUF_SIZE, COAP_METHOD_GET, "/temperature");
    if (bytes < 0) {
        printf("err;qb\n");
        return;
    }

#if EXP_CONFIG_CON
    coap_hdr_set_type(pdu.hdr, COAP_TYPE_CON);
#else
    coap_hdr_set_type(pdu.hdr, COAP_TYPE_NON);
#endif

    memcpy(&remote.addr.ipv6[0], &addr.u8[0], sizeof(addr.u8));
    bytes = gcoap_req_send(buf, pdu.payload - (uint8_t*)pdu.hdr + pdu.payload_len, &remote, handle_static_response, NULL);

    if (bytes <= 0) {
        printf("err;qs\n");
        return;
    }

    printf("txq;%04x;%u\n", *((uint16_t *) pdu.token), nodeid);
    return;
}

static ssize_t app_coap(coap_pkt_t* pdu, uint8_t *buf, size_t len, void *ctx)
{
    (void)ctx;
    printf("rxq;%04x\n", *((uint16_t *) pdu->token));
    gcoap_resp_init(pdu, buf, len, COAP_CODE_CONTENT);
    size_t resp_len = coap_opt_finish(pdu, COAP_OPT_FINISH_PAYLOAD);

    uint16_t temp = 2124;

    xtimer_usleep(20 * 1000);

    printf("txp;%04x\n", *((uint16_t *) pdu->token));
    return resp_len + sizeof(temp);
}

static ssize_t app_oscore(coap_pkt_t* pdu, uint8_t *buf, size_t len, void *ctx)
{
    (void)ctx;

    enum oscore_unprotect_request_result oscerr;
    oscore_oscoreoption_t header;
    oscore_requestid_t request_id;
    const char *errormessage = "";
    uint8_t *request_hash;

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
    ssize_t request_hash_len = coap_opt_get_opaque(pdu, 548, &request_hash);
    if (request_hash_len != REQUESTHASH_LEN) {
        errormessage = "No good Request-Hash";
        errorcode = COAP_CODE_BAD_REQUEST;
        goto error;
    }
    bool parsed = oscore_oscoreoption_parse(&header, header_data, header_size);
    if (!parsed) {
        errormessage = "OSCORE option unparsable";
        errorcode = COAP_CODE_BAD_OPTION;
        goto error;
    }

    oscore_msg_native_t native;
    oscore_msg_protected_t incoming_decrypted;
    oscore_msg_native_from_nanocoap_incoming(&native, pdu);

    prepare_pairwise_for_hash();
    configure_pairwise_for_hash(request_hash, REQUESTHASH_LEN);
    oscore_context_t *mysecc = &detcontext;
    oscerr = oscore_unprotect_request(native, &incoming_decrypted, header, mysecc, &request_id);
    if (oscerr != OSCORE_UNPROTECT_REQUEST_OK) {
        /* Not accepting duplicates b/c the deterministic context always starts at 0 */
        errormessage = "Unprotect failed";
        errorcode = COAP_CODE_BAD_REQUEST;
        goto error;
    }

    if (oscore_msg_protected_get_code(&incoming_decrypted) != COAP_GET) {
        errormessage = "Not an inner GET";
        errorcode = COAP_CODE_METHOD_NOT_ALLOWED; // should rather be inner
        goto error;
    }

    // Ignoring the path etc -- we're always sending the same response anyway

    printf("rxq;%04x\n", *((uint16_t *) pdu->token));
    // just to verify nothing went awry
    uint16_t oldtoken = *(uint16_t *)pdu->token;
    gcoap_resp_init(pdu, buf, len, COAP_CODE_CONTENT);
    assert(*(uint16_t *)pdu->token == oldtoken);

    enum oscore_prepare_result oscerr2;
    oscore_msg_native_t pdu_write;

    uint8_t *gcoap_observe_data;
    int8_t gcoap_observe_length;
    oscore_msg_native_from_gcoap_outgoing(&pdu_write, pdu, &gcoap_observe_length, &gcoap_observe_data);
    assert(*(uint16_t *)pdu->token == oldtoken);
    /* not doing observation -- why do we still have to acknowledge that the libOSCORE binding may just have dumped the observe value? */
    (void)gcoap_observe_data;
    (void)gcoap_observe_length;

    oscore_msg_protected_t outgoing_plaintext;
    oscerr2 = oscore_prepare_response(pdu_write, &outgoing_plaintext, &groupcontext, &request_id);
    if (oscerr2 != OSCORE_PREPARE_OK) {
        errormessage = "Context not usable";
        errorcode = COAP_CODE_SERVICE_UNAVAILABLE;
        goto error;
    }

    oscore_msg_protected_set_code(&outgoing_plaintext, COAP_CODE_CONTENT);

    uint8_t *payload;
    size_t payload_length;
    oscore_msgerr_native_t err = oscore_msg_protected_map_payload(&outgoing_plaintext, &payload, &payload_length);
    assert(!oscore_msgerr_protected_is_error(err));
    assert(payload_length >= 2);
    payload[0] = 0x08;
    payload[1] = 0x15;
    oscore_msg_protected_trim_payload(&outgoing_plaintext, 2);

    assert(*(uint16_t *)pdu->token == oldtoken);

    enum oscore_finish_result oscerr4;
    oscerr4 = oscore_encrypt_message(&outgoing_plaintext, &pdu_write);
    if (oscerr4 != OSCORE_FINISH_OK) {
        errormessage = "Error finishing";
        // FIXME verify that this truncates the response
        goto error;
    }

    printf("txp;%04x\n", *((uint16_t *) pdu->token));
    assert(*(uint16_t *)pdu->token == oldtoken);

    // FIXME we'll have to pick that from pdu, or make the oscore_msg_native_t enriched by a length
    return (pdu->payload - buf) + pdu->payload_len;

error:
    printf("error;%s;%04x\n", errormessage, *((uint16_t *) pdu->token));
    return gcoap_response(pdu, buf, len, errorcode);
}

static const coap_resource_t _resources[] = {
    { "/", COAP_POST, app_oscore, NULL },
    { "/temperature", COAP_GET, app_coap, NULL },
};

gcoap_listener_t app_listener = {
    &_resources[0],
    ARRAY_SIZE(_resources),
    NULL,
    NULL,
    NULL
};
