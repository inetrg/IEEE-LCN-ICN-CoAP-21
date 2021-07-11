#include "net/gcoap.h"
#include "msg.h"
#include "shell.h"
#include "evtimer.h"
#include "evtimer_msg.h"
#include "random.h"
#include "net/gnrc/netif.h"
#include <arpa/inet.h>
#include "net/nanocoap/cache.h"
#include "net/gcoap/forward_proxy.h"

#ifndef IPV6_PREFIX
#define IPV6_PREFIX         { 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0,  0, 0, 0, 0, 0, 0, 0, 0 }
#endif
#ifndef IPV6_PREFIX_LEN
#define IPV6_PREFIX_LEN     (64U)
#endif

gnrc_netif_t *mynetif;
uint8_t hwaddr[GNRC_NETIF_L2ADDR_MAXLEN];
char hwaddr_str[GNRC_NETIF_L2ADDR_MAXLEN * 3];
extern unsigned reqtx, resprx;

static const ipv6_addr_t _ipv6_prefix = { .u8 = IPV6_PREFIX };

ipv6_addr_t _my_link_local, _my_global;
uint16_t _my_id;
char _my_link_local_str[IPV6_ADDR_MAX_STR_LEN];
char _my_global_str[IPV6_ADDR_MAX_STR_LEN];
static bool gw_node = false;

#define MAIN_QUEUE_SIZE (4)
static msg_t _main_msg_queue[MAIN_QUEUE_SIZE];

extern gcoap_listener_t app_listener;
extern void send_static_request(uint16_t nodeid);
extern void send_static_request_proxy(uint16_t nodeid);
extern void install_routes(char *laddr, char *toaddr_str, char *nhaddr_str);

static const uint16_t narr[] = NARR;
static const size_t narr_sz = ARRAY_SIZE(narr);
static const char *gwaddrs[] = GWADDRS;
static evtimer_t evtimer;
static evtimer_msg_event_t events[ARRAY_SIZE(narr)];

static uint64_t start_time = 0;

#ifndef EVENTS
#define EVENTS (1000)
#endif
#define EVENT_TIME(i, start, current) (random_uint32_range(0, (i * 1000000) - (current - start)) / 1000)
//#define EVENT_TIME (1000 + random_uint32_range(0, 2000))
//#define EVENT_TIME (1000 + random_uint32_range(0, 500))
//#define EVENT_TIME (900 + random_uint32_range(0, 200))

void get_addr(uint16_t id, char *address)
{
#define MYMAP(ID,ADDR)                                          \
    if (id == ID) {                                             \
        memcpy(address, ADDR, strlen(ADDR)+1);                  \
        return;                                                 \
    }
#include "idaddr.inc"
#undef MYMAP
}

uint16_t get_id(char *address)
{
#define MYMAP(ID,ADDR)                                           \
    if (!memcmp(ADDR, address, strlen(ADDR))) {                  \
        return ID;                                               \
    }
#include "idaddr.inc"
#undef MYMAP
    return 0;
}

int get_proxy_nexthop(ipv6_addr_t *dest, ipv6_addr_t *nexthop)
{
    ipv6_addr_t dest_real = *dest;
    dest_real.u8[0] = 0x20;
    dest_real.u8[1] = 0x01;
    dest_real.u8[2] = 0x0d;
    dest_real.u8[3] = 0xb8;
    char dest_str[IPV6_ADDR_MAX_STR_LEN];
    char nexthop_str[IPV6_ADDR_MAX_STR_LEN];
    ipv6_addr_to_str(dest_str, &dest_real, sizeof(dest_str));
    ipv6_addr_to_str(nexthop_str, nexthop, sizeof(nexthop_str));
#define ROUTE(myid, laddr, toaddr, nhaddr)                              \
    if (_my_id == myid && !strcmp(dest_str, toaddr)) {                  \
        memcpy(nexthop_str, nhaddr, strlen(nhaddr)+1);                  \
        ipv6_addr_from_str(nexthop, nexthop_str);                       \
        return !strcmp(dest_str+8, nhaddr+4);                               \
    }
#include "routesdown.inc"
#undef ROUTE
    return 0;
}

typedef struct {
    int in_use;
    sock_udp_ep_t ep;
#if IS_ACTIVE(MODULE_NANOCOAP_CACHE)
    uint8_t cache_key[CONFIG_NANOCOAP_CACHE_KEY_LENGTH];
#endif
} client_ep_t;
static sock_udp_ep_t fwd_remote = { .family = AF_INET6, .port = COAP_PORT,};
ssize_t forward_to_forwarders(coap_pkt_t *client_pkt,
                              client_ep_t *client_ep,
                              ipv6_addr_t *nexthop_addr,
                              gcoap_resp_handler_t resp_handler)
{
    size_t len = client_pkt->payload_len + (client_pkt->payload - (uint8_t *)client_pkt->hdr);

    memcpy(&fwd_remote.addr.ipv6[0], &nexthop_addr->u8[0], sizeof(nexthop_addr->u8));
    fwd_remote.netif = (uint16_t) gnrc_netif_iter(NULL)->pid;

    printf("fqp;%04x\n", *((uint16_t *) client_pkt->token));
    len = gcoap_req_send((uint8_t *)client_pkt->hdr, len,
                         &fwd_remote,
                         resp_handler, (void *)client_ep);
    return len;
}

static int _send_get(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    start_time = xtimer_now_usec64();
    evtimer_init_msg(&evtimer);
    for (unsigned i = 0; i < narr_sz; i++) {
        events[i].event.offset = 100;
        events[i].msg.content.value = i;
        evtimer_add_msg(&evtimer, &events[i], thread_getpid());
    }
    unsigned i = 0;
    while ((i++) < EVENTS * narr_sz) {
        uint64_t _now;
        msg_t m;
        msg_receive(&m);
#if EXP_CONFIG_PROXY
        send_static_request_proxy(narr[m.content.value]);
#else
        send_static_request(narr[m.content.value]);
#endif
        _now = xtimer_now_usec64();
        events[m.content.value].event.offset = EVENT_TIME(i, start_time, _now);
        evtimer_add_msg(&evtimer, &events[m.content.value], thread_getpid());
    }
    return 0;
}

static int _start_exp(int argc, char **argv)
{
    (void)argc;
    (void)argv;

    if (gw_node) {
        puts("");
        puts("start");
        _send_get(0, NULL);
        xtimer_sleep(30);
        printf("end;%u;%u\n", reqtx, resprx);
    }
    return 0;
}

static const shell_command_t shell_commands[] = {
    { "send", "", _send_get },
    { "startexp", "", _start_exp },
    { NULL, NULL, NULL }
};

int main(void)
{
    gcoap_register_listener(&app_listener);

    /* initialize the forward proxy operation, if compiled */
    if (IS_ACTIVE(MODULE_GCOAP_FORWARD_PROXY)) {
        gcoap_forward_proxy_init();
    }

    msg_init_queue(_main_msg_queue, MAIN_QUEUE_SIZE);
    char line_buf[SHELL_DEFAULT_BUFSIZE];

    /* find first netif */
    mynetif = gnrc_netif_iter(NULL);

    uint16_t src_len = 8U;
    gnrc_netapi_set(mynetif->pid, NETOPT_SRC_LEN, 0, &src_len, sizeof(src_len));
#ifdef BOARD_NATIVE
    gnrc_netapi_get(mynetif->pid, NETOPT_ADDRESS, 0, hwaddr, sizeof(hwaddr));
#else
    gnrc_netapi_get(mynetif->pid, NETOPT_ADDRESS_LONG, 0, hwaddr, sizeof(hwaddr));
#endif
    gnrc_netif_addr_to_str(hwaddr, sizeof(hwaddr), hwaddr_str);

    /* get first ipv6 address from netif */
    gnrc_netif_ipv6_addrs_get(mynetif, &_my_link_local, sizeof(_my_link_local));
    ipv6_addr_to_str(_my_link_local_str, &_my_link_local, sizeof(_my_link_local_str));

    /* set global ipv6 address */
    memcpy(&_my_global, &_my_link_local, sizeof(_my_global));
    ipv6_addr_init_prefix(&_my_global, &_ipv6_prefix, IPV6_PREFIX_LEN);
    ipv6_addr_to_str(_my_global_str, &_my_global, sizeof(_my_global_str));
    gnrc_netif_ipv6_addr_add(mynetif, &_my_global, 128, GNRC_NETIF_IPV6_ADDRS_FLAGS_STATE_VALID);

//    netopt_enable_t opt = NETOPT_DISABLE;
//    opt = NETOPT_DISABLE;
//    gnrc_netapi_set(mynetif->pid, NETOPT_ACK_REQ, 0, &opt, sizeof(opt));

    for (unsigned i = 0; i < sizeof(gwaddrs) / sizeof(gwaddrs[0]); i++) {
        if (!strcmp(gwaddrs[i], _my_global_str)) {
            gw_node=true;
        }
    }

    _my_id = get_id(_my_global_str);

    void set_up_contexts(bool is_client);
    set_up_contexts(gw_node);

    printf("addr;%u;%s;%s;%s;%u\n", _my_id, hwaddr_str, _my_link_local_str, _my_global_str, gw_node);

#define ROUTE(myid, laddr, toaddr, nhaddr) install_routes(laddr, toaddr, nhaddr);
#include "routesdown.inc"
#include "routesup.inc"
#undef ROUTE

    random_init(*((uint32_t *)hwaddr));

    shell_run(shell_commands, line_buf, sizeof(line_buf));

    return 0;
}

void find_origin_server(sock_udp_ep_t *remote,
                            void *urip)
{
    (void)urip;
    remote->family = AF_INET6;
    remote->netif = mynetif->pid;
    remote->port = 5683;
    // All assuming there is only one way it goes down
#define ROUTE(myid, laddr, toaddr, nhaddr) ipv6_addr_from_str((void*)&remote->addr.ipv6, toaddr); remote->addr.ipv6[0] = 0xfe; remote->addr.ipv6[1] = 0x80; remote->addr.ipv6[2] = 0; remote->addr.ipv6[3] = 0; return;
#include "routesdown.inc"
#undef ROUTE
}
