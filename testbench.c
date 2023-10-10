#include "pub.h"

#define TESTBENCH_MAX_INST              8
// #define TESTBENCH_ECHO_CHECK            1
static volatile int g_stop = 0;
typedef struct {
    int                 valid;
    int                 idx;
    vacc_host_t         vacc_host;
    fgfw_epoll_inst_t   epoll_inst;
} testbench_inst_t;

typedef struct {
    uint32_t            magic;              /* TESTBENCH_PKT_MAGIC */
    uint16_t            type;
    uint16_t            cnt;
    uint32_t            payload_len;
    uint32_t            crc;
} testbench_pkt_head_t;

#define TESTBENCH_PKT_MAGIC             0x1357acbd

#define TESTBENCH_PKT_MAXLEN            (16 * 1024)

typedef struct {
    testbench_inst_t            inst_pool[TESTBENCH_MAX_INST];
    fgfw_epoll_thread_t         epoll_thread;
    uint8_t                     sendbuf[TESTBENCH_PKT_MAXLEN];
} testbench_ctx_t;

static vacc_host_t* testbench_get(struct _vacc_host *vacc_host, void *opaque)
{
    int i;
    testbench_ctx_t *tb_ctx = (testbench_ctx_t *)opaque;
    testbench_inst_t *inst;
    
    for (i = 0; i < TESTBENCH_MAX_INST; i++) {
        if (tb_ctx->inst_pool[i].valid == 0) {
            break;
        }
    }
    
    if (i == TESTBENCH_MAX_INST) {
        return NULL;
    }

    inst = &(tb_ctx->inst_pool[i]);
    memset(inst, 0, sizeof(testbench_inst_t));
    inst->idx = i;
    inst->valid = 1;

    return &(inst->vacc_host);
}

static void testbench_put(struct _vacc_host *vacc_host, void *opaque)
{
    testbench_inst_t *inst = FGFW_GETCONTAINER(vacc_host, testbench_inst_t, vacc_host);
    inst->valid = 0;
}

static void testbench_epoll_inst_cb(fgfw_epoll_inst_t *epoll_inst)
{
    testbench_inst_t *inst = FGFW_GETCONTAINER(epoll_inst, testbench_inst_t, epoll_inst);
    vacc_host_read(&(inst->vacc_host));
}

static int testbench_init(struct _vacc_host *vacc_host, void *opaque)
{
    testbench_ctx_t *tb_ctx = (testbench_ctx_t *)opaque;
    testbench_inst_t *inst = FGFW_GETCONTAINER(vacc_host, testbench_inst_t, vacc_host);

    switch (vacc_host->insttype) {
    case VACC_HOST_INSTTYPE_SERVER_LISTENER:
        fgfw_log("%s listen socket init, idx %d\n",
            vacc_host->transtype == VACC_HOST_TRANSTYPE_TCP ? "TCP" :
            vacc_host->transtype == VACC_HOST_TRANSTYPE_UDS ? "UDS" :
            vacc_host->transtype == VACC_HOST_TRANSTYPE_UDP ? "UDP" :
            "UNKNOWN",
            inst->idx);
        break;
    case VACC_HOST_INSTTYPE_SERVER_INST:
        fgfw_log("%s server inst connect, idx %d\n",
            vacc_host->transtype == VACC_HOST_TRANSTYPE_TCP ? "TCP" :
            vacc_host->transtype == VACC_HOST_TRANSTYPE_UDS ? "UDS" :
            vacc_host->transtype == VACC_HOST_TRANSTYPE_UDP ? "UDP" :
            "UNKNOWN",
            inst->idx);
        if (vacc_host->transtype == VACC_HOST_TRANSTYPE_TCP) {
            struct in_addr in = vacc_host->u.tcp.cli_addr.sin_addr;
            unsigned short port = ntohs(vacc_host->u.tcp.cli_addr.sin_port);
            char ipstr[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &in, ipstr, sizeof(ipstr));
            fgfw_log("\t\tclient: %s(%d)\n", ipstr, port);
        } else if (vacc_host->transtype == VACC_HOST_TRANSTYPE_UDS) {

        }

        break;
    case VACC_HOST_INSTTYPE_CLIENT_INST:
        fgfw_log("%s client inst connect, idx %d\n",
            vacc_host->transtype == VACC_HOST_TRANSTYPE_TCP ? "TCP" :
            vacc_host->transtype == VACC_HOST_TRANSTYPE_UDS ? "UDS" :
            vacc_host->transtype == VACC_HOST_TRANSTYPE_UDP ? "UDP" :
            "UNKNOWN",
            inst->idx);
        break;
    default:
        fgfw_log("vacc_host_init() unknown inst type %d\n", vacc_host->insttype);
        return -1;
    }

    inst->epoll_inst.epoll_inst_cb = testbench_epoll_inst_cb;
    inst->epoll_inst.fd = vacc_host->sock_fd;
    fgfw_epoll_thread_reg_inst(&(tb_ctx->epoll_thread), &(inst->epoll_inst), 0);

    return 0;
}

static int testbench_uninit(struct _vacc_host *vacc_host, void *opaque)
{
    testbench_ctx_t *tb_ctx = (testbench_ctx_t *)opaque;
    testbench_inst_t *inst = FGFW_GETCONTAINER(vacc_host, testbench_inst_t, vacc_host);

    switch (vacc_host->insttype) {
    case VACC_HOST_INSTTYPE_SERVER_LISTENER:
        fgfw_log("%s listen socket uninit, idx %d\n",
            vacc_host->transtype == VACC_HOST_TRANSTYPE_TCP ? "TCP" :
            vacc_host->transtype == VACC_HOST_TRANSTYPE_UDS ? "UDS" :
            vacc_host->transtype == VACC_HOST_TRANSTYPE_UDP ? "UDP" :
            "UNKNOWN",
            inst->idx);
        break;
    case VACC_HOST_INSTTYPE_SERVER_INST:
        fgfw_log("%s server inst disconnect, idx %d\n",
            vacc_host->transtype == VACC_HOST_TRANSTYPE_TCP ? "TCP" :
            vacc_host->transtype == VACC_HOST_TRANSTYPE_UDS ? "UDS" :
            vacc_host->transtype == VACC_HOST_TRANSTYPE_UDP ? "UDP" :
            "UNKNOWN",
            inst->idx);
        break;
    case VACC_HOST_INSTTYPE_CLIENT_INST:
        fgfw_log("%s client inst disconnect, idx %d\n",
            vacc_host->transtype == VACC_HOST_TRANSTYPE_TCP ? "TCP" :
            vacc_host->transtype == VACC_HOST_TRANSTYPE_UDS ? "UDS" :
            vacc_host->transtype == VACC_HOST_TRANSTYPE_UDP ? "UDP" :
            "UNKNOWN",
            inst->idx);
        break;
    default:
        fgfw_log("vacc_host_init() unknown inst type %d\n", vacc_host->insttype);
        return -1;
    }

    fgfw_epoll_thread_reg_uninst(&(tb_ctx->epoll_thread), &(inst->epoll_inst));

    return 0;
}
#if TESTBENCH_ECHO_CHECK
static int testbench_recv_echo_check(struct _vacc_host *vacc_host, void *opaque, void *buf, uint32_t len)
{

    static uint32_t total_len = 0;
    static uint16_t cnt = 0;
    uint32_t crc_calc;
    testbench_pkt_head_t *head = (testbench_pkt_head_t *)buf;

    g_stop = 1;
    
    fgfw_assert(len == (head->payload_len + sizeof(testbench_pkt_head_t)));

    // fgfw_hexdump(buf, len);
    fgfw_assert(cnt == head->cnt);
    fgfw_assert(head->magic == TESTBENCH_PKT_MAGIC);

    crc_calc = fgfw_crc32c_sw(head + 1, head->payload_len);
    fgfw_assert(head->crc == crc_calc);

    total_len += len;
    fgfw_log("cnt %d, len %d, check done, total %d\n", cnt, len, total_len);

    cnt++;

    g_stop = 0;

    return vacc_host_write(vacc_host, buf, len);
    /* just echo */
}
#else
static int testbench_recv_echo(struct _vacc_host *vacc_host, void *opaque, void *buf, uint32_t len)
{
    fgfw_log("recv len %d, echo send\n", len);

    /* just echo */
    return vacc_host_write(vacc_host, buf, len);
}
#endif

uint32_t g_payload_len_log[1024 * 1024];

static int testbench_recv_noecho(struct _vacc_host *vacc_host, void *opaque, void *buf, uint32_t len)
{
    static uint32_t total_len = 0;
    static uint16_t cnt = 0;
    uint32_t crc_calc, i;
    testbench_ctx_t *ctx = (testbench_ctx_t *)opaque;
    testbench_pkt_head_t *head = (testbench_pkt_head_t *)buf;
    
    g_stop = 1;

    fgfw_assert(len == (head->payload_len + sizeof(testbench_pkt_head_t)));

    // fgfw_hexdump(buf, len);
    fgfw_assert(cnt == head->cnt);
    fgfw_assert(head->magic == TESTBENCH_PKT_MAGIC);
    fgfw_assert(head->payload_len == g_payload_len_log[cnt]);
    crc_calc = fgfw_crc32c_sw(head + 1, head->payload_len);
    if (head->crc != crc_calc) {
        fgfw_err("head->crc != crc_calc\n");
        for (i = 0; i < head->payload_len; i++) {
            if (((uint8_t *)buf)[i + sizeof(testbench_pkt_head_t)] != ctx->sendbuf[i + sizeof(testbench_pkt_head_t)]) {
                fgfw_assert(0);
            }
        }
    }
    fgfw_assert(head->crc == crc_calc);

    total_len += len;
    fgfw_log("cnt %d, len %d, check done, total %d\n", cnt, len, total_len);

    g_stop = 0;

    cnt++;
    return 0;
}

static int test_proto_get_payload_len(void *buf)
{
    testbench_pkt_head_t *head = (testbench_pkt_head_t *)buf;
    return head->payload_len;
}
static testbench_ctx_t g_tb_ctx;

static int testbench_server(int port)
{
    vacc_host_create_param_t param;
    vacc_host_t *listen;
    int ret;

    memset(&g_tb_ctx, 0, sizeof(testbench_ctx_t));

    fgfw_epoll_thread_create(&(g_tb_ctx.epoll_thread));

    memset(&param, 0, sizeof(param));
    param.transtype = VACC_HOST_TRANSTYPE_TCP;
    param.insttype = VACC_HOST_INSTTYPE_SERVER_LISTENER;
    param.cb_get = testbench_get;
    param.cb_put = testbench_put;
    param.cb_init = testbench_init;
    param.cb_uninit = testbench_uninit;
#if TESTBENCH_ECHO_CHECK
    param.cb_recv = testbench_recv_echo_check;
    param.proto_abs.enable = 1;
    param.proto_abs.head_len = sizeof(testbench_pkt_head_t);
    param.proto_abs.pkg_max_len = TESTBENCH_PKT_MAXLEN;
    param.proto_abs.get_payload_len = test_proto_get_payload_len;
#else
    param.cb_recv = testbench_recv_echo;
    param.proto_abs.enable = 0;
#endif
#if FGFW_CONFIG_SOCKBUFSIZE
    param.sendbuf_size = FGFW_CONFIG_SOCKBUFSIZE;
    param.recvbuf_size = FGFW_CONFIG_SOCKBUFSIZE;
#endif
    param.opaque = &g_tb_ctx;
    strncpy(param.u.tcp.srv_ip, "127.0.0.1", sizeof(param.u.tcp.srv_ip));
    param.u.tcp.srv_port = port;

    listen = testbench_get(NULL, &g_tb_ctx);
    ret = vacc_host_create(listen, &param);
    if (ret != VACC_HOST_RET_OK) {
        fgfw_err("vacc_host_create() return %d\n", ret);
        return FGFW_RETVALUE_ERR;
    }

    while (1) {
        usleep(1000);
    }

    return 0;
}

static int testbench_client(int port, uint64_t send_len)
{
    vacc_host_create_param_t param;
    vacc_host_t *cli;
    int ret, len, i;
    static uint16_t cnt = 0;
    uint64_t left_len = send_len;

    memset(&g_tb_ctx, 0, sizeof(testbench_ctx_t));

    fgfw_epoll_thread_create(&(g_tb_ctx.epoll_thread));

    memset(&param, 0, sizeof(param));
    param.transtype = VACC_HOST_TRANSTYPE_TCP;
    param.insttype = VACC_HOST_INSTTYPE_CLIENT_INST;
    param.cb_get = testbench_get;
    param.cb_put = testbench_put;
    param.cb_init = testbench_init;
    param.cb_uninit = testbench_uninit;
    param.cb_recv = testbench_recv_noecho;
    param.proto_abs.enable = 1;
    param.proto_abs.head_len = sizeof(testbench_pkt_head_t);
    param.proto_abs.pkg_max_len = TESTBENCH_PKT_MAXLEN;
    param.proto_abs.get_payload_len = test_proto_get_payload_len;
#if FGFW_CONFIG_SOCKBUFSIZE
    param.sendbuf_size = FGFW_CONFIG_SOCKBUFSIZE;
    param.recvbuf_size = FGFW_CONFIG_SOCKBUFSIZE;
#endif
    param.opaque = &g_tb_ctx;
    strncpy(param.u.tcp.srv_ip, "127.0.0.1", sizeof(param.u.tcp.srv_ip));
    param.u.tcp.srv_port = port;

    cli = testbench_get(NULL, &g_tb_ctx);
    ret = vacc_host_create(cli, &param);
    if (ret != VACC_HOST_RET_OK) {
        fgfw_err("vacc_host_create() return %d\n", ret);
        return FGFW_RETVALUE_ERR;
    }

    for (i = 0; i < TESTBENCH_PKT_MAXLEN; i++) {
        // sendbuf[i] = (uint8_t)rand();
        g_tb_ctx.sendbuf[i] = i;
    }

    while (left_len) {
        testbench_pkt_head_t *pkt_head = (testbench_pkt_head_t *)g_tb_ctx.sendbuf;
        len = rand() % (sizeof(g_tb_ctx.sendbuf) - 1024);
        if ((uint64_t)len > left_len) {
            len = left_len;
        }
        pkt_head->magic = TESTBENCH_PKT_MAGIC;
        pkt_head->cnt = cnt;
        pkt_head->payload_len = len;
        pkt_head->crc = fgfw_crc32c_sw(pkt_head + 1, len);

        g_payload_len_log[cnt] = pkt_head->payload_len;

        if (vacc_host_write(cli, g_tb_ctx.sendbuf, sizeof(testbench_pkt_head_t) + len) == VACC_HOST_RET_OK) {
            fgfw_log("cnt %d, len %d\n", cnt, len);

            cnt++;

            usleep(100000);
        }

        while (g_stop) {
            usleep(100000);
        }
        left_len -= len;
    }

    while (1) {
        usleep(1000);
    }

    return 0;
}

int do_testbench(int mode, int testmode, int port[], uint64_t send_len)
{
    if (mode == FGFW_WORKMODE_SERVER) {
        testbench_server(port[0]);
    } else if (mode == FGFW_WORKMODE_CLIENT) {
        testbench_client(port[0], send_len);
    }

    return 0;
}