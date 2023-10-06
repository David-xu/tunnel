#include "pub.h"

#define TESTBENCH_MAX_INST              8

typedef struct {
    int                 valid;
    int                 idx;
    vacc_host_t         vacc_host;
    fgfw_epoll_inst_t   epoll_inst;
} testbench_inst_t;

typedef struct {
    testbench_inst_t            inst_pool[TESTBENCH_MAX_INST];
    fgfw_epoll_thread_t         epoll_thread;
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
    fgfw_epoll_thread_reg_inst(&(tb_ctx->epoll_thread), &(inst->epoll_inst));

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

static int testbench_recv_echo(struct _vacc_host *vacc_host, void *opaque, void *buf, uint32_t len)
{
    /* just echo */
    return vacc_host_write(vacc_host, buf, len);
}

static int testbench_recv_noecho(struct _vacc_host *vacc_host, void *opaque, void *buf, uint32_t len)
{
    fgfw_log("len %d\n", len);
    // fgfw_hexdump(buf, len);
    return 0;
}

static int testbench_server(int port)
{
    testbench_ctx_t tb_ctx;
    vacc_host_create_param_t param;
    vacc_host_t *listen;
    int ret;

    memset(&tb_ctx, 0, sizeof(testbench_ctx_t));

    fgfw_epoll_thread_create(&(tb_ctx.epoll_thread));

    memset(&param, 0, sizeof(param));
    param.transtype = VACC_HOST_TRANSTYPE_TCP;
    param.insttype = VACC_HOST_INSTTYPE_SERVER_LISTENER;
    param.cb_get = testbench_get;
    param.cb_put = testbench_put;
    param.cb_init = testbench_init;
    param.cb_uninit = testbench_uninit;
    param.cb_recv = testbench_recv_echo;
    param.proto_abs.enable = 0;
    param.opaque = &tb_ctx;
    strncpy(param.u.tcp.srv_ip, "127.0.0.1", sizeof(param.u.tcp.srv_ip));
    param.u.tcp.srv_port = port;

    listen = testbench_get(NULL, &tb_ctx);
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

static int testbench_client(int port)
{
    testbench_ctx_t tb_ctx;
    vacc_host_create_param_t param;
    vacc_host_t *cli;
    int ret, len;
    uint8_t sendbuf[1024];

    memset(&tb_ctx, 0, sizeof(testbench_ctx_t));

    fgfw_epoll_thread_create(&(tb_ctx.epoll_thread));

    memset(&param, 0, sizeof(param));
    param.transtype = VACC_HOST_TRANSTYPE_TCP;
    param.insttype = VACC_HOST_INSTTYPE_CLIENT_INST;
    param.cb_get = testbench_get;
    param.cb_put = testbench_put;
    param.cb_init = testbench_init;
    param.cb_uninit = testbench_uninit;
    param.cb_recv = testbench_recv_noecho;
    param.proto_abs.enable = 0;
    param.opaque = &tb_ctx;
    strncpy(param.u.tcp.srv_ip, "127.0.0.1", sizeof(param.u.tcp.srv_ip));
    param.u.tcp.srv_port = port;

    cli = testbench_get(NULL, &tb_ctx);
    ret = vacc_host_create(cli, &param);
    if (ret != VACC_HOST_RET_OK) {
        fgfw_err("vacc_host_create() return %d\n", ret);
        return FGFW_RETVALUE_ERR;
    }

    while (1) {
        len = rand() % sizeof(sendbuf);
        vacc_host_write(cli, sendbuf, len);
        usleep(1000);
    }

    return 0;
}

int do_testbench(int mode, int port)
{
    if (mode == FGFW_WORKMODE_SERVER) {
        testbench_server(port);
    } else if (mode == FGFW_WORKMODE_CLIENT) {
        testbench_client(port);
    }

    return 0;
}