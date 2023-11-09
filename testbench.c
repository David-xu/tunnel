#include "pub.h"

#define TESTBENCH_RAND_DISCON_PARAM     16
#define TESTBENCH_MAX_INST              32
#define TESTBENCH_SEND_LEN_LOG_LEN      1024
// #define TESTBENCH_ECHO_CHECK            1

typedef struct {
    uint32_t            magic;              /* TESTBENCH_PKT_MAGIC */
    uint16_t            type;
    uint16_t            cnt;
    uint32_t            payload_len;
    uint32_t            crc;
} testbench_pkt_head_t;

#define TESTBENCH_PKT_MAGIC             0x1357acbd

#define TESTBENCH_PKT_MAXLEN            (16 * 1024)

static int test_proto_get_payload_len(void *buf)
{
    testbench_pkt_head_t *head = (testbench_pkt_head_t *)buf;
    return head->payload_len;
}

typedef struct {
    int             send_timer_id;
    uint32_t        left_len;

    uint32_t        send_len_log[TESTBENCH_SEND_LEN_LOG_LEN];
    uint32_t        send_idx, recv_idx;
} testbench_inst_client_t;

typedef struct {
    rn_socket_public_t      socket;                 /* should be first element */
    rn_epoll_inst_t         epoll_inst;

    uint32_t                id;

    union {
        testbench_inst_client_t     client;
        struct {

        } server;
    } u;
} testbench_socket_inst_t;

typedef struct {
    rn_epoll_thread_t           epoll_thread;
    uint8_t                     sendbuf[TESTBENCH_PKT_MAXLEN];

    int                         workmode;           /* RN_WORKMODE_SERVER or RN_WORKMODE_CLIENT */

    rn_socket_mngr_t            socket_mngr;
    testbench_socket_inst_t     sock_inst_pool[TESTBENCH_MAX_INST];
    int                         testmode;

    uint32_t                    test_send_len;
    int                         port;
} testbench_ctx_t;

static testbench_ctx_t g_tb_ctx;

static void testbench_send_to_complete(vacc_host_t *vacc_host, void *buf, uint32_t len)
{
    uint32_t already_send = 0;
    int ret;

    while (already_send < len) {
        ret = vacc_host_write(vacc_host, buf + already_send, len - already_send);
        if (ret < 0) {
            if (ret == VACC_HOST_RET_PEERCLOSE) {
                break;
            }
            printf("########   vacc_host_write() return %d", ret);
            while (1) usleep(10000);
        }
        already_send += ret;
    }
}

#if TESTBENCH_ECHO_CHECK
static int testbench_recv_echo_check(struct _vacc_host *vacc_host, void *opaque, void *buf, uint32_t len)
{

    static uint32_t total_len = 0;
    static uint16_t cnt = 0;
    uint32_t crc_calc;
    testbench_pkt_head_t *head = (testbench_pkt_head_t *)buf;

    rn_assert(len == (head->payload_len + sizeof(testbench_pkt_head_t)));

    // rn_hexdump(buf, len);
    rn_assert(cnt == head->cnt);
    rn_assert(head->magic == TESTBENCH_PKT_MAGIC);

    crc_calc = rn_crc32c_sw(head + 1, head->payload_len);
    rn_assert(head->crc == crc_calc);

    total_len += len;
    rn_log("cnt %d, len %d, check done, total %d\n", cnt, len, total_len);

    cnt++;

    testbench_send_to_complete(vacc_host, buf, len);

    return 0;
    /* just echo */
}
#else
static int testbench_recv_echo(struct _vacc_host *vacc_host, void *opaque, void *buf, uint32_t len)
{
    rn_log("recv len %d, echo send\n", len);

    if (g_tb_ctx.testmode == 1) {
        if ((rand() % TESTBENCH_RAND_DISCON_PARAM) == 1) {
            vacc_host_destroy(vacc_host);
            return 0;
        }
    }

    /* just echo */
    testbench_send_to_complete(vacc_host, buf, len);

    return 0;
}
#endif

static int testbunch_client_send_timer_cb(void *param)
{
    testbench_socket_inst_t *inst = (testbench_socket_inst_t *)param;
    uint32_t len;
    testbench_pkt_head_t *pkt_head = (testbench_pkt_head_t *)g_tb_ctx.sendbuf;

    if ((inst->u.client.send_idx - inst->u.client.recv_idx) >= TESTBENCH_SEND_LEN_LOG_LEN) {
        rn_err("inst[%d] too many infly, inst->u.client.send_idx %d inst->u.client.recv_idx %d\n", inst->id, inst->u.client.send_idx, inst->u.client.recv_idx);
        return 0;
    }

    if (inst->u.client.left_len == 0) {
        rn_log("inst[%d] send finish.\n", inst->id);
        /* close */
        vacc_host_destroy(&(inst->socket.vacc_host));
        return 0;
    }

    if (g_tb_ctx.testmode == 1) {
        if ((rand() % TESTBENCH_RAND_DISCON_PARAM) == 1) {
            vacc_host_destroy(&(inst->socket.vacc_host));
            return 0;
        }
    }

    len = rand() % (sizeof(g_tb_ctx.sendbuf) - 1024);
    if ((uint64_t)len > inst->u.client.left_len) {
        len = inst->u.client.left_len;
    }
    pkt_head->magic = TESTBENCH_PKT_MAGIC;
    pkt_head->cnt = inst->u.client.send_idx;
    pkt_head->payload_len = len;
    pkt_head->crc = rn_crc32c_sw(pkt_head + 1, len);

    /* save len */
    inst->u.client.send_len_log[inst->u.client.send_idx % TESTBENCH_SEND_LEN_LOG_LEN] = pkt_head->payload_len;

    /* do send */
    testbench_send_to_complete(&(inst->socket.vacc_host), g_tb_ctx.sendbuf, sizeof(testbench_pkt_head_t) + len);

    rn_log("inst[%d] send_idx %d, len %d\n", inst->id, inst->u.client.send_idx, len);

    inst->u.client.send_idx++;
    inst->u.client.left_len -= len;

    return 0;
}


static void testbunch_listener_epoll_inst_cb(rn_epoll_inst_t *epoll_inst)
{
    testbench_socket_inst_t *inst = RN_GETCONTAINER(epoll_inst, testbench_socket_inst_t, epoll_inst);

    vacc_host_read(&(inst->socket.vacc_host), NULL, 0);
}

static void testbunch_epoll_inst_cb(rn_epoll_inst_t *epoll_inst)
{
    testbench_socket_inst_t *inst = RN_GETCONTAINER(epoll_inst, testbench_socket_inst_t, epoll_inst);

    vacc_host_read(&(inst->socket.vacc_host), NULL, 0);
}

static int testbench_client_inst_reset(testbench_socket_inst_t *inst)
{
    memset(&(inst->u.client), 0, sizeof(testbench_inst_client_t));
    inst->u.client.left_len = g_tb_ctx.test_send_len;

    return 0;
}

static int testbench_sock_inst_init(rn_socket_mngr_t *mngr, rn_socket_public_t *socket, void *cb_param)
{
    testbench_ctx_t *ctx = (testbench_ctx_t *)cb_param;
    testbench_socket_inst_t *inst = RN_GETCONTAINER(socket, testbench_socket_inst_t, socket);
    int ret;


    switch (socket->vacc_host.insttype) {
    case VACC_HOST_INSTTYPE_SERVER_LISTENER:
        /* add into epoll thread main loop */
        inst->epoll_inst.epoll_inst_cb = testbunch_listener_epoll_inst_cb;
        inst->epoll_inst.fd = socket->vacc_host.sock_fd;
        ret = rn_epoll_thread_reg_inst(&(ctx->epoll_thread), &(inst->epoll_inst));
        if (ret != RN_RETVALUE_OK) {
            /* todo: */
            rn_assert(0);
        }

        break;
    case VACC_HOST_INSTTYPE_SERVER_INST:
    case VACC_HOST_INSTTYPE_CLIENT_INST:
        /* add into epoll thread main loop */
        inst->epoll_inst.epoll_inst_cb = testbunch_epoll_inst_cb;
        inst->epoll_inst.fd = socket->vacc_host.sock_fd;
        ret = rn_epoll_thread_reg_inst(&(ctx->epoll_thread), &(inst->epoll_inst));
        if (ret != RN_RETVALUE_OK) {
            /* todo: */
            rn_assert(0);
        }

        if (socket->vacc_host.insttype == VACC_HOST_INSTTYPE_CLIENT_INST) {
            testbench_client_inst_reset(inst);

            /* add send timer */
            inst->u.client.send_timer_id = rn_timerfw_add_timer(&(ctx->epoll_thread), 1000, 10000, testbunch_client_send_timer_cb, inst);
            rn_assert(inst->u.client.send_timer_id >= 0);
            rn_log("inst[%d] add timer id %d, timer fd %d.\n",
                inst->id, inst->u.client.send_timer_id, ctx->epoll_thread.timer_list[inst->u.client.send_timer_id].timer_fd);
        }

        break;
    default:
        rn_assert(0);
    }

    return RN_RETVALUE_OK;
}

static int testbench_sock_inst_uninit(rn_socket_mngr_t *mngr, rn_socket_public_t *socket, void *cb_param)
{
    testbench_ctx_t *ctx = (testbench_ctx_t *)cb_param;
    testbench_socket_inst_t *inst = RN_GETCONTAINER(socket, testbench_socket_inst_t, socket);
    int ret;

    switch (socket->vacc_host.insttype) {
    case VACC_HOST_INSTTYPE_SERVER_LISTENER:
        /* fall though */
    case VACC_HOST_INSTTYPE_SERVER_INST:
    case VACC_HOST_INSTTYPE_CLIENT_INST:
        /* remove from epoll thread main loop */
        ret = rn_epoll_thread_reg_uninst(&(ctx->epoll_thread), &(inst->epoll_inst));
        if (ret != RN_RETVALUE_OK) {
            /* todo: */
            rn_assert(0);
        }

        if (socket->vacc_host.insttype == VACC_HOST_INSTTYPE_CLIENT_INST) {
            /* add send timer */
            if (inst->u.client.send_timer_id >= 0) {
                rn_log("inst[%d] remove timer id %d, timer fd %d.\n",
                    inst->id, inst->u.client.send_timer_id, ctx->epoll_thread.timer_list[inst->u.client.send_timer_id].timer_fd);
                rn_assert(rn_timerfw_del_timer(&(ctx->epoll_thread), inst->u.client.send_timer_id) == RN_RETVALUE_OK);
            } else {
                rn_assert(0);
            }
        }

        break;
    default:
        rn_assert(0);
    }

    return RN_RETVALUE_OK;
}

static int testbench_recv_noecho(struct _vacc_host *vacc_host, void *opaque, void *buf, uint32_t len)
{
    uint32_t crc_calc, i;
    testbench_ctx_t *ctx = (testbench_ctx_t *)opaque;
    testbench_pkt_head_t *head = (testbench_pkt_head_t *)buf;
    testbench_socket_inst_t *inst = RN_GETCONTAINER(vacc_host, testbench_socket_inst_t, socket.vacc_host);

    rn_assert(len == (head->payload_len + sizeof(testbench_pkt_head_t)));

    // rn_hexdump(buf, len);
    rn_assert(inst->u.client.recv_idx == head->cnt);
    rn_assert(head->magic == TESTBENCH_PKT_MAGIC);
    rn_assert(head->payload_len == inst->u.client.send_len_log[inst->u.client.recv_idx]);
    crc_calc = rn_crc32c_sw(head + 1, head->payload_len);
    if (head->crc != crc_calc) {
        rn_err("head->crc != crc_calc\n");
        for (i = 0; i < head->payload_len; i++) {
            if (((uint8_t *)buf)[i + sizeof(testbench_pkt_head_t)] != ctx->sendbuf[i + sizeof(testbench_pkt_head_t)]) {
                rn_assert(0);
            }
        }
    }
    rn_assert(head->crc == crc_calc);

    rn_log("inst[%d] cnt %d, len %d, check done\n", inst->id, inst->u.client.recv_idx, len);

    inst->u.client.recv_idx++;
    return 0;
}

static int testbench_server(int testmode, int port)
{
    protocol_abstract_t proto_abs;
    vacc_host_cb_recv cb_recv;

#if TESTBENCH_ECHO_CHECK
    cb_recv = testbench_recv_echo_check;
    proto_abs.enable = 1;
    proto_abs.head_len = sizeof(testbench_pkt_head_t);
    proto_abs.pkg_max_len = TESTBENCH_PKT_MAXLEN;
    proto_abs.get_payload_len = test_proto_get_payload_len;
#else
    cb_recv = testbench_recv_echo;
    memset(&proto_abs, 0, sizeof(protocol_abstract_t));
#endif

    rn_socket_mngr_listen_add_ex(&(g_tb_ctx.socket_mngr), "127.0.0.1", port, RN_CONFIG_SOCKET_BUF_SIZE, &proto_abs, cb_recv);

    while (1) {
        usleep(1000);
    }

    return 0;
}

static int testbench_add_new_client(int port)
{
    protocol_abstract_t proto_abs;
    vacc_host_cb_recv cb_recv;
    rn_socket_public_t *cli;

    cb_recv = testbench_recv_noecho;
    proto_abs.enable = 1;
    proto_abs.head_len = sizeof(testbench_pkt_head_t);
    proto_abs.pkg_max_len = TESTBENCH_PKT_MAXLEN;
    proto_abs.get_payload_len = test_proto_get_payload_len;

    rn_socket_mngr_connect_ex(&(g_tb_ctx.socket_mngr), "127.0.0.1", port, RN_CONFIG_SOCKET_BUF_SIZE, &cli, &proto_abs, cb_recv);

    rn_log("");

    return 0;
}

static int testbunch_client_new_inst_timer_cb(void *param)
{
    testbench_ctx_t *ctx = (testbench_ctx_t *)param;

    if (ctx->testmode == 0) {
        if (RN_GPFIFO_ISFULL(ctx->socket_mngr.free_fifo)) {
            testbench_add_new_client(ctx->port);
        }
    } else if (ctx->testmode == 1) {
        uint32_t i, n, n_free = RN_GPFIFO_CUR_LEN(ctx->socket_mngr.free_fifo);
        if (n_free) {
            n = rand() % n_free;
            for (i = 0; i < n; i++) {
                testbench_add_new_client(ctx->port);
            }
        }
    }

    return 0;
}

static int testbench_client(int port)
{
    int i;

    for (i = 0; i < TESTBENCH_PKT_MAXLEN; i++) {
        g_tb_ctx.sendbuf[i] = (uint8_t)rand();
        g_tb_ctx.sendbuf[i] = i;
    }
    g_tb_ctx.port = port;

    rn_timerfw_add_timer(&(g_tb_ctx.epoll_thread), 1000, 100000, testbunch_client_new_inst_timer_cb, &g_tb_ctx);

    while (1) {
        usleep(1000);
    }

    return 0;
}

int do_testbench(int mode, int testmode, int n_port, int port[], uint64_t send_len)
{
    int i;
    memset(&g_tb_ctx, 0, sizeof(testbench_ctx_t));
    g_tb_ctx.test_send_len = send_len;
    for (i = 0; i < TESTBENCH_MAX_INST; i++) {
        g_tb_ctx.sock_inst_pool[i].id = i;
    }

    rn_epoll_thread_create(&(g_tb_ctx.epoll_thread));
    rn_socket_mngr_create(&(g_tb_ctx.socket_mngr), &(g_tb_ctx.sock_inst_pool[0].socket), TESTBENCH_MAX_INST, sizeof(testbench_socket_inst_t),
        testbench_sock_inst_init, testbench_sock_inst_uninit, &g_tb_ctx);

    g_tb_ctx.workmode = mode;
    g_tb_ctx.testmode = testmode;

    if (mode == RN_WORKMODE_SERVER) {
        testbench_server(testmode, port[0]);
    } else if (mode == RN_WORKMODE_CLIENT) {
        testbench_client(port[0]);
    }

    return 0;
}

static int case_00(void)
{
    /* aes cipher */
    unsigned char key[16] = "0123456789abcdef";
    unsigned char plaintext[16] = "hello, world!";
    unsigned char ciphertext[16] = {0};
    AES_KEY aes_key;

    memcpy(ciphertext, plaintext, sizeof(plaintext));

    AES_set_encrypt_key(key, 128, &aes_key);
    AES_ecb_encrypt(ciphertext, ciphertext, &aes_key, AES_ENCRYPT);

    AES_set_decrypt_key(key, 128, &aes_key);
    AES_ecb_encrypt(ciphertext, ciphertext, &aes_key, AES_DECRYPT);

    if (memcmp(ciphertext, plaintext, sizeof(plaintext))) {
        return -1;
    }

    return 0;
}
#if 0
typedef struct {
    rn_socket_mngr_t        socket_mngr;
    rn_socket_public_t      sock_list[8];
    rn_epoll_inst_t         epoll_inst[8];
    rn_epoll_thread_t       epoll_thread;
} ut_case_01_param_t;

static int case_01_timer_cb(void *param)
{

}

static void rn_transport_listener_epoll_inst_cb(rn_epoll_inst_t *epoll_inst)
{
    rn_transport_t *transport = RN_GETCONTAINER(epoll_inst, rn_transport_t, epoll_inst);

    vacc_host_read(&(transport->socket.vacc_host), NULL, 0);
}

static void rn_transport_epoll_inst_cb(rn_epoll_inst_t *epoll_inst)
{

}

static int case_01_sock_init(rn_socket_mngr_t *mngr, rn_socket_public_t *socket, void *cb_param)
{
    ut_case_01_param_t *param = (ut_case_01_param_t *)cb_param;
    uint32_t idx = socket->conn_id;

    /* add into epoll thread main loop */
    transport->epoll_inst.epoll_inst_cb = rn_transport_listener_epoll_inst_cb;
    transport->epoll_inst.fd = socket->vacc_host.sock_fd;
    ret = rn_epoll_thread_reg_inst(tunnel->epoll_thread, &(transport->epoll_inst));
    if (ret != RN_RETVALUE_OK) {
        /* todo: */
        rn_assert(0);
    }

    return 0;
}

static int case_01_sock_uninit(rn_socket_mngr_t *mngr, rn_socket_public_t *socket, void *cb_param)
{
    return 0;
}

static int case_01(void)
{
    ut_case_01_param_t param;
    int ret;

    rn_assert(rn_epoll_thread_create(&(param.epoll_thread)) == RN_RETVALUE_OK);

    /*  */
    ret = rn_socket_mngr_create(&param.socket_mngr, param.sock_list, RN_ARRAY_SIZE(param.sock_list), sizeof(rn_socket_public_t),
        case_01_sock_init, case_01_sock_uninit, &param);
    if (ret != RN_RETVALUE_OK) {
        return -1;
    }

    rn_timerfw_add_timer(&(param.epoll_thread), 100, 1000000, case_01_timer_cb, &param);
    rn_socket_mngr_listen_add(&param.socket_mngr, "127.0.0.1", 40000, 64 * 1024);
    rn_socket_mngr_connect(&param.socket_mngr, "127.0.0.1", 40000, 64 * 1024, NULL);



    return 0;
}
#endif
typedef int (*test_case_fn)(void);
static test_case_fn g_test_case_list[] = {
    case_00,
    // case_01,
};

int do_ut(void)
{
    uint32_t i;
    for (i = 0; i < sizeof(g_test_case_list) / sizeof(g_test_case_list[0]); i++) {
        if (g_test_case_list[i]()) {
            printf("test case %d faild\n", i);
            return -1;
        }
    }

    printf("all case (total %d) pass.\n", i);

    return 0;
}
