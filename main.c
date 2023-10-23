#include "pub.h"

running_ctx_t g_ctx;

char * const short_options="hv";

enum {
    ARGPARAM_BEGIN = 256,
    ARGPARAM_MODE,
    ARGPARAM_SERV_IP,
    ARGPARAM_PORT_LIST,
    ARGPARAM_LOCAL_AGENT_PORT_LIST,
    ARGPARAM_TUNNEL_DEFAULT_KEY,
    ARGPARAM_TESTBENCH,
    ARGPARAM_TRANSPORT_SEND_BPS,
    ARGPARAM_PORT_AGENT_OFFSET,
    ARGPARAM_LENGTH,
};

struct option long_options[]={
    {"help", 0, NULL, 'h'},
    {"version", 0, NULL, 'v'},
    {"mode", 1, NULL, ARGPARAM_MODE},
    {"serv_ip", 1, NULL, ARGPARAM_SERV_IP},
    {"port_list", 1, NULL, ARGPARAM_PORT_LIST},
    {"len", 1, NULL, ARGPARAM_LENGTH},
    {"local_agent_port_list", 1, NULL, ARGPARAM_LOCAL_AGENT_PORT_LIST},
    {"tunnel_default_key", 1, NULL, ARGPARAM_TUNNEL_DEFAULT_KEY},
    {"testbench", 1, NULL, ARGPARAM_TESTBENCH},
    {"transport_send_bps", 1, NULL, ARGPARAM_TRANSPORT_SEND_BPS},
    {"port_agent_offset", 1, NULL, ARGPARAM_PORT_AGENT_OFFSET},
};

static void rottenut_usage(char* progname)
{
    printf("usage: %s" "[--help|-h]|[--version|-v]" "\n", progname);
    printf("Commonly arguments:\n");
    printf("     --version|-v                   show the version.\n");
    printf("     --mode                         --mode=[server/client]\n");
    printf("     --serv_ip                      server ip address\n");
    printf("     --port_list                    tcp port list\n");
    printf("     --len                          set length\n");
    printf("     --local_agent_port_list        local agent port list\n");
    printf("     --tunnel_default_key           tunnel default aes key\n");
    printf("     --testbench=[test work mode]   testbench, set testbench mode\n");
    printf("     --transport_send_bps           send bps(bytes per second)\n");
    printf("     --port_agent_offset            server port = client port + port_agent_offset\n");
}

static void termsig_handler(int signal, siginfo_t *info, void *c)
{
    g_ctx.kill_signal = signal;
    g_ctx.kill_pid = info->si_pid;
    g_ctx.running = 0;
}
static void termsig_handler_pipe(int signal, siginfo_t *info, void *c)
{
    g_ctx.sigpipe_cnt++;
}

static void setup_signal_handling(void)
{
    struct sigaction act;
    struct sigaction actpipe;

    memset(&act, 0, sizeof(act));
    act.sa_sigaction = termsig_handler;
    act.sa_flags = SA_SIGINFO;
    sigaction(SIGINT,  &act, NULL);
    sigaction(SIGHUP,  &act, NULL);
    sigaction(SIGTERM, &act, NULL);

    memset(&actpipe, 0, sizeof(actpipe));
    actpipe.sa_sigaction = termsig_handler_pipe;
    actpipe.sa_flags = SA_SIGINFO;
	sigemptyset(&actpipe.sa_mask);
	sigaction(SIGPIPE, &actpipe, NULL);
}

static int tb_insert_timer_1ms(void *param)
{
    running_ctx_t *ctx = (running_ctx_t *)param;

    rn_tunnel_transport_polling_all(ctx->tunnel, RN_CONFIG_TOKEN_FILL_CYCLE_MS);

    return 0;
}

int do_server(running_ctx_t *ctx)
{
    int i, ret;
    /* create tunnel */
    ctx->tunnel = rn_tunnel_create(&(ctx->epoll_thread), ctx->pkb_pool, RN_CONFIG_MAX_TUNNEL_TRANSPORT, ctx->default_key, ctx->transport_send_bps);
    /* create all listener */
    for (i = 0; i < ctx->n_port; i++) {
        ret = rn_socket_mngr_listen_add(&(ctx->tunnel->socket_mngr), ctx->serv_ip, ctx->port_list[i], RN_CONFIG_SOCKET_BUF_SIZE);
        if (ret != RN_RETVALUE_OK) {
            rn_err("create listen socket %s %d faild.\n", ctx->serv_ip, ctx->port_list[i]);
            return ret;
        }
    }

    /* create local_agent, no need to set port_agent_offset */
    ctx->local_agent = rn_local_agent_create(ctx->tunnel, &(ctx->epoll_thread), ctx->pkb_pool, RN_CONFIG_MAX_AGENT_CONN, -1);

    return RN_RETVALUE_OK;
}

int do_client(running_ctx_t *ctx)
{
    int i, ret;
    rn_socket_public_t *p, *n;
    rn_transport_t *transport;
    rn_bundle_id client_bundle_id;
    rn_pkb_t *pkb;

    /* create tunnel */
    ctx->tunnel = rn_tunnel_create(&(ctx->epoll_thread), ctx->pkb_pool, RN_CONFIG_MAX_TUNNEL_TRANSPORT, ctx->default_key, ctx->transport_send_bps);
    /* connect to server's transport socket */
    for (i = 0; i < ctx->n_port; i++) {
        /* connect */
        ret = rn_socket_mngr_connet(&(ctx->tunnel->socket_mngr), ctx->serv_ip, ctx->port_list[i], RN_CONFIG_SOCKET_BUF_SIZE);
        if (ret != RN_RETVALUE_OK) {
            rn_err("connect to %s %d faild.\n", ctx->serv_ip, ctx->port_list[i]);
            return ret;
        }
    }
    /* bundle create */
    client_bundle_id = rn_tunnel_bundle_new(ctx->tunnel, NULL, NULL, 0);
    rn_assert(client_bundle_id == 0);
    /* all transport need to do 'bundle join' */
    rn_assert(ctx->tunnel->socket_mngr.n_client_inst == ctx->n_port);
    RN_LISTENTRYWALK_SAVE(p, n, &(ctx->tunnel->socket_mngr.client_inst_list), list_entry) {
        rn_assert(p->vacc_host.insttype == VACC_HOST_INSTTYPE_CLIENT_INST);
        transport = RN_GETCONTAINER(p, rn_transport_t, socket);
        pkb = rn_pkb_pool_get_pkb(ctx->pkb_pool);
        rn_assert(pkb != NULL);
        ret = tunnel_proc_send_bundle_join(ctx->tunnel, transport, pkb, NULL, getpid());
        rn_assert(ret == RN_RETVALUE_OK);
    }

    /* create local_agent */
    ctx->local_agent = rn_local_agent_create(ctx->tunnel, &(ctx->epoll_thread), ctx->pkb_pool, RN_CONFIG_MAX_AGENT_CONN, ctx->port_agent_offset);
    /* create all listener */
    for (i = 0; i < ctx->n_local_agent_port; i++) {
        rn_socket_mngr_listen_add(&(ctx->local_agent->socket_mngr), "127.0.01", ctx->local_agent_port_list[i], RN_CONFIG_SOCKET_BUF_SIZE);
    }

    return RN_RETVALUE_OK;
}

static void cmd_loop(void)
{
	char *argv[64];
	uint32_t len[64];

    char line[1024];
    int i, total_len, argc;
    while (g_ctx.running) {
        printf("cmd:\n");
        fflush(stdout);
        memset(line, 0, sizeof(line));
        fgets(line, sizeof(line), stdin);
        total_len = strlen(line);
        line[total_len - 1] = 0;
        total_len -= 1;
        argc = rn_stdiv(line, total_len, sizeof(len) / sizeof(len[0]), argv, len, 2, " \n", 0);
        for (i = 0; i < argc; i++) {
            argv[i][len[i]] = 0;
            if (memcmp(argv[0], "--dump", 6) == 0) {
                if (g_ctx.mode == RN_WORKMODE_CLIENT) {
                    rn_log("client:\n");
                } else {
                    rn_log("server:\n");
                }
            } else if (memcmp(argv[0], "-q", 2) == 0) {
                g_ctx.running = 0;
            }
        }
    }
}

int main(int argc, char *argv[])
{
    int ret, cmdtype, longp_idx, i, testbench = 0, testbench_mode = 0;
    uint64_t len;

    /* set default key */
    memset(g_ctx.default_key, 0, sizeof(g_ctx.default_key));
    strncpy((char *)g_ctx.default_key, "abcd01234567ef", sizeof(g_ctx.default_key));

    while ((cmdtype = getopt_long(argc, argv, short_options, long_options, &longp_idx)) != -1) {
        switch (cmdtype) {
        case 'h':
            rottenut_usage(argv[0]);
            return 0;
        case 'v':
            break;
        case ARGPARAM_MODE:
            if (strcmp(optarg, "server") == 0) {
                g_ctx.mode = RN_WORKMODE_SERVER;
            } else if (strcmp(optarg, "client") == 0) {
                g_ctx.mode = RN_WORKMODE_CLIENT;
            } else {
                printf("invalid mode %s\n", optarg);
                return 0;
            }

            break;
        case ARGPARAM_SERV_IP:
            strncpy(g_ctx.serv_ip, optarg, sizeof(g_ctx.serv_ip));
            break;
        case ARGPARAM_PORT_LIST:
        {
            char *p;
            int n_port = 0;
            p = strtok(optarg, ",");
            while (p != NULL) {
                g_ctx.port_list[n_port++] = strtoull(p, NULL, 0);
                p = strtok(NULL, ",");
            }
            g_ctx.n_port = n_port;
            break;
        }
        case ARGPARAM_LOCAL_AGENT_PORT_LIST:
        {
            char *p;
            int n_port = 0;
            p = strtok(optarg, ",");
            while (p != NULL) {
                g_ctx.local_agent_port_list[n_port++] = strtoull(p, NULL, 0);
                p = strtok(NULL, ",");
            }
            g_ctx.n_local_agent_port = n_port;
            break;
        }
        case ARGPARAM_LENGTH:
        {
            len = strtoull(optarg, NULL, 0);
            break;
        }
        case ARGPARAM_TUNNEL_DEFAULT_KEY:
        {
            int i, len = strlen(optarg), v, n_valid = 0;
            memset(&g_ctx.default_key, 0, sizeof(g_ctx.default_key));
            for (i = 0; i < len; i++) {
                v = rn_c2n(((char *)optarg)[i]);
                if (v < 0) {
                    continue;
                } else {
                    if (n_valid & 1) {
                        g_ctx.default_key[n_valid / 2] |= v;
                    } else {
                        g_ctx.default_key[n_valid / 2] = v << 4;
                    }
                    n_valid++;
                }
                if (n_valid == sizeof(g_ctx.default_key) * 2) {
                    break;
                }
            }
            break;
        }
        case ARGPARAM_TESTBENCH:
        {
            testbench = 1;
            testbench_mode = strtoull(optarg, NULL, 0);
            break;
        }
        case ARGPARAM_TRANSPORT_SEND_BPS:
        {
            g_ctx.transport_send_bps = strtoull(optarg, NULL, 0);
            break;
        }
        case ARGPARAM_PORT_AGENT_OFFSET:
        {
            g_ctx.port_agent_offset = strtoull(optarg, NULL, 0);
            break;
        }
        default:
            break;
        }
    }

    rn_log("serv_ip %s, n_port %d:\n", g_ctx.serv_ip, g_ctx.n_port);
    for (i = 0; i < g_ctx.n_port; i++) {
        rn_log("\t\t%d\n", g_ctx.port_list[i]);
    }
    rn_log("n_local_agent_port %d:\n", g_ctx.n_local_agent_port);
    for (i = 0; i < g_ctx.n_local_agent_port; i++) {
        rn_log("\t\t%d\n", g_ctx.local_agent_port_list[i]);
    }
    rn_log("default aes key:\n");
    rn_hexdump(g_ctx.default_key, sizeof(g_ctx.default_key));
    if (g_ctx.transport_send_bps == 0) {
        g_ctx.transport_send_bps = RN_TRANSPORT_DEFAULT_SEND_BPS;
    }
    rn_log("transport_send_bps: %d\n", g_ctx.transport_send_bps);
    rn_log("port_agent_offset: %d\n", g_ctx.port_agent_offset);

    srand(time(0));

    if (testbench) {
        if ((g_ctx.mode == RN_WORKMODE_SERVER) || (g_ctx.mode == RN_WORKMODE_CLIENT)) {
            if (g_ctx.n_local_agent_port == 0) {
                rn_log("need set --local_agent_port_list\n");
                return 0;
            }

            return do_testbench(g_ctx.mode, testbench_mode, g_ctx.n_local_agent_port, g_ctx.local_agent_port_list, len);
        } else {
            return do_ut();
        }
    }

    setup_signal_handling();

    /* create epoll_thread */
    rn_assert(rn_epoll_thread_create(&(g_ctx.epoll_thread)) == RN_RETVALUE_OK);
    /* create global pkb pool */
    g_ctx.pkb_pool = rn_pkb_pool_create(RN_CONFIG_MAX_PKB_NUM, RN_CONFIG_PKB_SIZE);
    rn_assert(g_ctx.pkb_pool != NULL);

    switch (g_ctx.mode) {
    case RN_WORKMODE_SERVER:
        ret = do_server(&g_ctx);
        break;
    case RN_WORKMODE_CLIENT:
        ret = do_client(&g_ctx);
        break;
    default:
        rottenut_usage(argv[0]);
        return 0;
    }
    if (ret) {
        return 0;
    }

    g_ctx.transport_polling_timer_id = rn_timerfw_add_timer(&(g_ctx.epoll_thread), 1000, RN_CONFIG_TOKEN_FILL_CYCLE_MS * 1000, tb_insert_timer_1ms, &g_ctx);
    rn_assert(g_ctx.transport_polling_timer_id >= 0);

    g_ctx.running = 1;
    while (g_ctx.running) {
        cmd_loop();
    }

    rn_local_agent_destroy(g_ctx.local_agent);
    rn_tunnel_destroy(g_ctx.tunnel);

    rn_timerfw_del_timer(&(g_ctx.epoll_thread), g_ctx.transport_polling_timer_id);
    rn_assert(g_ctx.epoll_thread.n_inst == 0);
    rn_assert(g_ctx.epoll_thread.n_timer == 0);
    rn_epoll_thread_destroy(&(g_ctx.epoll_thread));

    rn_assert(RN_GPFIFO_ISFULL(g_ctx.pkb_pool->free_pkt_fifo));
    rn_pkb_pool_destroy(g_ctx.pkb_pool);

    rn_log("exit...\n");

    return 0;
}
