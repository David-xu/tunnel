#include "pub.h"

char * const short_options="hv";

static running_ctx_t g_ctx = {0};

uint64_t g_dbgprint_flag = 0xffffffffffffffffull;

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
};

struct option long_options[]={
    {"help", 0, NULL, 'h'},
    {"version", 0, NULL, 'v'},
    {"mode", 1, NULL, ARGPARAM_MODE},
    {"serv_ip", 1, NULL, ARGPARAM_SERV_IP},
    {"port_list", 1, NULL, ARGPARAM_PORT_LIST},
    {"local_agent_port_list", 1, NULL, ARGPARAM_LOCAL_AGENT_PORT_LIST},
    {"tunnel_default_key", 1, NULL, ARGPARAM_TUNNEL_DEFAULT_KEY},
    {"testbench", 1, NULL, ARGPARAM_TESTBENCH},
    {"transport_send_bps", 1, NULL, ARGPARAM_TRANSPORT_SEND_BPS},
    {"port_agent_offset", 1, NULL, ARGPARAM_PORT_AGENT_OFFSET},
};

static void tunnel_usage(char* progname)
{
    printf("usage: %s" "[--help|-h]|[--version|-v]" "\n", progname);
    printf("Commonly arguments:\n");
    printf("     --version|-v                   show the version.\n");
    printf("     --mode                         --mode=[server/client]\n");
    printf("     --serv_ip                      server ip address\n");
    printf("     --port_list                    tcp port list\n");
    printf("     --local_agent_port_list        local agent port list\n");
    printf("     --tunnel_default_key           tunnel default aes key\n");
    printf("     --testbench=[port]             testbench, set tcp port\n");
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

int do_server(running_ctx_t *ctx)
{
    int ret;
    /* create tunnel */
    ret = fgfw_tunnel_create(&(ctx->tunnel), ctx->mode, ctx->transport_send_bps, ctx->serv_ip, ctx->n_port, ctx->port_list, ctx->default_key);

    /* create local agent */
    ret = fgfw_local_agent_create(&(ctx->local_agent), ctx->mode, ctx->port_agent_offset, &(ctx->tunnel), ctx->n_local_agent_port, ctx->local_agent_port_list);
    if (ret) {
        fgfw_err("local agent create faild %d\n", ret);
        fgfw_tunnel_destroy(&(ctx->tunnel));
        return 0;
    }

    return 0;
}

int do_client(running_ctx_t *ctx)
{
    int ret;

    /* create tunnel */
    ret = fgfw_tunnel_create(&(ctx->tunnel), ctx->mode, ctx->transport_send_bps, ctx->serv_ip, ctx->n_port, ctx->port_list, ctx->default_key);

    /* create local agent */
    ret = fgfw_local_agent_create(&(ctx->local_agent), ctx->mode, ctx->port_agent_offset, &(ctx->tunnel), ctx->n_local_agent_port, ctx->local_agent_port_list);
    if (ret) {
        fgfw_err("local agent create faild %d\n", ret);
        fgfw_tunnel_destroy(&(ctx->tunnel));
        return 0;
    }

    return 0;
}

#define FGFW_TOKEN_FILL_CYCLE_MS                            1

static int tb_insert_timer_1ms(void *param)
{
    running_ctx_t *ctx = (running_ctx_t *)param;
    
    fgfw_transport_pool_fill_token_all(&(ctx->tunnel.transport_pool), FGFW_TOKEN_FILL_CYCLE_MS);

    return 0;
}

static void set_default_aes_key(running_ctx_t *ctx) {
    memset(ctx->default_key, 0, sizeof(ctx->default_key));
    strncpy((char *)ctx->default_key, "abcd01234567ef", sizeof(ctx->default_key));
}

extern int do_testbench(int mode, int port);

int main(int argc, char *argv[])
{
    int cmdtype, longp_idx, i, testbench = 0;

    set_default_aes_key(&g_ctx);

    while ((cmdtype = getopt_long(argc, argv, short_options, long_options, &longp_idx)) != -1) {
        switch (cmdtype) {
        case 'h':
            tunnel_usage(argv[0]);
            return 0;
        case 'v':
            break;
        case ARGPARAM_MODE:
            if (strcmp(optarg, "server") == 0) {
                g_ctx.mode = FGFW_WORKMODE_SERVER;
            } else if (strcmp(optarg, "client") == 0) {
                g_ctx.mode = FGFW_WORKMODE_CLIENT;
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
        case ARGPARAM_TUNNEL_DEFAULT_KEY:
        {
            int i, len = strlen(optarg), v, n_valid = 0;
            memset(&g_ctx.default_key, 0, sizeof(g_ctx.default_key));
            for (i = 0; i < len; i++) {
                v = fgfw_c2n(((char *)optarg)[i]);
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
            testbench = strtoull(optarg, NULL, 0);

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

    fgfw_log("serv_ip %s, n_port %d:\n", g_ctx.serv_ip, g_ctx.n_port);
    for (i = 0; i < g_ctx.n_port; i++) {
        fgfw_log("\t\t%d\n", g_ctx.port_list[i]);
    }
    fgfw_log("n_local_agent_port %d:\n", g_ctx.n_local_agent_port);
    for (i = 0; i < g_ctx.n_local_agent_port; i++) {
        fgfw_log("\t\t%d\n", g_ctx.local_agent_port_list[i]);
    }
    fgfw_log("default aes key:\n");
    fgfw_hexdump(g_ctx.default_key, sizeof(g_ctx.default_key));
    if (g_ctx.transport_send_bps == 0) {
        g_ctx.transport_send_bps = FGFW_TRANSPORT_DEFAULT_SEND_BPS;
    }
    fgfw_log("transport_send_bps: %d\n", g_ctx.transport_send_bps);
    fgfw_log("port_agent_offset: %d\n", g_ctx.port_agent_offset);
    
#if 0
    unsigned char key[16] = "0123456789abcdef";
    unsigned char plaintext[16] = "hello, world!";
    unsigned char ciphertext[16] = {0};
    unsigned char decrypted[16] = {0};

    fgfw_aes_encrypt(key, plaintext, ciphertext);

    fgfw_aes_decrypt(key, ciphertext, decrypted);
    fgfw_hexdump(decrypted, 16);
#endif
    FGFW_BUILD_BUG_ON(sizeof(fgfw_tunnel_protocol_pkt_head_t) != FGFW_TRANSPORT_PKT_ALIGN);
    FGFW_BUILD_BUG_ON(sizeof(fgfw_tunnel_protocol_pkt_session_data_t) != FGFW_TRANSPORT_PKT_ALIGN);
    // FGFW_BUILD_BUG_ON(FGFW_TRANSPORT_MAX_SEND_LEN >= (FGFW_TRANSPORT_RECVBUF_SIZE / 16));
    FGFW_BUILD_BUG_ON((FGFW_TUNNEL_SESSION_RECV_RING_BUF_SIZE % FGFW_TRANSPORT_RECVBUF_SIZE) != 0);

    srand(time(0));

    if (testbench) {
        return do_testbench(g_ctx.mode, testbench);
    }

    setup_signal_handling();

    switch (g_ctx.mode) {
    case FGFW_WORKMODE_SERVER:
        do_server(&g_ctx);
        break;
    case FGFW_WORKMODE_CLIENT:
        do_client(&g_ctx);
        break;
    default:
        tunnel_usage(argv[0]);
        return 0;
    }

    /* ugly */
    g_ctx.tunnel.local_agent = &(g_ctx.local_agent);

    fgfw_timerfw_add_timer(&(g_ctx.tunnel.epoll_thread), 100000, FGFW_TOKEN_FILL_CYCLE_MS * 1000, tb_insert_timer_1ms, &g_ctx);

    if (g_ctx.mode == FGFW_WORKMODE_CLIENT) {
        fgfw_tunnel_connect_to_serv(&(g_ctx.tunnel), g_ctx.serv_ip, g_ctx.n_port, g_ctx.port_list);
    }

    g_ctx.running = 1;
    while (g_ctx.running) {
        usleep(10000);
    }

    fgfw_local_agent_destroy(&(g_ctx.local_agent));
    fgfw_tunnel_destroy(&(g_ctx.tunnel));

    fgfw_log("ext...\n");

    return 0;
}