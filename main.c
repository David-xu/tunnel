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

int do_server(running_ctx_t *ctx)
{
    return 0;
}

int do_client(running_ctx_t *ctx)
{
    return 0;
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
    int cmdtype, longp_idx, i, testbench = 0, testbench_mode = 0;
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
        if (g_ctx.n_local_agent_port == 0) {
            rn_log("need set --local_agent_port_list\n");
            return 0;
        }
        
        return do_testbench(g_ctx.mode, testbench_mode, g_ctx.local_agent_port_list, len);
    }

    setup_signal_handling();

    switch (g_ctx.mode) {
    case RN_WORKMODE_SERVER:
        do_server(&g_ctx);
        break;
    case RN_WORKMODE_CLIENT:
        do_client(&g_ctx);
        break;
    default:
        rottenut_usage(argv[0]);
        return 0;
    }

    g_ctx.running = 1;
    while (g_ctx.running) {
        cmd_loop();
    }

    rn_log("exit...\n");

    return 0;
}