#include "pub.h"
#include "testbench.h"

running_ctx_t g_ctx;

char * const short_options="hvd";

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
    { "daemon", 0, NULL, 'd'},
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
    printf("     --daemon|-d                    run in daemon mode\n");
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

static int fds[2];

#define RN_CONFIG_LOG_FILE "/var/log/rottenNut.log"

void set_fd_cloexec(int fd)
{
    int f;
    f = fcntl(fd, F_GETFD);
    fcntl(fd, F_SETFD, f | FD_CLOEXEC);
}

void os_daemonize(void)
{
    pid_t pid;

    if (pipe(fds) == -1)
        exit(1);

    pid = fork();
    if (pid > 0) {
        uint8_t status;
        ssize_t len;

        close(fds[1]);

again:
        len = read(fds[0], &status, 1);
        if (len == -1 && (errno == EINTR))
            goto again;

        if (len != 1)
            exit(1);
        else if (status == 1) {
            fprintf(stderr, "Could not acquire pidfile: %s\n", strerror(errno));
            exit(1);
        } else
            exit(0);
    } else if (pid < 0)
        exit(1);

    close(fds[0]);
    set_fd_cloexec(fds[1]);

    setsid();

    pid = fork();
    if (pid > 0)
        exit(0);
    else if (pid < 0)
        exit(1);

    umask(027);

    signal(SIGTSTP, SIG_IGN);
    signal(SIGTTOU, SIG_IGN);
    signal(SIGTTIN, SIG_IGN);
}

/*
 * Opens a file with FD_CLOEXEC set
 */
int open_cloexec(const char *name, int flags, ...)
{
    int ret;
    int mode = 0;

    if (flags & O_CREAT) {
        va_list ap;

        va_start(ap, flags);
        mode = va_arg(ap, int);
        va_end(ap);
    }

#ifdef O_CLOEXEC
    ret = open(name, flags | O_CLOEXEC, mode);
#else
    ret = open(name, flags, mode);
    if (ret >= 0) {
        set_fd_cloexec(ret);
    }
#endif

#ifdef O_DIRECT
    if (ret == -1 && errno == EINVAL && (flags & O_DIRECT)) {
        fprintf(stderr, "file system may not support O_DIRECT");
        errno = EINVAL; /* in case it was clobbered */
    }
#endif /* O_DIRECT */

    return ret;
}

int set_log_file(void)
{
    int fd;
    int log_fd;
    FILE *fp = NULL;

    fd = open_cloexec("/dev/null", O_RDWR);
    if (fd == -1)
        return -1;

    dup2(fd, 0);
    close(fd);

    fp = fopen(RN_CONFIG_LOG_FILE, "a+");
    if (fp == NULL) {
        printf("open log file failed\n");
        return -2;
    }

    setlinebuf(fp);
    log_fd = fileno(fp);

    setlinebuf(stdout);
    setlinebuf(stderr);
    close(1);
    close(2);

    if ((dup2(log_fd, 1) < 0) || (dup2(log_fd, 2) < 0)) {
        printf("redirect stdout & stderr failed\n");
        return -3;
    }
    close(log_fd);

    return 0;
}

void os_setup_post(void)
{
    uint8_t status = 0;
    ssize_t len;

again1:
    len = write(fds[1], &status, 1);
    if (len == -1 && (errno == EINTR))
        goto again1;

    if (len != 1)
        exit(1);

    if (chdir("/")) {
        perror("not able to chdir to /");
        exit(1);
    }

    if (set_log_file() < 0) {
        fprintf(stderr, "set log file failed\n");
        exit(2);
    }
}

static void termsig_handler(int signal, siginfo_t *info, void *c)
{
    g_ctx.kill_signal = signal;
    g_ctx.kill_pid = info->si_pid;
    g_ctx.running = 0;
}

static void setup_signal_term_handling(void)
{
    struct sigaction act;

    memset(&act, 0, sizeof(act));
    act.sa_sigaction = termsig_handler;
    act.sa_flags = SA_SIGINFO;
    sigaction(SIGINT,  &act, NULL);
    sigaction(SIGHUP,  &act, NULL);
    sigaction(SIGTERM, &act, NULL);
}

static void termsig_handler_pipe(int signal, siginfo_t *info, void *c)
{
    g_ctx.sigpipe_cnt++;
}

static void setup_signal_pipe_handling(void)
{
    struct sigaction actpipe;

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
    rn_agent_conn_polling_all(ctx->local_agent, RN_CONFIG_TOKEN_FILL_CYCLE_MS);

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
    ctx->local_agent = rn_local_agent_create(ctx->tunnel, &(ctx->epoll_thread), ctx->pkb_pool, RN_CONFIG_MAX_AGENT_CONN_SERV, -1);

    /* set local_agent in tunnel */
    ctx->tunnel->local_agent = ctx->local_agent;

    return RN_RETVALUE_OK;
}

int do_client(running_ctx_t *ctx)
{
    int i, ret;
    rn_socket_public_t *p, *n;
    rn_transport_t *transport;
    rn_bundle_id client_bundle_id;

    /* create tunnel */
    ctx->tunnel = rn_tunnel_create(&(ctx->epoll_thread), ctx->pkb_pool, RN_CONFIG_MAX_TUNNEL_TRANSPORT, ctx->default_key, ctx->transport_send_bps);
    /* connect to server's transport socket */
    for (i = 0; i < ctx->n_port; i++) {
        /* connect */
        ret = rn_socket_mngr_connect(&(ctx->tunnel->socket_mngr), ctx->serv_ip, ctx->port_list[i], RN_CONFIG_SOCKET_BUF_SIZE, NULL);
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
        /* send msg */
        transport = RN_GETCONTAINER(p, rn_transport_t, socket);
        ret = tunnel_proc_send_bundle_join(ctx->tunnel, transport, NULL, getpid());
        rn_assert(ret == RN_RETVALUE_OK);
        /* local transport join bundle */
        rn_tunnel_bundle_insert_transport(ctx->tunnel, client_bundle_id, transport->transport_id);
    }

    /* create local_agent */
    ctx->local_agent = rn_local_agent_create(ctx->tunnel, &(ctx->epoll_thread), ctx->pkb_pool, RN_CONFIG_MAX_AGENT_CONN_CLIENT, ctx->port_agent_offset);
    /* create all listener */
    for (i = 0; i < ctx->n_local_agent_port; i++) {
        rn_socket_mngr_listen_add(&(ctx->local_agent->socket_mngr), "127.0.0.1", ctx->local_agent_port_list[i], RN_CONFIG_SOCKET_BUF_SIZE);
    }

    /* set local_agent in tunnel */
    ctx->tunnel->local_agent = ctx->local_agent;

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
                    rn_local_agent_dump(g_ctx.local_agent);
                    rn_tunnel_dump(g_ctx.tunnel);
                } else {
                    rn_log("server:\n");
                    rn_tunnel_dump(g_ctx.tunnel);
                    rn_local_agent_dump(g_ctx.local_agent);
                }
            } else if (memcmp(argv[0], "-q", 2) == 0) {
                g_ctx.running = 0;
            }
        }
    }
}

int main(int argc, char *argv[])
{
    int ret, cmdtype, longp_idx, i, daemonize = 0, testbench = 0, testbench_mode = 0;
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
        case 'd':
            daemonize = 1;
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

    if (daemonize) {
        os_daemonize();
        os_setup_post();
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

    setup_signal_pipe_handling();

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

    setup_signal_term_handling();

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
    if (daemonize) {
        while (g_ctx.running) usleep(1000000);
    } else {
        while (g_ctx.running) {
            cmd_loop();
        }
    }

    rn_timerfw_del_timer(&(g_ctx.epoll_thread), g_ctx.transport_polling_timer_id);

    rn_local_agent_destroy(g_ctx.local_agent);
    rn_tunnel_destroy(g_ctx.tunnel);

    rn_assert(g_ctx.epoll_thread.n_inst == 0);
    rn_assert(g_ctx.epoll_thread.n_timer == 0);
    rn_epoll_thread_destroy(&(g_ctx.epoll_thread));

#ifdef RN_CONFIG_PKBPOOL_CHECK
    if (!RN_GPFIFO_ISFULL(g_ctx.pkb_pool->free_pkt_fifo)) {
        rn_pkb_pool_dump(g_ctx.pkb_pool);
    }
#else
    rn_assert(RN_GPFIFO_ISFULL(g_ctx.pkb_pool->free_pkt_fifo));
#endif

    rn_pkb_pool_destroy(g_ctx.pkb_pool);

    rn_log("exit...\n");

    return 0;
}
