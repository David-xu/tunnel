#include "pub.h"

char * const short_options="hv";

enum {
    ARGPARAM_BEGIN = 256,
    ARGPARAM_MODE,
    ARGPARAM_SERV_IP,
    ARGPARAM_PORT_LIST,
    ARGPARAM_LOCAL_AGENT_PORT_LIST,
};

struct option long_options[]={
    {"help", 0, NULL, 'h'},
    {"version", 0, NULL, 'v'},
    {"mode", 1, NULL, ARGPARAM_MODE},
    {"serv_ip", 1, NULL, ARGPARAM_SERV_IP},
    {"port_list", 1, NULL, ARGPARAM_PORT_LIST},
    {"local_agent_port_list", 1, NULL, ARGPARAM_LOCAL_AGENT_PORT_LIST},
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
}

int main(int argc, char *argv[])
{
    int cmdtype, longp_idx, i, ret;
    static running_ctx_t ctx = {0};

    while ((cmdtype = getopt_long(argc, argv, short_options, long_options, &longp_idx)) != -1) {
        switch (cmdtype) {
        case 'h':
            tunnel_usage(argv[0]);
            return 0;
        case 'v':
            break;
        case ARGPARAM_MODE:
            if (strcmp(optarg, "server") == 0) {
                ctx.mode = FGFW_WORKMODE_SERVER;
            } else if (strcmp(optarg, "client") == 0) {
                ctx.mode = FGFW_WORKMODE_CLIENT;
            } else {
                printf("invalid mode %s\n", optarg);
                return 0;
            }

            break;
        case ARGPARAM_SERV_IP:
            strncpy(ctx.serv_ip, optarg, sizeof(ctx.serv_ip));
            break;
        case ARGPARAM_PORT_LIST:
        {
            char *p;
            int n_port = 0;
            p = strtok(optarg, ",");
            while (p != NULL) {
                ctx.port_list[n_port++] = strtoull(p, NULL, 0);
                p = strtok(NULL, ",");
            }
            ctx.n_port = n_port;
            break;
        }
        case ARGPARAM_LOCAL_AGENT_PORT_LIST:
        {
            char *p;
            int n_port = 0;
            p = strtok(optarg, ",");
            while (p != NULL) {
                ctx.local_agent_port_list[n_port++] = strtoull(p, NULL, 0);
                p = strtok(NULL, ",");
            }
            ctx.n_local_agent_port = n_port;
            break;
            break;
        }
        default:
            break;
        }
    }

    fgfw_log("serv_ip %s, n_port %d:\n", ctx.serv_ip, ctx.n_port);
    for (i = 0; i < ctx.n_port; i++) {
        fgfw_log("\t\t%d\n", ctx.port_list[i]);
    }
    fgfw_log("n_local_agent_port %d:\n", ctx.n_local_agent_port);
    for (i = 0; i < ctx.n_local_agent_port; i++) {
        fgfw_log("\t\t%d\n", ctx.local_agent_port_list[i]);
    }

    unsigned char key[16] = "0123456789abcdef";
    unsigned char plaintext[16] = "hello, world!";
    unsigned char ciphertext[16] = {0};
    unsigned char decrypted[16] = {0};

    fgfw_aes_encrypt(key, plaintext, ciphertext);

    fgfw_aes_decrypt(key, ciphertext, decrypted);

    /* create tunnel */
    ret = fgfw_tunnel_create(&(ctx.tunnel), ctx.mode, ctx.serv_ip, ctx.n_port, ctx.port_list);

    /* create local agent */
    ret = fgfw_local_agent_create(&(ctx.local_agent), &(ctx.tunnel), ctx.n_local_agent_port, ctx.local_agent_port_list);
    if (ret) {
        fgfw_err("local agent create faild %d\n", ret);
        fgfw_tunnel_destroy(&(ctx.tunnel));
        return 0;
    }

    while (1) {
        usleep(10000);
    }

    return 0;
}