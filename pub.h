#ifndef _PUB_H_
#define _PUB_H_
#include <stdio.h>
#include <getopt.h> /*getopt_long() */
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <time.h>
#include <assert.h>
#include <pthread.h>
#include <sys/epoll.h>
#include <openssl/aes.h>

#include "util.h"
#include "vacc_host.h"
#include "transport.h"
#include "protocol.h"
#include "epoll_worker.h"
#include "tunnel.h"
#include "local_agent.h"

#define FGFW_BUILD_BUG_ON(condition)            ((void)sizeof(char[1 - 2*!!(condition)]))

#define fgfw_assert(cond)    do{ \
    if (!(cond)) { \
        fgfw_printf("%-24s %4d Assert! `" #cond "'\n", __FUNCTION__, __LINE__); \
        assert(0); \
    } \
} while (0)

#define fgfw_log(fmt, args...) do { \
        fgfw_printf("[LOG] %-24s %4d: "fmt, __FUNCTION__, __LINE__, ##args); \
    } while(0)
#define fgfw_warn(fmt, args...) do { \
        fgfw_printf("[WARN] %-24s %4d: "fmt, __FUNCTION__, __LINE__, ##args); \
    } while(0)
#define fgfw_err(fmt, args...) do { \
        fgfw_printf("[ERR] %-24s %4d: "fmt, __FUNCTION__, __LINE__, ##args); \
    } while(0)

#define FGFW_RETVALUE_OK                    0
#define FGFW_RETVALUE_ERR                   -1
#define FGFW_RETVALUE_INVALID_PARAM         -2
#define FGFW_RETVALUE_NOENOUGHRES           -3

#define FGFW_WORKMODE_SERVER                1
#define FGFW_WORKMODE_CLIENT                2

#define FGFW_MAX_TUNNEL_PORT                64
#define FGFW_MAX_LOCAL_AGENT_PORT           16

typedef struct {
    int     mode;                   /* FGFW_WORKMODE_SERVER | FGFW_WORKMODE_CLIENT */
    char    serv_ip[16];

    int     n_port;
    int     port_list[FGFW_MAX_TUNNEL_PORT];

    int     n_local_agent_port;
    int     local_agent_port_list[FGFW_MAX_LOCAL_AGENT_PORT];

    fgfw_tunnel_t           tunnel;

    fgfw_local_agent_t      local_agent;
    
} running_ctx_t;

#endif