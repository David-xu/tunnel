#ifndef _PUB_H_
#define _PUB_H_
#include <stdio.h>
#include <unistd.h>
#include <getopt.h> /*getopt_long() */
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <time.h>
#include <assert.h>
#include <pthread.h>
#include <signal.h>
#include <sys/epoll.h>
#include <sys/timerfd.h>
#include <sys/types.h>
#include <openssl/aes.h>
#include <xmmintrin.h>
#include <emmintrin.h>
#include <immintrin.h>

// #define FGFW_CONFIG_SOCKBUFSIZE             8192

typedef int fgfw_transport_id;
#define FGFW_TRANSPORT_ID_INVALID           ((fgfw_transport_id)(-1))

typedef int fgfw_tunnel_bundle_id;
#define FGFW_BUNDLE_ID_INVALID              ((fgfw_tunnel_bundle_id)(-1))

typedef int fgfw_local_agent_conn_id;
#define FGFW_AGENT_CONN_ID_INVALID          ((fgfw_local_agent_conn_id)(-1))

typedef int fgfw_tunnel_session_id;
#define FGFW_TUNNEL_SESSION_ID_INVALID      ((fgfw_tunnel_session_id)(-1))

#include "util.h"
#include "vacc_host.h"
#include "epoll_worker.h"
#include "transport.h"
#include "protocol.h"
#include "tunnel.h"
#include "local_agent.h"

#define FGFW_BUILD_BUG_ON(condition)            ((void)sizeof(char[1 - 2*!!(condition)]))

#define fgfw_assert(cond)    do{ \
    if (!(cond)) { \
        fgfw_printf("%-24s %4d Assert! `" #cond "'\n", __FUNCTION__, __LINE__); \
        while (1) {sleep(1000);} \
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

extern uint64_t g_dbgprint_flag;
#define FGFW_DBGFLAG_SESSION                            (0x1 << 0)
#define FGFW_DBGFLAG_AGENT_CONN                         (0x1 << 1)
#define FGFW_DBGFLAG_PROTOCOL                           (0x1 << 2)
#define fgfw_dbg(flag, fmt, args...) do { \
        if (g_dbgprint_flag & flag) { \
            fgfw_printf("[DBG] %-24s %4d: "fmt, __FUNCTION__, __LINE__, ##args); \
        } \
    } while(0)

#define FGFW_RETVALUE_OK                    0
#define FGFW_RETVALUE_ERR                   -1
#define FGFW_RETVALUE_INVALID_PARAM         -2
#define FGFW_RETVALUE_NO_SUCH_BUNDLE        -3
#define FGFW_RETVALUE_NO_SUCH_SESSION       -4
#define FGFW_RETVALUE_NO_SUCH_TRANSPORT     -5
#define FGFW_RETVALUE_NOENOUGHRES           -6
#define FGFW_RETVALUE_NOTALIGN              -7
#define FGFW_RETVALUE_SESSION_NOT_READY     -8
#define FGFW_RETVALUE_TIMER_NOT_READY       -9
#define FGFW_RETVALUE_NOENOUGHSPACE         -10
#define FGFW_RETVALUE_PKT_INCOMPLETE        -11
#define FGFW_RETVALUE_PROTO_ERR             -12
#define FGFW_RETVALUE_SESSION_CREATE_FAILD  -13
#define FGFW_RETVALUE_CHALLENGE_NOT_MATCH   -14
#define FGFW_RETVALUE_BUNDLE_NOT_BUILD      -15
#define FGFW_RETVALUE_NOPKT_NEED_PROC       -16

#define FGFW_WORKMODE_SERVER                1
#define FGFW_WORKMODE_CLIENT                2

#define FGFW_MAX_TUNNEL_PORT                64
#define FGFW_MAX_LOCAL_AGENT_PORT           16

typedef struct {
    volatile int    running;
    int             kill_signal;
    int             kill_pid;
    int             sigpipe_cnt;

    int     mode;                   /* FGFW_WORKMODE_SERVER | FGFW_WORKMODE_CLIENT */
    uint32_t transport_send_bps;
    int     port_agent_offset;
    char    serv_ip[16];

    int     n_port;
    int     port_list[FGFW_MAX_TUNNEL_PORT];

    int     n_local_agent_port;
    int     local_agent_port_list[FGFW_MAX_LOCAL_AGENT_PORT];

    uint8_t default_key[16];

    fgfw_tunnel_t           tunnel;

    fgfw_local_agent_t      local_agent;
    
} running_ctx_t;

#endif