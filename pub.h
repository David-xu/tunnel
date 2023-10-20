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

#include "util.h"
#include "epoll_worker.h"
#include "vacc_host.h"
#include "testbench.h"

#define RN_BUILD_BUG_ON(condition)          ((void)sizeof(char[1 - 2*!!(condition)]))

#define RN_RETVALUE_OK                      0
#define RN_RETVALUE_ERR                     -1
#define RN_RETVALUE_SYSCALL_FAILD           -2
#define RN_RETVALUE_INVALID_PARAM           -3
#define RN_RETVALUE_NO_SUCH_BUNDLE          -4
#define RN_RETVALUE_NO_SUCH_SESSION         -5
#define RN_RETVALUE_NO_SUCH_TRANSPORT       -6
#define RN_RETVALUE_NOENOUGHRES             -7
#define RN_RETVALUE_NOTALIGN                -8
#define RN_RETVALUE_SESSION_NOT_READY       -9
#define RN_RETVALUE_TIMER_NOT_READY         -10
#define RN_RETVALUE_NOENOUGHSPACE           -11
#define RN_RETVALUE_PKT_INCOMPLETE          -12
#define RN_RETVALUE_PROTO_ERR               -13
#define RN_RETVALUE_SESSION_CREATE_FAILD    -14
#define RN_RETVALUE_CHALLENGE_NOT_MATCH     -15
#define RN_RETVALUE_BUNDLE_NOT_BUILD        -16
#define RN_RETVALUE_NOPKT_NEED_PROC         -17

#define rn_assert(cond)    do{ \
    if (!(cond)) { \
        rn_printf("%-24s %4d Assert! `" #cond "'\n", __FUNCTION__, __LINE__); \
        while (1) {sleep(1000);} \
    } \
} while (0)

#define rn_log(fmt, args...) do { \
        rn_printf("[LOG] %-24s %4d: "fmt, __FUNCTION__, __LINE__, ##args); \
    } while(0)
#define rn_warn(fmt, args...) do { \
        rn_printf("[WARN] %-24s %4d: "fmt, __FUNCTION__, __LINE__, ##args); \
    } while(0)
#define rn_err(fmt, args...) do { \
        rn_printf("[ERR] %-24s %4d: "fmt, __FUNCTION__, __LINE__, ##args); \
    } while(0)

#define RN_WORKMODE_SERVER                  1
#define RN_WORKMODE_CLIENT                  2

#define RN_MAX_TUNNEL_PORT                  64
#define RN_MAX_LOCAL_AGENT_PORT             16
#define RN_AES_ENCDEC_DATALEN               16
#define RN_AES_KEY_LEN                      RN_AES_ENCDEC_DATALEN
#define RN_TRANSPORT_DEFAULT_SEND_BPS       (10000)

typedef struct {
    volatile int    running;
    int             kill_signal;
    int             kill_pid;
    int             sigpipe_cnt;

    int             mode;                   /* RN_WORKMODE_SERVER | RN_WORKMODE_CLIENT */
    uint32_t        transport_send_bps;
    int             port_agent_offset;
    char            serv_ip[16];

    int             n_port;
    int             port_list[RN_MAX_TUNNEL_PORT];

    int             n_local_agent_port;
    int             local_agent_port_list[RN_MAX_LOCAL_AGENT_PORT];

    uint8_t         default_key[RN_AES_KEY_LEN];
} running_ctx_t;

#endif