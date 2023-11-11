#ifndef _PUB_H_
#define _PUB_H_
#include <stdio.h>
#include <unistd.h>
#include <getopt.h> /*getopt_long() */
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <stdarg.h>
#include <time.h>
#include <assert.h>
#include <pthread.h>
#include <signal.h>
#include <sys/epoll.h>
#include <sys/timerfd.h>
#include <sys/types.h>
#include <sys/stat.h>
#ifdef WITH_OPENSSL_LIB
#include <openssl/aes.h>
#else
#include "aes_wrapper.h"
#endif
#if 0
#include <xmmintrin.h>
#include <emmintrin.h>
#include <immintrin.h>
#endif
#define RN_CONFIG_PKB_SIZE                  (4 * 1024)
#define RN_CONFIG_MAX_PKB_NUM               (4096)
#define RN_CONFIG_TOKEN_FILL_CYCLE_MS       1
#define RN_CONFIG_SOCKET_BUF_SIZE           (32 * 1024)
#define RN_CONFIG_MAX_TUNNEL_TRANSPORT      64
#define RN_CONFIG_MAX_AGENT_CONN_CLIENT     256
#define RN_CONFIG_MAX_AGENT_CONN_SERV       1024

#define RN_WORKMODE_SERVER                  1
#define RN_WORKMODE_CLIENT                  2

#define RN_MAX_TUNNEL_PORT                  64
#define RN_MAX_LOCAL_AGENT_PORT             16
#define RN_AES_ENCDEC_DATALEN               16
#define RN_AES_KEY_LEN                      RN_AES_ENCDEC_DATALEN
#define RN_TRANSPORT_DEFAULT_SEND_BPS       (10000)

typedef int rn_transport_id;
#define RN_TRANSPORT_ID_INVALID             ((rn_transport_id)(-1))

typedef int rn_bundle_id;
#define RN_BUNDLE_ID_INVALID                ((rn_bundle_id)(-1))

typedef int rn_local_agent_conn_id;
#define RN_AGENT_CONN_ID_INVALID            ((rn_local_agent_conn_id)(-1))

#include "vacc_host.h"
#include "util.h"
#include "epoll_worker.h"
#include "tunnel.h"
#include "local_agent.h"

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

    rn_pkb_pool_t   *pkb_pool;
    rn_epoll_thread_t   epoll_thread;
    int             transport_polling_timer_id;

    //
    rn_tunnel_t         *tunnel;
    rn_local_agent_t    *local_agent;
} running_ctx_t;

#endif