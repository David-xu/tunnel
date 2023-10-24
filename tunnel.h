#ifndef _TUNNEL_H_
#define _TUNNEL_H_

/* transport frame proto */
#define RN_TRANSPORT_PROTOCOL_PKTLEN_ALIGN          RN_AES_ENCDEC_DATALEN
#define RN_TRANSPORT_FRAME_HEAD_LEN                 RN_AES_ENCDEC_DATALEN
#define RN_TRANSPORT_PROTOCOL_MAGIC                 0x57464746

typedef enum {
    RN_TRANSPORT_FRAME_TYPE_DATA = 1,                           /* without ack */
    RN_TRANSPORT_FRAME_TYPE_UPDATE_KEY,                         /* without ack */
    RN_TRANSPORT_FRAME_TYPE_BUNDLE_JOIN,                        /* without ack */
    RN_TRANSPORT_FRAME_TYPE_SESSION_NEW,
    RN_TRANSPORT_FRAME_TYPE_SESSION_NEW_ACK,
    RN_TRANSPORT_FRAME_TYPE_SESSION_DEL,                        /* without ack */
} rn_transport_frame_type_e;

static inline const char * rn_transport_frame_type_str(rn_transport_frame_type_e type)
{
    const char *__name_str[] = {
        [0] = "0",
        [RN_TRANSPORT_FRAME_TYPE_DATA] = "RN_TRANSPORT_FRAME_TYPE_DATA",
        [RN_TRANSPORT_FRAME_TYPE_UPDATE_KEY] = "RN_TRANSPORT_FRAME_TYPE_UPDATE_KEY",
        [RN_TRANSPORT_FRAME_TYPE_BUNDLE_JOIN] = "RN_TRANSPORT_FRAME_TYPE_BUNDLE_JOIN",
        [RN_TRANSPORT_FRAME_TYPE_SESSION_NEW] = "RN_TRANSPORT_FRAME_TYPE_SESSION_NEW",
        [RN_TRANSPORT_FRAME_TYPE_SESSION_NEW_ACK] = "RN_TRANSPORT_FRAME_TYPE_SESSION_NEW_ACK",
        [RN_TRANSPORT_FRAME_TYPE_SESSION_DEL] = "RN_TRANSPORT_FRAME_TYPE_SESSION_DEL",
    };
    if (type >= RN_ARRAY_SIZE(__name_str)) {
        return "unknown";
    }

    return __name_str[type];
}

typedef struct {
    uint32_t                        magic;                      /* RN_TRANSPORT_PROTOCOL_MAGIC */
    uint32_t                        challenge;
    uint32_t                        align_len;                  /* include head */
    uint32_t                        real_len        : 24;       /* include head */
    uint32_t                        type            : 8;
} rn_transport_frame_head_t;

typedef struct {
    char            src_ipstr[INET_ADDRSTRLEN];
    uint32_t        pid_at_cli;                                 /* client's pid */
} rn_transport_frame_boundle_join_t;

typedef struct {
    uint32_t        port;
    uint32_t        src_agent_conn_id;
} rn_protocol_pkt_session_new_req_t;

typedef struct {
    int             ret;
    uint32_t        src_agent_conn_id;                          /* produced server */
    uint32_t        dst_agent_conn_id;                          /* origin agent_conn id in client */
    uint32_t        source_challenge;                           /* should eq to challenge of req frame */
} rn_protocol_pkt_session_new_resp_t;

typedef struct {
    uint32_t        src_agent_conn_id;                          /*  */
    uint32_t        dst_agent_conn_id;                          /*  */
} rn_protocol_pkt_session_del_req_t;

typedef struct {
    uint32_t        src_agent_conn_id;
    uint32_t        dst_agent_conn_id;                          /* indicate session, after 'session create' proc, produced by tunnel server */
    uint64_t        idx;                                        //
} rn_protocol_pkt_session_data_t;

typedef enum {
    RN_TRANSPORT_STATE_UNINIT = 0,
    RN_TRANSPORT_STATE_LISTENING,
    RN_TRANSPORT_STATE_CONNECTED,
    RN_TRANSPORT_STATE_BUNDLE_ALREADY_JOIN,
} rn_transport_state_e;

#define RN_CONFIG_TRANSPORT_FRAME_MAXLEN            (RN_CONFIG_PKB_SIZE)

/*
 * bundle
 */
#define RN_MAX_TRANSPORT_PER_BUNDLE                 64

typedef struct {
    rn_bundle_id                            bundle_id;

    int                                     valid;

    char                                    ipstr_at_cli[INET_ADDRSTRLEN];
    char                                    ipstr_at_srv[INET_ADDRSTRLEN];
    uint32_t                                pid_at_cli;                     /* client's pid */

    int                                     n_agent_conn;
    rn_listhead_t                           agent_conn_list_head;

    uint32_t                                n_transport;
    rn_transport_id                         transport_list[RN_MAX_TRANSPORT_PER_BUNDLE];
} rn_bundle_t;

/*
 * tunnel mngr
 */
#define RN_CONFIG_TRANSPORT_SEND_FIFO_DEPTH         4
#define RN_CONFIG_TRANSPORT_BKT_MAX_BURST           (RN_CONFIG_TRANSPORT_FRAME_MAXLEN * 2)          /* max burst 2 pkt */
#define RN_CONFIG_TUNNEL_BUNDLE_MAX                 16

struct _rn_tunnel;

typedef struct {
    rn_socket_public_t      socket;                 /* should be first element */
    rn_epoll_inst_t         epoll_inst;
    rn_transport_id         transport_id;
    struct _rn_tunnel       *tunnel;
    /* send pending fifo, depth : RN_CONFIG_TRANSPORT_SEND_FIFO_DEPTH */
    rn_gpfifo_t             *send_fifo;

    /* need reset */
    rn_transport_state_e    transport_state;        /* after this element, should be reset */

    rn_bundle_id            belongs_to_bundle_id;   /* which bundle this transport belongs to, RN_BUNDLE_ID_INVALID if not belongs to any bundle */

    /* recv */
    rn_pkb_t                *cur_proc_frame;
    rn_transport_frame_head_t   *frame_head;

    /* send bucket */
    single_token_bucket_t   send_stb;
    uint32_t                send_bps;               /* byte per second (>=1000) */

    int                     aes_128_tx_enable, aes_128_rx_enable;
    AES_KEY                 aes_128_enc_key, aes_128_dec_key;

    struct {
        uint64_t            send_no_enough_credit;
        uint64_t            send_pkt, send_bytes, send_pkt_not_complete;

        uint64_t            head_not_complete;
        uint64_t            body_not_complete;

        uint64_t            drop_transport_not_in_bundle;
        uint64_t            drop_agent_conn_not_ready;

        uint64_t            vacc_send_err, vacc_recv_err;
    } stat;
} rn_transport_t;

static inline int rn_transport_can_send(rn_transport_t *transport)
{
    if ((transport->transport_state == RN_TRANSPORT_STATE_CONNECTED) || (transport->transport_state == RN_TRANSPORT_STATE_BUNDLE_ALREADY_JOIN)) {
        return 1;
    }

    return 0;
}

struct _rn_local_agent;

typedef struct _rn_tunnel {
    rn_socket_mngr_t        socket_mngr;
    rn_epoll_thread_t       *epoll_thread;
    rn_pkb_pool_t           *pkb_pool;
    struct _rn_local_agent  *local_agent;

    int                     n_bundle;
    rn_bundle_t             bundle_list[RN_CONFIG_TUNNEL_BUNDLE_MAX];


    uint8_t                 default_key[RN_AES_KEY_LEN];
    uint32_t                default_transport_send_bps;

    struct {
        uint64_t            invalid_frame_cnt;
    } stat;

    int                     n_transport;
    rn_transport_t          transport_pool[0];
} rn_tunnel_t;

#ifdef RN_CONFIG_TRANSPORT_CHECK
static inline void rn_tunnel_transport_valid(rn_transport_t *transport)
{
    rn_tunnel_t *tunnel;
    int idx;

    tunnel = transport->tunnel;
    rn_assert(transport->send_fifo != NULL);
    rn_assert(tunnel != NULL);
    idx = transport - tunnel->transport_pool;
    rn_assert(idx == transport->transport_id);
    rn_assert(idx == transport->socket.conn_id);
}
#else
#define rn_tunnel_transport_valid(transport)
#endif

static inline void rn_transport_tx_enable_aes_128(rn_transport_t *transport, uint8_t key[])
{
    AES_set_encrypt_key(key, 128, &(transport->aes_128_enc_key));

    transport->aes_128_tx_enable = 1;
}

static inline void rn_transport_rx_enable_aes_128(rn_transport_t *transport, uint8_t key[])
{
    AES_set_decrypt_key(key, 128, &(transport->aes_128_dec_key));

    transport->aes_128_rx_enable = 1;
}

static inline rn_transport_t * rn_tunnel_get_transport(rn_tunnel_t *tunnel, rn_transport_id transport_id)
{
    rn_transport_t *transport;

    rn_assert((transport_id >= 0) && (transport_id < tunnel->n_transport));

    transport = &(tunnel->transport_pool[transport_id]);

    rn_tunnel_transport_valid(transport);

    return transport;
}

int rn_transport_send(rn_tunnel_t *tunnel, rn_transport_t *transport, rn_pkb_t *pkb, rn_transport_frame_type_e type, uint32_t *challenge);
int tunnel_proc_send_bundle_join(rn_tunnel_t *tunnel, rn_transport_t *transport, char src_ipstr[], uint32_t pid_at_cli);
int tunnel_proc_send_session_new(rn_tunnel_t *tunnel, rn_transport_t *transport, uint32_t port, rn_local_agent_conn_id src_agent_conn_id, uint32_t *create_challenge);
int tunnel_proc_send_session_new_ack(rn_tunnel_t *tunnel, rn_transport_t *transport, int ret, uint32_t src_agent_conn_id, uint32_t dst_agent_conn_id, uint32_t source_challenge);
int tunnel_proc_send_session_del(rn_tunnel_t *tunnel, rn_transport_t *transport, rn_local_agent_conn_id src_agent_conn_id, rn_local_agent_conn_id dst_agent_conn_id);
int tunnel_proc_send_session_data(rn_tunnel_t *tunnel, rn_transport_t *transport, rn_pkb_t *pkb, rn_local_agent_conn_id src_agent_conn_id, rn_local_agent_conn_id dst_agent_conn_id, uint64_t idx);

int rn_tunnel_transport_polling_all(rn_tunnel_t *tunnel, int cycle_ms);

rn_transport_id rn_tunnel_bundle_transport_select(rn_tunnel_t *tunnel, rn_bundle_id bundle_id);
int rn_tunnel_bundle_find_transport(rn_tunnel_t *tunnel, rn_bundle_id bundle_id, rn_transport_id transport_id);
int rn_tunnel_bundle_insert_transport(rn_tunnel_t *tunnel, rn_bundle_id bundle_id, rn_transport_id transport_id);
int rn_tunnel_bundle_remove_transport(rn_tunnel_t *tunnel, rn_bundle_id bundle_id, rn_transport_id transport_id);
struct _rn_local_agent_conn_t;
int rn_tunnel_bundle_local_agent_conn_inbundle(rn_tunnel_t *tunnel, rn_bundle_id bundle_id, struct _rn_local_agent_conn_t *agent_conn);
int rn_tunnel_bundle_remote_agent_conn_inbundle(rn_tunnel_t *tunnel, rn_bundle_id bundle_id, rn_local_agent_conn_id remote_agent_conn_id, rn_local_agent_conn_id *local_agent_conn_id);
int rn_tunnel_bundle_attach_agent_conn(rn_tunnel_t *tunnel, rn_bundle_id bundle_id, struct _rn_local_agent_conn_t *agent_conn);
int rn_tunnel_bundle_detach_agent_conn(rn_tunnel_t *tunnel, rn_bundle_id bundle_id, struct _rn_local_agent_conn_t *agent_conn);
rn_bundle_id rn_tunnel_bundle_find(rn_tunnel_t *tunnel, char *ipstr_at_cli, char *ipstr_at_srv, uint32_t pid_at_cli);
rn_bundle_id rn_tunnel_bundle_new(rn_tunnel_t *tunnel, char *ipstr_at_cli, char *ipstr_at_srv, uint32_t pid_at_cli);
void rn_tunnel_bundle_del(rn_tunnel_t *tunnel, rn_bundle_id bundle_id);

rn_tunnel_t * rn_tunnel_create(rn_epoll_thread_t *epoll_thread, rn_pkb_pool_t *pkb_pool, uint32_t n_transport, uint8_t *default_key, uint32_t default_transport_send_bps);
int rn_tunnel_destroy(rn_tunnel_t *tunnel);

#endif
