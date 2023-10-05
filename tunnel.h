#ifndef _TUNNEL_H_
#define _TUNNEL_H_

#define FGFW_TUNNEL_SESSION_MAX                             64
#define FGFW_TUNNEL_BUNDLE_MAX                              16
#define FGFW_TUNNEL_MAX_TRANSPORT_PER_BUNDLE                64

#define FGFW_TUNNEL_SESSION_RECV_RING_BUF_SIZE              (2 * 1024 * 1024)

typedef int fgfw_tunnel_bundle_id;
#define FGFW_BUNDLE_ID_INVALID              ((fgfw_tunnel_bundle_id)(-1))

typedef struct _fgfw_tunnel_bundle {
    fgfw_tunnel_bundle_id                   bundle_id;

    int                                     valid;

    char                                    ipstr_at_cli[INET_ADDRSTRLEN];
    char                                    ipstr_at_srv[INET_ADDRSTRLEN];
    uint32_t                                pid_at_cli;                         /* client's pid */

    uint32_t                                n_transport, transport_idx;
    fgfw_transport_id                       transport_list[FGFW_TUNNEL_MAX_TRANSPORT_PER_BUNDLE];
} fgfw_tunnel_bundle_t;

typedef int fgfw_tunnel_session_id;

typedef enum {
    FGFW_TUNNEL_SESSION_STATE_FREE = 0,
    FGFW_TUNNEL_SESSION_STATE_INIT,
    FGFW_TUNNEL_SESSION_STATE_CREATING,                     /* wait for ack */
    FGFW_TUNNEL_SESSION_STATE_CREATE_FAILD,
    FGFW_TUNNEL_SESSION_STATE_READY,                        /* can send data */
    FGFW_TUNNEL_SESSION_STATE_DELETING,                     /* wait for ack */
} fgfw_tunnel_session_state_e;

typedef struct _fgfw_tunnel_session {
    struct _fgfw_tunnel                     *tunnel;
    fgfw_tunnel_bundle_id                   bundle_id;

    fgfw_tunnel_session_id                  id;             /* [0, (FGFW_TUNNEL_SESSION_MAX - 1)] */
    volatile fgfw_tunnel_session_state_e    session_state;
    fgfw_listhead_t                         node;

    uint32_t                                session_key;
    uint32_t                                session_offset_send;

    uint64_t                                recv_ring_tail, recv_ring_head;
    uint8_t                                 recv_ring_buf[FGFW_TUNNEL_SESSION_RECV_RING_BUF_SIZE];
    fgfw_range_res_t                        recv_range;     /* aready recv and store in recv_ring_buf, but not included in recv_ring_head->recv_ring_tail*/

    /*  */
    int                                     create_ret;
    uint32_t                                create_challenge;
} fgfw_tunnel_session_t;

struct _fgfw_local_agent;

/* connect to remote */
typedef struct _fgfw_tunnel {
    fgfw_epoll_thread_t     epoll_thread;

    int                     transport_key_enable;
    uint8_t                 default_key[16];

    int                     mode;           /* FGFW_WORKMODE_SERVER / FGFW_WORKMODE_CLIENT */

    fgfw_tunnel_session_t   _session_res[FGFW_TUNNEL_SESSION_MAX];
    fgfw_tunnel_session_t   *free_session_list[FGFW_TUNNEL_SESSION_MAX];
    uint32_t                free_session_tail, free_session_head;

    fgfw_transport_pool_t   transport_pool;

    int                     n_active_session;
    fgfw_listhead_t         active_session_list;

    int                     n_active_transport;
    fgfw_listhead_t         active_transport_list;

    int                     n_listen_transport;
    fgfw_listhead_t         listen_transport_list;

    int                     n_bundle;
    fgfw_tunnel_bundle_t    bundle_list[FGFW_TUNNEL_BUNDLE_MAX];

    /* return session id
     * or some err: FGFW_RETVALUE_NOENOUGHRES (no free resource)
     */
    fgfw_tunnel_session_id (*session_open)(struct _fgfw_tunnel *tunnel, fgfw_tunnel_bundle_id bundle_id, uint32_t port, uint32_t new_session_key);
    /*
     *
     */
    int (*session_close)(struct _fgfw_tunnel *tunnel, fgfw_tunnel_session_id session_id);
    /*
     */
    int (*session_send)(struct _fgfw_tunnel *tunnel, fgfw_tunnel_session_id session_id, void *buf, int len);
    /*
     */
    int (*session_recv)(struct _fgfw_tunnel *tunnel, fgfw_tunnel_session_id session_id, uint64_t session_offset, void *buf_first, int first_len, void *buf_second, int second_len);

    /* ugly */
    struct _fgfw_local_agent    *local_agent;
} fgfw_tunnel_t;

fgfw_tunnel_bundle_id fgfw_tunnel_bundle_find(fgfw_tunnel_t *tunnel, char *ipstr_at_cli, char *ipstr_at_srv, uint32_t pid_at_cli);
fgfw_tunnel_bundle_id fgfw_tunnel_bundle_new(fgfw_tunnel_t *tunnel, char *ipstr_at_cli, char *ipstr_at_srv, uint32_t pid_at_cli);
void fgfw_tunnel_bundle_del(fgfw_tunnel_t *tunnel, fgfw_tunnel_bundle_id bundle_id);
int fgfw_tunnel_bundle_find_transport(fgfw_tunnel_t *tunnel, fgfw_tunnel_bundle_id bundle_id, fgfw_transport_id transport_id);
int fgfw_tunnel_bundle_insert_transport(fgfw_tunnel_t *tunnel, fgfw_tunnel_bundle_id bundle_id, fgfw_transport_id transport_id);
int fgfw_tunnel_bundle_remove_transport(fgfw_tunnel_t *tunnel, fgfw_tunnel_bundle_id bundle_id, fgfw_transport_id transport_id);
fgfw_transport_id fgfw_tunnel_bundle_get_transport_id(fgfw_tunnel_t *tunnel, fgfw_tunnel_bundle_id bundle_id);

int fgfw_tunnel_create(fgfw_tunnel_t *tunnel, int mode, char *serv_ip, int n_port, int port_list[], uint8_t default_key[]);
int fgfw_tunnel_destroy(fgfw_tunnel_t *tunnel);
int fgfw_tunnel_connect_to_serv(fgfw_tunnel_t *tunnel, char *serv_ip, int n_port, int port_list[]);

/****************************************************************************************************
 * tunnel protocol
 */

#define FGFW_TUNNEL_PROTOCOL_MAGIC                          0x57464746
#define FGFW_TUNNEL_PROTOCOL_PKTLEN_ALIGN                   FGFW_TRANSPORT_PKT_ALIGN

static inline uint32_t fgfw_tunnel_protocol_align(int len) {
    uint32_t tmp = FGFW_TUNNEL_PROTOCOL_PKTLEN_ALIGN - 1;
    return ((len + tmp) & (~tmp));
}

typedef enum {
    FGFW_TP_TYPE_REQ = 0,
    FGFW_TP_TYPE_REQ_BUNDLE_JOIN,
    FGFW_TP_TYPE_REQ_SESSION_NEW,
    FGFW_TP_TYPE_REQ_SESSION_DEL,

    FGFW_TP_TYPE_RESP = 0x100,
    FGFW_TP_TYPE_RESP_BUNDLE_JOIN_ACK,
    FGFW_TP_TYPE_RESP_SESSION_NEW_ACK,
    FGFW_TP_TYPE_RESP_SESSION_DEL_ACK,

    FGFW_TP_TYPE_SESSION_DATA = 0x200,
} fgfw_tunnel_protocol_type_e;

typedef struct {
    fgfw_tunnel_protocol_type_e tp_type;
    uint32_t                    real_len;                   /* include this struct */
    uint32_t                    align_len;                  /* include this struct, align to FGFW_TUNNEL_PROTOCOL_PKTLEN_ALIGN */
    uint32_t                    challenge;                  /* make all pkt not same */
} fgfw_tunnel_protocol_pkt_head_t;

typedef struct {
    uint32_t        magic;
    char            src_ipstr[INET_ADDRSTRLEN];
    uint32_t        pid_at_cli;                             /* client's pid */
    uint32_t        key_len;
    uint8_t         key[64];
} fgfw_tunnel_protocol_pkt_bundle_join_req_t;

typedef struct {
    uint32_t        magic;
    int             ret;
    uint32_t        bundle_id;                              /* srv return */
} fgfw_tunnel_protocol_pkt_bundle_join_resp_t;

typedef struct {
    uint32_t        magic;
    uint32_t        port;
    fgfw_tunnel_session_id  orig_session_id;
} fgfw_tunnel_protocol_pkt_session_new_req_t;

typedef struct {
    uint32_t        magic;
    int             ret;
    fgfw_tunnel_session_id  orig_session_id;
    uint32_t        session_key;                            /* produced by server */
} fgfw_tunnel_protocol_pkt_session_new_resp_t;

typedef struct {
    uint32_t        magic;
    uint32_t        session_key;                            /*  */
} fgfw_tunnel_protocol_pkt_session_del_req_t;

typedef struct {
    uint32_t        magic;
    int             ret;
    uint32_t        session_key;                            /*  */
} fgfw_tunnel_protocol_pkt_session_del_resp_t;

typedef struct {
    uint32_t        magic;
    uint32_t        session_key;                            /* indicate session, after 'session create' proc, produced by tunnel server */
    uint64_t        session_offset;
} fgfw_tunnel_protocol_pkt_session_data_t;

/* */
int tunnel_proc_send_req_bundle_join(fgfw_tunnel_t *tunnel, fgfw_transport_t *transport, char src_ipstr[], uint32_t pid_at_cli, int key_len, uint8_t key[]);
int tunnel_proc_send_resp_bundle_join(fgfw_tunnel_t *tunnel, fgfw_transport_t *transport, uint32_t challenge, int ret, uint32_t bundle_id);
int tunnel_proc_send_req_session_new(fgfw_tunnel_t *tunnel, fgfw_transport_t *transport, uint32_t port, fgfw_tunnel_session_id orig_session_id, uint32_t *create_challenge);
int tunnel_proc_send_resp_session_new(fgfw_tunnel_t *tunnel, fgfw_transport_t *transport, uint32_t challenge, int ret, uint32_t session_key);

/*  */
int tunnel_transport_proc_one_pkt(fgfw_tunnel_t *tunnel, fgfw_transport_t *transport);

#endif