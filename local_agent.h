#ifndef _LOCAL_AGENT_H_
#define _LOCAL_AGENT_H_

typedef enum {
    RN_AGENT_CONN_STATE_UNINIT = 0,
    RN_AGENT_CONN_STATE_LISTENING,
    RN_AGENT_CONN_STATE_CONNECTED,
    RN_AGENT_CONN_STATE_SESSION_CREATING,           /* already send RN_TRANSPORT_FRAME_TYPE_SESSION_NEW */
    RN_AGENT_CONN_STATE_SESSION_OK,
} rn_agent_conn_state_e;

struct _rn_local_agent;
typedef struct _rn_local_agent_conn_t {
    rn_socket_public_t      socket;                 /* should be first element */
    rn_epoll_inst_t         epoll_inst;
    rn_local_agent_conn_id  local_agent_conn_id;
    struct _rn_local_agent  *local_agent;
    rn_gpfifo_t             *recv_fifo;             /*  */

    /* need reset */
    rn_agent_conn_state_e   agent_conn_state;       /* after this element, should be reset */
    rn_local_agent_conn_id  peer_agent_conn_id;     /* after session create, save peer agent conn id */
    int                     passive_close;          /* after recv session del msg */
    rn_transport_id         ctrl_transport_id;      /* all control msg should send by same transport */

    rn_bundle_id            bundle_id;              /*  */
    rn_listhead_t           bundle_link;            /* link to bundle */

    uint32_t                source_challenge;       /* save source challenge while session create */

    struct {
        uint64_t            session_not_ok;
        uint64_t            recv_fifo_full;
        uint64_t            no_free_pkb;

        uint64_t            send_pkt, send_bytes;

        uint64_t            vacc_send_err, vacc_recv_err;
    } stat;
} rn_local_agent_conn_t;

#define RN_CONFIG_AGENT_CONN_RECV_FIFO_DEPTH        2

/* this is used for connect to local */
typedef struct _rn_local_agent {
    rn_socket_mngr_t        socket_mngr;
    rn_tunnel_t             *tunnel;
    rn_epoll_thread_t       *epoll_thread;
    rn_pkb_pool_t           *pkb_pool;

    int                     port_agent_offset;              /* create session: port + port_agent_offset */

    int                     n_agent_conn;
    rn_local_agent_conn_t   agent_conn_list[0];
} rn_local_agent_t;

#ifdef RN_CONFIG_AGENT_CONN_CHECK
static inline void rn_agent_conn_valid(rn_local_agent_conn_t *agent_conn)
{
    rn_local_agent_t *local_agent;
    int idx;

    local_agent = agent_conn->local_agent;
    rn_assert(agent_conn->recv_fifo != NULL);
    rn_assert(local_agent != NULL);
    idx = agent_conn - local_agent->agent_conn_list;
    rn_assert(idx == agent_conn->local_agent_conn_id);
    rn_assert(idx == agent_conn->socket.conn_id);
}
#else
#define rn_agent_conn_valid(agent_conn)
#endif

static inline rn_local_agent_conn_t * rn_local_agent_get_conn(rn_local_agent_t *local_agent, rn_local_agent_conn_id agent_conn_id)
{
    rn_local_agent_conn_t *agent_conn = &(local_agent->agent_conn_list[agent_conn_id]);

    rn_assert((agent_conn_id >= 0) && (agent_conn_id < local_agent->n_agent_conn));

    rn_agent_conn_valid(agent_conn);

    return agent_conn;
}

rn_local_agent_t * rn_local_agent_create(rn_tunnel_t *tunnel, rn_epoll_thread_t *epoll_thread, rn_pkb_pool_t *pkb_pool, uint32_t n_agent_conn, int port_agent_offset);
int rn_local_agent_destroy(rn_local_agent_t *local_agent);


#endif

