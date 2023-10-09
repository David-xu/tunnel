#ifndef _LOCAL_AGENT_H_
#define _LOCAL_AGENT_H_

#define FGFW_LOCAL_AGENT_MAX_CONN           256

struct _fgfw_local_agent;
typedef struct {
    int                         valid;
    fgfw_local_agent_conn_id    conn_id;
    struct _fgfw_local_agent    *local_agent;
    fgfw_tunnel_session_id      session_id;
    vacc_host_t                 vacc_host;
    fgfw_listhead_t             node;           /* link to active local conn list */
    fgfw_epoll_inst_t           epoll_inst;     /*  */

    uint32_t                    listen_port;
    uint32_t                    connect_port;
} fgfw_local_agent_conn_t;

/* this is used for connect to local */
typedef struct _fgfw_local_agent {
    fgfw_epoll_thread_t     epoll_thread;
    fgfw_tunnel_t           *tunnel;

    int                     mode;           /* FGFW_WORKMODE_SERVER / FGFW_WORKMODE_CLIENT */
    int                     port_agent_offset;

    fgfw_local_agent_conn_t local_conn_pool[FGFW_LOCAL_AGENT_MAX_CONN];
    fgfw_local_agent_conn_t *free_local_conn[FGFW_LOCAL_AGENT_MAX_CONN];
    uint32_t                free_local_conn_tail, free_local_conn_head;


    int                     n_active_local_conn;
    fgfw_listhead_t         active_local_conn;

    int                     n_listen_local_conn;
    fgfw_listhead_t         listen_local_conn;

    /*
     * return new agent_conn id
     */
    fgfw_local_agent_conn_id (*local_conn_open)(struct _fgfw_local_agent *local_agent, fgfw_tunnel_session_id session_id, uint32_t port);
    /*
     *
     */
    int (*local_conn_close)(struct _fgfw_local_agent *local_agent, fgfw_local_agent_conn_id id);
    /*
     */
    int (*local_conn_send)(struct _fgfw_local_agent *local_agent, fgfw_local_agent_conn_id agent_conn_id, void *buf, int len);
} fgfw_local_agent_t;

void fgfw_local_agent_dump(fgfw_local_agent_t *local_agent);
int fgfw_local_agent_bundle_id_valid(fgfw_local_agent_conn_id agent_conn_id);
int fgfw_local_agent_create(fgfw_local_agent_t *local_agent, int mode, int port_agent_offset, fgfw_tunnel_t *tunnel, int n_local_agent_port, int local_agent_port_list[]);
int fgfw_local_agent_destroy(fgfw_local_agent_t *local_agent);

#endif