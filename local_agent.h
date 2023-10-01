#ifndef _LOCAL_AGENT_H_
#define _LOCAL_AGENT_H_

#define FGFW_LOCAL_AGENT_MAX_CONN           256

typedef struct {
    vacc_host_t             vacc_host;
    fgfw_listhead_t         node;           /* link to active local conn list */
} fgfw_local_agent_conn_t;

/* this is used for connect to local */
typedef struct {
    fgfw_epoll_thread_t     epoll_thread;
    fgfw_tunnel_t           *tunnel;

    fgfw_local_agent_conn_t local_conn_pool[FGFW_LOCAL_AGENT_MAX_CONN];
    fgfw_local_agent_conn_t *free_local_conn[FGFW_LOCAL_AGENT_MAX_CONN];
    uint32_t                free_local_conn_tail, free_local_conn_head;


    int                     n_active_local_conn;
    fgfw_listhead_t         active_local_conn;

    int                     n_listen_local_conn;
    fgfw_listhead_t         listen_local_conn;
} fgfw_local_agent_t;

int fgfw_local_agent_create(fgfw_local_agent_t *local_agent, fgfw_tunnel_t *tunnel, int n_local_agent_port, int local_agent_port_list[]);
int fgfw_local_agent_destroy(fgfw_local_agent_t *local_agent);

#endif