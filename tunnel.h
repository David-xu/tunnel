#ifndef _TUNNEL_H_
#define _TUNNEL_H_

#define FGFW_TUNNEL_SESSION_MAX         256

typedef int fgfw_tunnel_session_id;

typedef enum {
    FGFW_TUNNEL_SESSION_STATE_FREE = 0,
    FGFW_TUNNEL_SESSION_STATE_INIT
} fgfw_tunnel_session_state_e;

typedef struct _fgfw_tunnel_session {
    fgfw_tunnel_session_id              id; 
    fgfw_tunnel_session_state_e         session_state;
    fgfw_listhead_t                     node;
} fgfw_tunnel_session_t;

/* connect to remote */
typedef struct _fgfw_tunnel {
    fgfw_epoll_thread_t     epoll_thread;

    int                     mode;           /* FGFW_WORKMODE_SERVER / FGFW_WORKMODE_CLIENT */

    fgfw_tunnel_session_t   _session_res[FGFW_TUNNEL_SESSION_MAX];
    fgfw_tunnel_session_t   *free_session_list[FGFW_TUNNEL_SESSION_MAX];
    uint32_t                free_session_tail, free_session_head;

    int                     n_active_session;
    fgfw_listhead_t         active_session_list;

    /* return session id
     * or some err: FGFW_RETVALUE_NOENOUGHRES (no free resource)
     */
    fgfw_tunnel_session_id (*session_open)(struct _fgfw_tunnel *tunnel);
    /*
     *
     */
    int (*session_close)(struct _fgfw_tunnel *tunnel, fgfw_tunnel_session_id session_id);
} fgfw_tunnel_t;

int fgfw_tunnel_create(fgfw_tunnel_t *tunnel, int mode, char *serv_ip, int n_port, int port_list[]);
int fgfw_tunnel_destroy(fgfw_tunnel_t *tunnel);

#endif