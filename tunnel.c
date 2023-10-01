#include "pub.h"

static fgfw_tunnel_session_id fgfw_tunnel_session_open(fgfw_tunnel_t *tunnel)
{
    fgfw_tunnel_session_t *new_session;

    if (tunnel->free_session_tail == tunnel->free_session_head) {
        return FGFW_RETVALUE_NOENOUGHRES;
    }
    
    /* dequeue from free list */
    new_session = tunnel->free_session_list[tunnel->free_session_head % FGFW_TUNNEL_SESSION_MAX];
    fgfw_assert(new_session->session_state == FGFW_TUNNEL_SESSION_STATE_FREE);
    tunnel->free_session_head++;

    /**/
    new_session->session_state = FGFW_TUNNEL_SESSION_STATE_INIT;

    /**/
    fgfw_listadd_tail(&(new_session->node), &(tunnel->active_session_list));
    tunnel->n_active_session++;

    /* do session create */
    /* 1. send control pkt */
    /* 2. wait for ack */

    return new_session->id;
}

static int fgfw_tunnel_session_close(fgfw_tunnel_t *tunnel, fgfw_tunnel_session_id session_id)
{
    fgfw_tunnel_session_t *session = &(tunnel->_session_res[session_id]);

    fgfw_assert((session_id >= 0) && (session_id < FGFW_TUNNEL_SESSION_MAX));
    
    if (session->session_state == FGFW_TUNNEL_SESSION_STATE_FREE) {
        fgfw_warn("session id %d, already freed\n", session_id);
        return FGFW_RETVALUE_OK;
    }

    /* do session destroy */
    /* 1. send control pkt */
    /* 2. wait for ack */

    /* free session */
    fgfw_listdel(&(session->node));
    tunnel->n_active_session--;
    
    session->session_state = FGFW_TUNNEL_SESSION_STATE_FREE;

    /* enqueue into free list */
    tunnel->free_session_list[tunnel->free_session_tail % FGFW_TUNNEL_SESSION_MAX] = session;
    tunnel->free_session_tail++;
    fgfw_assert((tunnel->free_session_tail - tunnel->free_session_head) < FGFW_TUNNEL_SESSION_MAX);

    return FGFW_RETVALUE_OK;
}

int fgfw_tunnel_create(fgfw_tunnel_t *tunnel, int mode, char *serv_ip, int n_port, int port_list[])
{
    int ret, i;

    if ((mode != FGFW_WORKMODE_SERVER) && (mode != FGFW_WORKMODE_CLIENT)) {
        return FGFW_RETVALUE_INVALID_PARAM;
    }

    memset(tunnel, 0, sizeof(fgfw_tunnel_t));

    tunnel->n_active_session = 0;
    fgfw_initlisthead(&(tunnel->active_session_list));

    /* init free session list */
    for (i = 0; i < FGFW_TUNNEL_SESSION_MAX; i++) {
        tunnel->_session_res[i].id = i;
        tunnel->_session_res[i].session_state = FGFW_TUNNEL_SESSION_STATE_FREE;
        tunnel->free_session_list[i] = &(tunnel->_session_res[i]);
    }
    tunnel->free_session_tail = FGFW_TUNNEL_SESSION_MAX;
    tunnel->free_session_head = 0;

    /* create epoll thread */
    ret = fgfw_epoll_thread_create(&(tunnel->epoll_thread));
    if (ret) {
        fgfw_err("fgfw_epoll_thread_create() return %d\n", ret);
        return ret;
    }

    tunnel->mode = mode;

    tunnel->session_open = fgfw_tunnel_session_open;
    tunnel->session_close = fgfw_tunnel_session_close;

    return FGFW_RETVALUE_OK;
}

int fgfw_tunnel_destroy(fgfw_tunnel_t *tunnel)
{
    fgfw_tunnel_session_t *p, *n;

    FGFW_LISTENTRYWALK_SAVE(p, n, &(tunnel->active_session_list), node) {
        tunnel->session_close(tunnel, p->id);
    }

    fgfw_epoll_thread_destroy(&(tunnel->epoll_thread));
    
    return FGFW_RETVALUE_OK;
}