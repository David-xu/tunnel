#include "pub.h"

static int rn_agent_conn_new_connect(rn_local_agent_t *local_agent, rn_local_agent_conn_t *agent_conn)
{
    rn_transport_id ctrl_transport_id;
    rn_transport_t *transport;
    uint32_t remote_port;
    int ret;

    rn_assert(agent_conn->ctrl_transport_id == RN_TRANSPORT_ID_INVALID);

    /* select transport */
    ctrl_transport_id = rn_tunnel_bundle_transport_select(local_agent->tunnel, agent_conn->bundle_id);
    transport = rn_tunnel_get_transport(local_agent->tunnel, ctrl_transport_id);
    remote_port = agent_conn->socket.listen_port + local_agent->port_agent_offset;

    /* send session new by bundle */
    ret = tunnel_proc_send_session_new(local_agent->tunnel, transport, remote_port, agent_conn->local_agent_conn_id, &agent_conn->source_challenge);
    rn_assert(ret == RN_RETVALUE_OK);

    agent_conn->agent_conn_state = RN_AGENT_CONN_STATE_SESSION_CREATING;
    agent_conn->ctrl_transport_id = ctrl_transport_id;

    return RN_RETVALUE_OK;
}

static int rn_agent_conn_del_connect(rn_local_agent_t *local_agent, rn_local_agent_conn_t *agent_conn)
{
    rn_transport_t *transport;
    int ret;

    rn_assert(agent_conn->ctrl_transport_id != RN_TRANSPORT_ID_INVALID);

    if (agent_conn->passive_close == 1) {
        /* passive close, no need to send 'session del' */
    } else {
        //
        transport = rn_tunnel_get_transport(local_agent->tunnel, agent_conn->ctrl_transport_id);

        /* need to send session del */
        ret = tunnel_proc_send_session_del(local_agent->tunnel, transport, agent_conn->local_agent_conn_id, agent_conn->peer_agent_conn_id);
        rn_assert(ret == RN_RETVALUE_OK);
    }

    return RN_RETVALUE_OK;
}


static void rn_agent_conn_reset(rn_local_agent_t *local_agent, rn_local_agent_conn_t *agent_conn)
{
    rn_pkb_t *pkb;

    rn_agent_conn_valid(agent_conn);

    /* detach from bundle */
    if (agent_conn->bundle_id != RN_BUNDLE_ID_INVALID) {
        rn_assert(rn_tunnel_bundle_detach_agent_conn(local_agent->tunnel, agent_conn->bundle_id, agent_conn) == RN_RETVALUE_OK);
    }

    /* drain recv fifo */
    while (!RN_GPFIFO_ISEMPTY(agent_conn->recv_fifo)) {
        pkb = rn_gpfifo_dequeue_p(agent_conn->recv_fifo);
        rn_assert(pkb != NULL);
        rn_assert(rn_pkb_pool_put_pkb(local_agent->pkb_pool, pkb) == RN_RETVALUE_OK);
    }

    memset(RN_V2P(RN_P2V(agent_conn) + offsetof(rn_local_agent_conn_t, agent_conn_state)), 0, sizeof(rn_local_agent_conn_t) - offsetof(rn_local_agent_conn_t, agent_conn_state));

    agent_conn->agent_conn_state = RN_AGENT_CONN_STATE_UNINIT;
    agent_conn->peer_agent_conn_id = RN_AGENT_CONN_ID_INVALID;
    agent_conn->ctrl_transport_id = RN_TRANSPORT_ID_INVALID;
    agent_conn->bundle_id = RN_BUNDLE_ID_INVALID;
    rn_initlisthead(&(agent_conn->bundle_link));
}

static void rn_agent_conn_listener_epoll_inst_cb(rn_epoll_inst_t *epoll_inst)
{
    rn_local_agent_conn_t *agent_conn = RN_GETCONTAINER(epoll_inst, rn_local_agent_conn_t, epoll_inst);

    vacc_host_read(&(agent_conn->socket.vacc_host), NULL, 0);
}

static void rn_agent_conn_epoll_inst_cb(rn_epoll_inst_t *epoll_inst)
{
    rn_local_agent_conn_t *agent_conn = RN_GETCONTAINER(epoll_inst, rn_local_agent_conn_t, epoll_inst);
    rn_local_agent_t *local_agent = agent_conn->local_agent;
    rn_pkb_t *pkb;
    int ret, recv_len;

    rn_agent_conn_valid(agent_conn);

    /* agent session not ready, detach this agent conn */
    if (agent_conn->agent_conn_state != RN_AGENT_CONN_STATE_SESSION_OK) {
        agent_conn->stat.session_not_ok++;
        goto __detach_epoll_inst;
    }

    /* recv fifo is already full, detach this agent conn */
    if (RN_GPFIFO_ISFULL(agent_conn->recv_fifo)) {
        agent_conn->stat.recv_fifo_full++;
        goto __detach_epoll_inst;
    }

    /* get one pkb */
    pkb = rn_pkb_pool_get_pkb(local_agent->pkb_pool);
    if (pkb == NULL) {
        agent_conn->stat.no_free_pkb++;
        goto __detach_epoll_inst;
    }

    /* do recv, rand() len */
    recv_len = rand() % RN_PKB_LEFTSPACE(pkb);
    ret = rn_pkb_recv(pkb, recv_len, &(agent_conn->socket.vacc_host));
    if (ret < 0) {
        rn_pkb_pool_put_pkb(local_agent->pkb_pool, pkb);
        goto __pkt_recv_err;
    }

    /* recv_buff enqueue */
    rn_assert(rn_gpfifo_enqueue_p(agent_conn->recv_fifo, pkb) == RN_RETVALUE_OK);

    return;


__detach_epoll_inst:
    /* remove from epoll_thread */
    ret = rn_epoll_thread_reg_uninst(local_agent->epoll_thread, &(agent_conn->epoll_inst));
    if (ret != RN_RETVALUE_OK) {
        /* todo: */
        rn_assert(0);
    }
    return;

__pkt_recv_err:
    /* todo: */
    if (ret == VACC_HOST_RET_PEERCLOSE) {
        /* peer close */
    } else {
        /* maybe some err, just return */
        agent_conn->stat.vacc_recv_err++;
    }

    return;
}

static int rn_agent_conn_init(rn_socket_mngr_t *mngr, rn_socket_public_t *socket, void *cb_param)
{
    rn_local_agent_t *local_agent = (rn_local_agent_t *)cb_param;
    rn_local_agent_conn_t *agent_conn = RN_GETCONTAINER(socket, rn_local_agent_conn_t, socket);
    int ret;

    rn_assert(agent_conn->agent_conn_state == RN_AGENT_CONN_STATE_UNINIT);

    switch (socket->vacc_host.insttype) {
    case VACC_HOST_INSTTYPE_SERVER_LISTENER:
        /* add into epoll thread main loop */
        agent_conn->epoll_inst.epoll_inst_cb = rn_agent_conn_listener_epoll_inst_cb;
        agent_conn->epoll_inst.fd = socket->vacc_host.sock_fd;
        ret = rn_epoll_thread_reg_inst(local_agent->epoll_thread, &(agent_conn->epoll_inst));
        if (ret != RN_RETVALUE_OK) {
            /* todo: */
            rn_assert(0);
        }

        /* change to listening */
        agent_conn->agent_conn_state = RN_AGENT_CONN_STATE_LISTENING;

        break;
    case VACC_HOST_INSTTYPE_SERVER_INST:
    case VACC_HOST_INSTTYPE_CLIENT_INST:
        /* add into epoll thread main loop */
        agent_conn->epoll_inst.epoll_inst_cb = rn_agent_conn_epoll_inst_cb;
        agent_conn->epoll_inst.fd = socket->vacc_host.sock_fd;
        ret = rn_epoll_thread_reg_inst(local_agent->epoll_thread, &(agent_conn->epoll_inst));
        if (ret != RN_RETVALUE_OK) {
            /* todo: */
            rn_assert(0);
        }

        rn_agent_conn_reset(local_agent, agent_conn);

        /* change to connected */
        agent_conn->agent_conn_state = RN_AGENT_CONN_STATE_CONNECTED;

        if (socket->vacc_host.insttype == VACC_HOST_INSTTYPE_SERVER_INST) {
            /* attach agent_conn to bundle, only has bundle 0 */
            rn_tunnel_bundle_attach_agent_conn(local_agent->tunnel, 0, agent_conn);

            if (rn_agent_conn_new_connect(local_agent, agent_conn) != RN_RETVALUE_OK) {
                vacc_host_destroy(&(socket->vacc_host));
            }
        } else {

        }

        break;
    default:
        rn_assert(0);
    }

    return RN_RETVALUE_OK;
}

static int rn_agent_conn_uninit(rn_socket_mngr_t *mngr, rn_socket_public_t *socket, void *cb_param)
{
    rn_local_agent_t *local_agent = (rn_local_agent_t *)cb_param;
    rn_local_agent_conn_t *agent_conn = RN_GETCONTAINER(socket, rn_local_agent_conn_t, socket);
    int ret;

    switch (socket->vacc_host.insttype) {
    case VACC_HOST_INSTTYPE_SERVER_LISTENER:
        rn_assert(agent_conn->agent_conn_state == RN_AGENT_CONN_STATE_LISTENING);
        /* remove from epoll thread main loop */
        ret = rn_epoll_thread_reg_uninst(local_agent->epoll_thread, &(agent_conn->epoll_inst));
        if (ret != RN_RETVALUE_OK) {
            /* todo: */
            rn_assert(0);
        }
        break;
    case VACC_HOST_INSTTYPE_SERVER_INST:
    case VACC_HOST_INSTTYPE_CLIENT_INST:
        rn_assert(agent_conn->agent_conn_state != RN_AGENT_CONN_STATE_UNINIT);
        /* remove from epoll thread main loop */
        ret = rn_epoll_thread_reg_uninst(local_agent->epoll_thread, &(agent_conn->epoll_inst));
        if (ret != RN_RETVALUE_OK) {
            /* todo: */
            rn_assert(0);
        }

        rn_log("agent conn id %d %s close.\n", agent_conn->local_agent_conn_id, agent_conn->passive_close == 1 ? "passive" : "active");

        if ((agent_conn->agent_conn_state == RN_AGENT_CONN_STATE_SESSION_CREATING) || (agent_conn->agent_conn_state == RN_AGENT_CONN_STATE_SESSION_OK)) {
            if (agent_conn->passive_close == 0) {
                rn_agent_conn_del_connect(local_agent, agent_conn);
            } else {
                /* passive close, no need to send 'session del' */
            }
        }

        rn_agent_conn_reset(local_agent, agent_conn);

        break;
    default:
        rn_assert(0);
    }

    return RN_RETVALUE_OK;
}


rn_local_agent_t * rn_local_agent_create(rn_tunnel_t *tunnel, rn_epoll_thread_t *epoll_thread, rn_pkb_pool_t *pkb_pool, uint32_t n_agent_conn, int port_agent_offset)
{
    rn_local_agent_t *local_agent;
    uint32_t agent_conn_size = sizeof(rn_local_agent_conn_t);
    uint32_t total_size = sizeof(rn_tunnel_t) + agent_conn_size * n_agent_conn;
    uint32_t i;
    int ret;

    RN_BUILD_BUG_ON(offsetof(rn_local_agent_conn_t, socket) != 0);
    RN_BUILD_BUG_ON(RN_AGENT_CONN_STATE_UNINIT != 0);

    rn_assert(epoll_thread != NULL);

    local_agent = malloc(total_size);
    rn_assert(local_agent != NULL);
    memset(local_agent, 0, sizeof(rn_local_agent_t));

    ret = rn_socket_mngr_create(&(local_agent->socket_mngr), &(local_agent->agent_conn_list[0].socket),
        n_agent_conn, agent_conn_size, rn_agent_conn_init, rn_agent_conn_uninit, local_agent);
    rn_assert(ret == RN_RETVALUE_OK);

    local_agent->tunnel = tunnel;
    local_agent->epoll_thread = epoll_thread;
    local_agent->pkb_pool = pkb_pool;
    local_agent->port_agent_offset = port_agent_offset;

    local_agent->n_agent_conn = n_agent_conn;
    for (i = 0; i < n_agent_conn; i++) {
        local_agent->agent_conn_list[i].local_agent_conn_id = i;
        local_agent->agent_conn_list[i].local_agent = local_agent;
        local_agent->agent_conn_list[i].recv_fifo = rn_gpfifo_create(RN_CONFIG_AGENT_CONN_RECV_FIFO_DEPTH, sizeof(rn_pkb_t *));
        rn_assert(local_agent->agent_conn_list[i].recv_fifo != NULL);
        local_agent->agent_conn_list[i].peer_agent_conn_id = RN_AGENT_CONN_ID_INVALID;
        local_agent->agent_conn_list[i].ctrl_transport_id = RN_TRANSPORT_ID_INVALID;
        local_agent->agent_conn_list[i].bundle_id = RN_BUNDLE_ID_INVALID;
    }

    return local_agent;
}

int rn_local_agent_destroy(rn_local_agent_t *local_agent)
{
    int ret, i;

    ret = rn_socket_mngr_destroy(&(local_agent->socket_mngr));
    rn_assert(ret == RN_RETVALUE_OK);

    for (i = 0; i < local_agent->n_agent_conn; i++) {
        rn_assert(RN_GPFIFO_ISEMPTY(local_agent->agent_conn_list[i].recv_fifo));
        rn_gpfifo_destroy(local_agent->agent_conn_list[i].recv_fifo);
    }

    free(local_agent);

    return RN_RETVALUE_OK;

}


