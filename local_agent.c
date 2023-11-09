#include "pub.h"

struct {
    uint64_t            session_not_ok;
    uint64_t            recv_fifo_full;
    uint64_t            no_free_pkb;

    uint64_t            send_pkt, send_bytes, send_pkt_not_complete;

    uint64_t            vacc_send_err, vacc_recv_err;

    uint64_t            dest_transport_send_fifo_afull;
} stat;


static void rn_agent_conn_dump_cb(rn_socket_public_t *socket, void *dump_p)
{
    rn_local_agent_conn_t *agent_conn = RN_GETCONTAINER(socket, rn_local_agent_conn_t, socket);

    if (socket->vacc_host.insttype == VACC_HOST_INSTTYPE_SERVER_LISTENER) {
        return;
    }

    rn_printf("\t\t\tagent_conn id %d, fd %d, peer agent conn id %d, state %d, bundle_id %d, session_data_idx %ld, recv_fifo tail %d head %d\n"
        "\t\t\t stat:\n"
        "\t\t\tsession_not_ok %ld\n"
        "\t\t\trecv_fifo_full %ld\n"
        "\t\t\tno_free_pkb %ld\n"
        "\t\t\trecv_pkt %ld, recv_bytes %ld\n"
        "\t\t\tsend_pkt %ld, send_bytes %ld\n"
        "\t\t\tsend_pkt_not_complete %ld\n"
        "\t\t\tvacc_send_err %ld\n"
        "\t\t\tvacc_recv_err %ld\n"
        "\t\t\tdest_transport_send_fifo_full %ld\n",
        agent_conn->local_agent_conn_id, agent_conn->socket.vacc_host.sock_fd, agent_conn->peer_agent_conn_id,
        agent_conn->agent_conn_state, agent_conn->bundle_id, agent_conn->session_data_idx, agent_conn->recv_fifo->tail, agent_conn->recv_fifo->head,
        agent_conn->stat.session_not_ok,
        agent_conn->stat.recv_fifo_full,
        agent_conn->stat.no_free_pkb,
        agent_conn->stat.recv_pkt, agent_conn->stat.recv_bytes,
        agent_conn->stat.send_pkt, agent_conn->stat.send_bytes,
        agent_conn->stat.send_pkt_not_complete,
        agent_conn->stat.vacc_send_err,
        agent_conn->stat.vacc_recv_err,
        agent_conn->stat.dest_transport_send_fifo_afull);

    if (agent_conn->session_pkt_reorder) {
        uint64_t idx_list[agent_conn->session_pkt_reorder->window_size];
        void *p[agent_conn->session_pkt_reorder->window_size];
        rn_pkb_t *pkb;
        int n, i;

        n = rn_reorder_get_pending_list(agent_conn->session_pkt_reorder, idx_list, p);
        rn_printf("\t\t\treorder n_pending %d\n", n);
        for (i = 0; i < n; i++) {
            pkb = p[i];
            rn_printf("\t\t\t\tidx %ld\n", idx_list[i]);
            rn_printf("\t\t\t\tpkb cur_len %ld\n", pkb->cur_len);
#ifdef RN_CONFIG_PKBPOOL_CHECK
            rn_printf("\t\t\t\tpkb idx %d\n", pkb->idx);
#endif
        }
    }

}

void rn_local_agent_dump(rn_local_agent_t *local_agent)
{
    rn_printf("local agent: n_agent_conn %d\n",
        local_agent->n_agent_conn);

    rn_socket_mngr_dump(&(local_agent->socket_mngr), rn_agent_conn_dump_cb, local_agent);
}

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

/*
 * return: number of pkt dispatched success
 */
static int rn_agent_conn_dispatch(rn_local_agent_t *local_agent, rn_local_agent_conn_t *agent_conn)
{
    int ret, n_dispatch_pkt = 0;
    rn_transport_id transport_id;
    rn_transport_t *transport;
    rn_pkb_t *pkb;

    if (agent_conn->agent_conn_state != RN_AGENT_CONN_STATE_SESSION_OK) {
        agent_conn->stat.session_not_ok++;
        return 0;
    }

    rn_assert(agent_conn->peer_agent_conn_id != RN_AGENT_CONN_ID_INVALID);

    while (1) {
        if (RN_GPFIFO_ISEMPTY(agent_conn->recv_fifo)) {
            break;
        }

        transport_id = rn_tunnel_bundle_transport_select(local_agent->tunnel, agent_conn->bundle_id);
        transport = rn_tunnel_get_transport(local_agent->tunnel, transport_id);

        if (RN_GPFIFO_CUR_LEFT(transport->send_fifo) < RN_CONFIG_TRANSPORT_SEND_FIFO_CONTROL_PKT_QUOTA) {
            /* can't do dispatch */
            agent_conn->stat.dest_transport_send_fifo_afull++;
            break;
        }

        pkb = rn_gpfifo_dequeue_p(agent_conn->recv_fifo);

        ret = tunnel_proc_send_session_data(local_agent->tunnel, transport, pkb, agent_conn->local_agent_conn_id, agent_conn->peer_agent_conn_id, agent_conn->session_data_idx);
        rn_assert(ret == RN_RETVALUE_OK);
        agent_conn->session_data_idx++;

        n_dispatch_pkt++;
    }


    return n_dispatch_pkt;
}

static void rn_agent_conn_reset(rn_local_agent_t *local_agent, rn_local_agent_conn_t *agent_conn)
{
    rn_pkb_t *pkb;
    uint64_t i;
    uint32_t window_size;
    int ret;

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
    rn_assert(RN_GPFIFO_ISEMPTY(agent_conn->recv_fifo));
    agent_conn->recv_fifo->tail = agent_conn->recv_fifo->head = 0;

    /* drain recv reorder buffer */
    rn_assert(agent_conn->session_pkt_reorder != NULL);
    window_size = agent_conn->session_pkt_reorder->window_size;
    for (i = 0; i < window_size; i++) {
        ret = rn_reorder_get_entry(agent_conn->session_pkt_reorder, i, (void *)&pkb);
        if (ret == RN_RETVALUE_OK) {
            /* free pkb */
            rn_assert(pkb != NULL);
            rn_assert(rn_pkb_pool_put_pkb(local_agent->pkb_pool, pkb) == RN_RETVALUE_OK);
        }
    }
    /* destroy and create new session pkt order */
    rn_reorder_destroy(agent_conn->session_pkt_reorder);
    agent_conn->session_pkt_reorder = rn_reorder_create(window_size);
    rn_assert(agent_conn->session_pkt_reorder);

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

    rn_agent_conn_dispatch(local_agent, agent_conn);

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
    recv_len = rand() % (RN_CONFIG_TRANSPORT_FRAME_SESSION_DATA_MAXLEN / 2);
    recv_len += (RN_CONFIG_TRANSPORT_FRAME_SESSION_DATA_MAXLEN / 2);
    ret = rn_pkb_recv(pkb, recv_len, &(agent_conn->socket.vacc_host));
    if (ret < 0) {
        rn_pkb_pool_put_pkb(local_agent->pkb_pool, pkb);
        goto __pkt_recv_err;
    }

    rn_dbg(
        RUN_DBGFLAG_AGENT_CONN_DUMPDATA, "agent_conn id %d, peer conn id %d, ret %d, pkb->cur_len %d, recv data: 0x%08x 0x%08x 0x%08x 0x%08x\n",
        agent_conn->local_agent_conn_id, agent_conn->peer_agent_conn_id, ret, pkb->cur_len,
        ((uint32_t *)RN_PKB_HEAD(pkb))[0], ((uint32_t *)RN_PKB_HEAD(pkb))[1], ((uint32_t *)RN_PKB_HEAD(pkb))[2], ((uint32_t *)RN_PKB_HEAD(pkb))[3]);

    /* recv_buff enqueue */
    agent_conn->stat.recv_bytes += pkb->cur_len;
    agent_conn->stat.recv_pkt++;
    rn_assert(rn_gpfifo_enqueue_p(agent_conn->recv_fifo, pkb) == RN_RETVALUE_OK);

    rn_agent_conn_dispatch(local_agent, agent_conn);

    return;


__detach_epoll_inst:
    /* remove from epoll_thread */
    if (agent_conn->epoll_inst.already_in_epoll == 1) {
        ret = rn_epoll_thread_reg_uninst(local_agent->epoll_thread, &(agent_conn->epoll_inst));
        if (ret != RN_RETVALUE_OK) {
            /* todo: */
            rn_assert(0);
        }
        rn_dbg(RUN_DBGFLAG_AGENT_CONN, "agent_conn %d, epoll detach.\n", agent_conn->local_agent_conn_id);
    }

    return;

__pkt_recv_err:
    /* todo: */
    if (ret == VACC_HOST_RET_PEERCLOSE) {
        /* peer close */
    } else {
        /* maybe some err, just return */
        agent_conn->stat.vacc_recv_err++;
        rn_assert(0);
    }

    return;
}

/*
 * try to drain agent_conn recv session order
 */
void rn_agent_conn_session_order_drain(rn_local_agent_t *local_agent, rn_local_agent_conn_t *agent_conn)
{
    int ret;
    rn_pkb_t *pkb;

    /* try to send pkt */
    while (1) {
        ret = rn_reorder_get_entry(agent_conn->session_pkt_reorder, agent_conn->session_pkt_reorder->next_idx, (void **)&pkb);
        if (ret == RN_RETVALUE_REORDER_NO_VALID) {
            break;
        }
        /* do send */
        ret = rn_pkb_send(pkb, pkb->cur_len, &(agent_conn->socket.vacc_host));
        rn_assert(ret != RN_RETVALUE_NOENOUGHSPACE);
        if (ret >= 0) {
            agent_conn->stat.send_bytes += ret;
            if (pkb->cur_len == 0) {
                /* all data in this pkt already send */

                /* remove from 'recv session order' */
                rn_reorder_remove(agent_conn->session_pkt_reorder);

                /* free this pkt */
                rn_assert(rn_pkb_pool_put_pkb(local_agent->pkb_pool, pkb) == RN_RETVALUE_OK);

                agent_conn->stat.send_pkt++;
            } else {
                /* data not send completed, just wait for next loop */
                agent_conn->stat.send_pkt_not_complete++;
                break;
            }
        } else {
            if (ret == VACC_HOST_RET_PEERCLOSE) {
                /* peer close */
            } else {
                /* maybe some err, just return */
                agent_conn->stat.vacc_send_err++;
            }
            break;
        }
    }
}

static int rn_agent_conn_polling(rn_local_agent_t *local_agent, rn_local_agent_conn_t *agent_conn, int cycle_ms)
{
    int ret;

    rn_agent_conn_dispatch(local_agent, agent_conn);

    if (RN_GPFIFO_CUR_LEN(agent_conn->recv_fifo) < (agent_conn->recv_fifo->depth / 4)) {
        if (agent_conn->epoll_inst.already_in_epoll == 0) {
            ret = rn_epoll_thread_reg_inst(local_agent->epoll_thread, &(agent_conn->epoll_inst));
            if (ret != RN_RETVALUE_OK) {
                /* todo: */
                rn_assert(0);
            }
            rn_dbg(RUN_DBGFLAG_AGENT_CONN, "agent_conn %d, epoll attach.\n", agent_conn->local_agent_conn_id);
        }
    }

    rn_agent_conn_session_order_drain(local_agent, agent_conn);

    return RN_RETVALUE_OK;
}


int rn_agent_conn_polling_all(rn_local_agent_t *local_agent, int cycle_ms)
{
    rn_socket_public_t *p, *n;
    rn_socket_mngr_t *mngr = &(local_agent->socket_mngr);
    rn_local_agent_conn_t *agent_conn;

    rn_assert((mngr->n_listen + mngr->n_srv_inst + mngr->n_client_inst + RN_GPFIFO_CUR_LEN(mngr->free_fifo)) == mngr->unit_num);

    /* server inst list: */
    if (mngr->n_srv_inst) {
        RN_LISTENTRYWALK_SAVE(p, n, &(mngr->srv_inst_list), list_entry) {
            rn_assert(p->vacc_host.insttype == VACC_HOST_INSTTYPE_SERVER_INST);
            agent_conn = RN_GETCONTAINER(p, rn_local_agent_conn_t, socket);
            rn_agent_conn_polling(local_agent, agent_conn, cycle_ms);
        }
    }
    /* client inst list: */
    if (mngr->n_client_inst) {
        RN_LISTENTRYWALK_SAVE(p, n, &(mngr->client_inst_list), list_entry) {
            rn_assert(p->vacc_host.insttype == VACC_HOST_INSTTYPE_CLIENT_INST);
            agent_conn = RN_GETCONTAINER(p, rn_local_agent_conn_t, socket);
            rn_agent_conn_polling(local_agent, agent_conn, cycle_ms);
        }
    }

    return RN_RETVALUE_OK;
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
            ret = rn_tunnel_bundle_attach_agent_conn(local_agent->tunnel, 0, agent_conn);
            if (ret != RN_RETVALUE_OK) {
                rn_log("bundle 0 is not valid.\n");
                vacc_host_destroy(&(socket->vacc_host));
            }

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
        local_agent->agent_conn_list[i].session_pkt_reorder = rn_reorder_create(RN_CONFIG_AGENT_CONN_SESSION_PKT_WINDOW);
        rn_assert(local_agent->agent_conn_list[i].session_pkt_reorder != NULL);
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

        rn_assert(rn_reorder_get_pending_list(local_agent->agent_conn_list[i].session_pkt_reorder, NULL, NULL) == 0);
        rn_reorder_destroy(local_agent->agent_conn_list[i].session_pkt_reorder);
    }

    free(local_agent);

    return RN_RETVALUE_OK;

}


