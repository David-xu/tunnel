#include "pub.h"

int tunnel_proc_send_bundle_join(rn_tunnel_t *tunnel, rn_transport_t *transport, char src_ipstr[], uint32_t pid_at_cli)
{
    rn_pkb_t *pkb;
    rn_transport_frame_boundle_join_t *bundle_join_req;

    pkb = rn_pkb_pool_get_pkb(tunnel->pkb_pool);
    rn_assert(pkb != NULL);

    bundle_join_req = RN_PKB_HEAD(pkb);

    memset(bundle_join_req, 0, sizeof(rn_transport_frame_boundle_join_t));

    if (src_ipstr) {
        strncpy(bundle_join_req->src_ipstr, src_ipstr, sizeof(bundle_join_req->src_ipstr));
    }
    bundle_join_req->pid_at_cli = pid_at_cli;
    pkb->cur_len = sizeof(rn_transport_frame_boundle_join_t);

    return rn_transport_send(tunnel, transport, pkb, RN_TRANSPORT_FRAME_TYPE_BUNDLE_JOIN, NULL);
}

static int tunnel_proc_recv_bundle_join(rn_tunnel_t *tunnel, rn_transport_t *transport, rn_transport_frame_head_t *frame_head)
{
    int ret;
    rn_bundle_id bundle_id;
    rn_transport_frame_boundle_join_t *bundle_join_req = (rn_transport_frame_boundle_join_t *)(frame_head + 1);

    if (transport->transport_state != RN_TRANSPORT_STATE_CONNECTED) {
        rn_err("transport_id %d, recv RN_TRANSPORT_FRAME_TYPE_BUNDLE_JOIN in err state %d",
            transport->transport_id, transport->transport_state);
        return RN_RETVALUE_INVALID_STATE;
    }

    struct in_addr in = transport->socket.vacc_host.u.tcp.cli_addr.sin_addr;
    char ipstr[INET_ADDRSTRLEN];

    inet_ntop(AF_INET, &in, ipstr, sizeof(ipstr));

    bundle_id = rn_tunnel_bundle_find(tunnel, bundle_join_req->src_ipstr, ipstr, bundle_join_req->pid_at_cli);
    if (bundle_id < 0) {
        bundle_id = rn_tunnel_bundle_new(tunnel, bundle_join_req->src_ipstr, ipstr, bundle_join_req->pid_at_cli);
        if (bundle_id < 0) {
            rn_err("no enough bundle resouce.\n");
            rn_assert(0);
        }
    }
    ret = rn_tunnel_bundle_insert_transport(tunnel, bundle_id, transport->transport_id);
    if (ret < 0) {
        rn_err("too many transport in bundle %d.\n", bundle_id);
        rn_assert(0);
    } else {
        rn_log("bundle %d: ipstr_at_cli %s, ipstr_at_srv %s, pid %d, add new transport %d, ret %d\n",
            bundle_id, bundle_join_req->src_ipstr, ipstr, bundle_join_req->pid_at_cli, transport->transport_id, ret);
    }

    return RN_RETVALUE_OK;
}

int tunnel_proc_send_session_new(rn_tunnel_t *tunnel, rn_transport_t *transport, uint32_t port, rn_local_agent_conn_id src_agent_conn_id, uint32_t *create_challenge)
{
    rn_pkb_t *pkb;
    rn_protocol_pkt_session_new_req_t *session_new_req;

    pkb = rn_pkb_pool_get_pkb(tunnel->pkb_pool);
    rn_assert(pkb != NULL);

    session_new_req = RN_PKB_HEAD(pkb);

    memset(session_new_req, 0, sizeof(rn_protocol_pkt_session_new_req_t));

    session_new_req->port = port;
    session_new_req->src_agent_conn_id = src_agent_conn_id;
    pkb->cur_len = sizeof(rn_protocol_pkt_session_new_req_t);

    rn_dbg(RUN_DBGFLAG_PROTOCOL_DUMP, "transport_id %d, port %d, src_agent_conn_id %d\n",
        transport->transport_id, session_new_req->port, session_new_req->src_agent_conn_id);

    return rn_transport_send(tunnel, transport, pkb, RN_TRANSPORT_FRAME_TYPE_SESSION_NEW, create_challenge);
}

static int tunnel_proc_recv_session_new(rn_tunnel_t *tunnel, rn_transport_t *transport, rn_transport_frame_head_t *frame_head)
{
    rn_protocol_pkt_session_new_req_t *session_new_req = (rn_protocol_pkt_session_new_req_t *)(frame_head + 1);
    rn_bundle_id bundle_id = transport->belongs_to_bundle_id;
    rn_socket_public_t *connected_socket;
    rn_local_agent_conn_t *agent_conn;
    int ret;

    rn_dbg(RUN_DBGFLAG_PROTOCOL_DUMP, "transport_id %d, port %d, src_agent_conn_id %d\n",
        transport->transport_id, session_new_req->port, session_new_req->src_agent_conn_id);

    if (transport->transport_state != RN_TRANSPORT_STATE_BUNDLE_ALREADY_JOIN) {
        /* todo */
        rn_assert(0);
    }

    /* check peer agent_conn is already in bundle */
    if (rn_tunnel_bundle_remote_agent_conn_inbundle(tunnel, bundle_id, session_new_req->src_agent_conn_id, NULL)) {
        ret = RN_RETVALUE_SESSION_CREATE_FAILD;
        rn_err("remote agent conn id %d already in bundle %d, return %d.\n",
            session_new_req->src_agent_conn_id, bundle_id, ret);

        ret = tunnel_proc_send_session_new_ack(tunnel, transport, ret, RN_AGENT_CONN_ID_INVALID, session_new_req->src_agent_conn_id, frame_head->challenge);
        rn_assert(ret == RN_RETVALUE_OK);

        return RN_RETVALUE_OK;
    }

    /* connect to local port */
    ret = rn_socket_mngr_connect(&(tunnel->local_agent->socket_mngr), "127.0.0.1", session_new_req->port, RN_CONFIG_SOCKET_BUF_SIZE, &connected_socket);
    if (ret != RN_RETVALUE_OK) {
        ret = RN_RETVALUE_SESSION_CREATE_FAILD;
        rn_err("connect to %s %d faild, return %d.\n",
            "127.0.0.1", session_new_req->port, ret);

        ret = tunnel_proc_send_session_new_ack(tunnel, transport, ret, RN_AGENT_CONN_ID_INVALID, session_new_req->src_agent_conn_id, frame_head->challenge);
        rn_assert(ret == RN_RETVALUE_OK);

        return RN_RETVALUE_OK;
    }

    /* connect success */
    agent_conn = RN_GETCONTAINER(connected_socket, rn_local_agent_conn_t, socket);

    /* attach agent_conn to bundle which has this transport */
    rn_tunnel_bundle_attach_agent_conn(tunnel, bundle_id, agent_conn);
    /* set peer agent_conn id */
    rn_assert(agent_conn->peer_agent_conn_id == RN_AGENT_CONN_ID_INVALID);
    agent_conn->peer_agent_conn_id = session_new_req->src_agent_conn_id;
    /* set ctrl_transport_id, use recv transport as 'control msg transport' */
    agent_conn->ctrl_transport_id = transport->transport_id;
    /* change state */
    rn_assert(agent_conn->agent_conn_state == RN_AGENT_CONN_STATE_CONNECTED);
    agent_conn->agent_conn_state = RN_AGENT_CONN_STATE_SESSION_OK;

    rn_log("session create (passive), bundle id %d, remote agent_conn id %d --> local agent_conn id %d\n",
        bundle_id, agent_conn->peer_agent_conn_id, agent_conn->local_agent_conn_id);

    /* send ack */
    ret = RN_RETVALUE_OK;
    ret = tunnel_proc_send_session_new_ack(tunnel, transport, ret, agent_conn->local_agent_conn_id, agent_conn->peer_agent_conn_id, frame_head->challenge);
    rn_assert(ret == RN_RETVALUE_OK);

    return RN_RETVALUE_OK;
}

int tunnel_proc_send_session_new_ack(rn_tunnel_t *tunnel, rn_transport_t *transport, int ret, uint32_t src_agent_conn_id, uint32_t dst_agent_conn_id, uint32_t source_challenge)
{
    rn_pkb_t *pkb;
    rn_protocol_pkt_session_new_resp_t *session_new_resp;

    pkb = rn_pkb_pool_get_pkb(tunnel->pkb_pool);
    rn_assert(pkb != NULL);

    session_new_resp = RN_PKB_HEAD(pkb);

    memset(session_new_resp, 0, sizeof(rn_protocol_pkt_session_new_resp_t));

    session_new_resp->ret = ret;
    session_new_resp->src_agent_conn_id = src_agent_conn_id;
    session_new_resp->dst_agent_conn_id = dst_agent_conn_id;
    session_new_resp->source_challenge = source_challenge;

    pkb->cur_len = sizeof(rn_protocol_pkt_session_new_resp_t);

    rn_dbg(RUN_DBGFLAG_PROTOCOL_DUMP, "transport_id %d, src_agent_conn_id %d, dst_agent_conn_id %d, source_challenge 0x%x\n",
        transport->transport_id, session_new_resp->src_agent_conn_id, session_new_resp->dst_agent_conn_id, session_new_resp->source_challenge);

    return rn_transport_send(tunnel, transport, pkb, RN_TRANSPORT_FRAME_TYPE_SESSION_NEW_ACK, NULL);
}

static int tunnel_proc_recv_session_new_ack(rn_tunnel_t *tunnel, rn_transport_t *transport, rn_transport_frame_head_t *frame_head)
{
    rn_protocol_pkt_session_new_resp_t *session_new_resp = (rn_protocol_pkt_session_new_resp_t *)(frame_head + 1);
    rn_bundle_id bundle_id = transport->belongs_to_bundle_id;
    rn_local_agent_conn_t *agent_conn;

    rn_dbg(RUN_DBGFLAG_PROTOCOL_DUMP, "transport_id %d, ret %d, src_agent_conn_id %d, dst_agent_conn_id %d, source_challenge 0x%x\n",
        transport->transport_id, session_new_resp->ret, session_new_resp->src_agent_conn_id, session_new_resp->dst_agent_conn_id, session_new_resp->source_challenge);

    if (transport->transport_state != RN_TRANSPORT_STATE_BUNDLE_ALREADY_JOIN) {
        /* todo */
        rn_assert(0);
    }

    /* get local agent_conn () session_new_resp->dst_agent_conn_id */
    agent_conn = rn_local_agent_get_conn(tunnel->local_agent, session_new_resp->dst_agent_conn_id);
    rn_assert(agent_conn->bundle_id == bundle_id);

    /* 0. check challenge */
    rn_assert(agent_conn->source_challenge == session_new_resp->source_challenge);

    /* 1. local agent_conn should already in bundle */
    rn_assert(rn_tunnel_bundle_local_agent_conn_inbundle(tunnel, bundle_id, agent_conn) == 1);

    /*  */
    if (session_new_resp->ret != RN_RETVALUE_OK) {
        rn_err("session create return %d, close local agent conn\n", session_new_resp->ret);
        vacc_host_destroy(&(agent_conn->socket.vacc_host));
        return RN_RETVALUE_OK;
    }

    /* set peer agent_conn id */
    rn_assert(agent_conn->peer_agent_conn_id == RN_AGENT_CONN_ID_INVALID);
    agent_conn->peer_agent_conn_id = session_new_resp->src_agent_conn_id;

    /* change agent conn state */
    rn_assert(agent_conn->agent_conn_state == RN_AGENT_CONN_STATE_SESSION_CREATING);
    agent_conn->agent_conn_state = RN_AGENT_CONN_STATE_SESSION_OK;

    rn_log("session create (active), bundle id %d, remote agent_conn id %d --> local agent_conn id %d\n",
        bundle_id, agent_conn->peer_agent_conn_id, agent_conn->local_agent_conn_id);

    return RN_RETVALUE_OK;
}

int tunnel_proc_send_session_del(rn_tunnel_t *tunnel, rn_transport_t *transport, rn_local_agent_conn_id src_agent_conn_id, rn_local_agent_conn_id dst_agent_conn_id)
{
    rn_pkb_t *pkb;
    rn_protocol_pkt_session_del_req_t *session_del_req;

    pkb = rn_pkb_pool_get_pkb(tunnel->pkb_pool);
    rn_assert(pkb != NULL);

    session_del_req = RN_PKB_HEAD(pkb);

    memset(session_del_req, 0, sizeof(rn_protocol_pkt_session_del_req_t));

    session_del_req->src_agent_conn_id = src_agent_conn_id;
    session_del_req->dst_agent_conn_id = dst_agent_conn_id;

    pkb->cur_len = sizeof(rn_protocol_pkt_session_del_req_t);

    rn_dbg(RUN_DBGFLAG_PROTOCOL_DUMP, "transport_id %d, src_agent_conn_id %d, dst_agent_conn_id %d\n",
        transport->transport_id, session_del_req->src_agent_conn_id, session_del_req->dst_agent_conn_id);

    return rn_transport_send(tunnel, transport, pkb, RN_TRANSPORT_FRAME_TYPE_SESSION_DEL, NULL);
}

static int tunnel_proc_recv_session_del(rn_tunnel_t *tunnel, rn_transport_t *transport, rn_transport_frame_head_t *frame_head)
{
    rn_protocol_pkt_session_del_req_t *session_del_req = (rn_protocol_pkt_session_del_req_t *)(frame_head + 1);
    rn_bundle_id bundle_id = transport->belongs_to_bundle_id;
    rn_local_agent_conn_id local_agent_conn_id;
    rn_local_agent_conn_t *local_agent_conn;

    rn_dbg(RUN_DBGFLAG_PROTOCOL_DUMP, "transport_id %d, src_agent_conn_id %d, dst_agent_conn_id %d\n",
        transport->transport_id, session_del_req->src_agent_conn_id, session_del_req->dst_agent_conn_id);

    if (transport->transport_state != RN_TRANSPORT_STATE_BUNDLE_ALREADY_JOIN) {
        /* todo */
        rn_assert(0);
    }

    if (rn_tunnel_bundle_remote_agent_conn_inbundle(tunnel, bundle_id, session_del_req->src_agent_conn_id, &local_agent_conn_id) == 0) {
        /* can't find remote agent_conn */
        rn_err("transport_id %d, bundle_id %d, session_del_req->src_agent_conn_id %d, can't find in bundle.\n",
            transport->transport_id, bundle_id, session_del_req->src_agent_conn_id);
        return RN_RETVALUE_OK;
    }

    if (local_agent_conn_id != (rn_local_agent_conn_id)(session_del_req->dst_agent_conn_id))
    {
        rn_err("transport_id %d, bundle_id %d, session_del_req->src_agent_conn_id %d, session_del_req->dst_agent_conn_id %d != local_agent_conn_id %d, bundle %d\n",
            transport->transport_id, bundle_id, session_del_req->src_agent_conn_id, session_del_req->dst_agent_conn_id, local_agent_conn_id);
        return RN_RETVALUE_OK;
    }

    local_agent_conn = rn_local_agent_get_conn(tunnel->local_agent, local_agent_conn_id);

    if (local_agent_conn->socket.vacc_host.insttype != VACC_HOST_INSTTYPE_CLIENT_INST) {
        rn_err("transport_id %d, bundle_id %d, session_del_req->src_agent_conn_id %d, session_del_req->dst_agent_conn_id %d, insttype %d, can't del\n",
            transport->transport_id, bundle_id, session_del_req->src_agent_conn_id, session_del_req->dst_agent_conn_id, local_agent_conn->socket.vacc_host.insttype);
        return RN_RETVALUE_OK;
    }

    /* set passive close */
    local_agent_conn->passive_close = 1;

    /* close local agent conn */
    vacc_host_destroy(&(local_agent_conn->socket.vacc_host));

    return RN_RETVALUE_OK;
}

int tunnel_proc_send_session_data(rn_tunnel_t *tunnel, rn_transport_t *transport, rn_pkb_t *pkb, rn_local_agent_conn_id src_agent_conn_id, rn_local_agent_conn_id dst_agent_conn_id, uint64_t idx)
{
    rn_protocol_pkt_session_data_t *session_data;

    /* append session data head */
    rn_assert(pkb->cur_off >= sizeof(rn_protocol_pkt_session_data_t));
    pkb->cur_off -= sizeof(rn_protocol_pkt_session_data_t);
    pkb->cur_len += sizeof(rn_protocol_pkt_session_data_t);
    session_data = RN_PKB_HEAD(pkb);
    session_data->src_agent_conn_id = src_agent_conn_id;
    session_data->dst_agent_conn_id = dst_agent_conn_id;
    session_data->idx = idx;

    rn_dbg(RUN_DBGFLAG_PROTOCOL_DUMP, "transport_id %d, src_agent_conn_id %d, dst_agent_conn_id %d, idx 0x%ld: 0x%08x 0x%08x 0x%08x 0x%08x\n",
        transport->transport_id, session_data->src_agent_conn_id, session_data->dst_agent_conn_id, session_data->idx,
        ((uint32_t *)(session_data + 1))[0], ((uint32_t *)(session_data + 1))[1], ((uint32_t *)(session_data + 1))[2], ((uint32_t *)(session_data + 1))[3]);

    return rn_transport_send(tunnel, transport, pkb, RN_TRANSPORT_FRAME_TYPE_DATA, NULL);
}

static int tunnel_proc_recv_session_data(rn_tunnel_t *tunnel, rn_transport_t *transport, rn_transport_frame_head_t *frame_head, rn_pkb_t *pkb)
{
    rn_protocol_pkt_session_data_t *session_data = (rn_protocol_pkt_session_data_t *)(frame_head + 1);
    rn_local_agent_conn_id local_agent_conn_id;
    rn_local_agent_conn_t *local_agent_conn;
    int ret;

    pkb->cur_len = frame_head->real_len;

    rn_dbg(RUN_DBGFLAG_PROTOCOL_DUMP, "transport_id %d, align_len 0x%x, real_len 0x%x, src_agent_conn_id %d, dst_agent_conn_id %d, idx 0x%ld: 0x%08x 0x%08x 0x%08x 0x%08x\n",
        transport->transport_id, frame_head->align_len, frame_head->real_len, session_data->src_agent_conn_id, session_data->dst_agent_conn_id, session_data->idx,
        ((uint32_t *)(session_data + 1))[0], ((uint32_t *)(session_data + 1))[1], ((uint32_t *)(session_data + 1))[2], ((uint32_t *)(session_data + 1))[3]);

    /* change len, remove public head and session data head */
    pkb->cur_off += (RN_TRANSPORT_FRAME_HEAD_LEN + sizeof(rn_protocol_pkt_session_data_t));
    pkb->cur_len -= (RN_TRANSPORT_FRAME_HEAD_LEN + sizeof(rn_protocol_pkt_session_data_t));

    local_agent_conn_id = (rn_local_agent_conn_id)(session_data->dst_agent_conn_id);
    local_agent_conn = rn_local_agent_get_conn(tunnel->local_agent, local_agent_conn_id);

    if (local_agent_conn->agent_conn_state != RN_AGENT_CONN_STATE_SESSION_OK) {
        /* need drop pkt */
        transport->stat.drop_agent_conn_not_ready++;

        rn_err("transport id %d, agent_conn id %d, agent_conn_state %d, drop session data.\n",
            transport->transport_id, local_agent_conn_id, local_agent_conn->agent_conn_state);
        return RN_RETVALUE_ERR;
    }
    /* some thing wrong */
    if (local_agent_conn->peer_agent_conn_id != (rn_local_agent_conn_id)session_data->src_agent_conn_id) {
        /* need drop pkt */
        transport->stat.drop_agent_conn_not_ready++;

        rn_err("transport id %d, agent_conn id %d, local_agent_conn->peer_agent_conn_id %d != session_data->src_agent_conn_id %d, drop session data.\n",
            transport->transport_id, local_agent_conn_id, local_agent_conn->peer_agent_conn_id, session_data->src_agent_conn_id);
        return RN_RETVALUE_ERR;
    }

    ret = rn_reorder_insert(local_agent_conn->session_pkt_reorder, session_data->idx, pkb);
    if (ret == RN_RETVALUE_REORDER_EXCEED_WIN) {
        rn_err("transport id %d, agent_conn id %d, exceed window idx 0x%lx, next idx 0x%lx, window size 0x%x, drop session data.\n",
            transport->transport_id, local_agent_conn_id, session_data->idx, local_agent_conn->session_pkt_reorder->next_idx, local_agent_conn->session_pkt_reorder->window_size);
        return RN_RETVALUE_ERR;

    } else if (ret == RN_RETVALUE_REORDER_DUP) {
        rn_err("transport id %d, agent_conn id %d, dup session data idx 0x%lx, drop session data.\n",
            transport->transport_id, local_agent_conn_id, session_data->idx);
        return RN_RETVALUE_ERR;
    }

    rn_agent_conn_session_order_drain(tunnel->local_agent, local_agent_conn);

    return RN_RETVALUE_OK;
}

static void rn_transport_invalid_frame(rn_transport_t *transport)
{
    rn_tunnel_t *tunnel = transport->tunnel;

    /* invalid frame, just disconnect */
    rn_err(".............................invalid frame...................................\n");
    tunnel->stat.invalid_frame_cnt++;
    vacc_host_destroy(&(transport->socket.vacc_host));
}

static void rn_transport_reset(rn_tunnel_t *tunnel, rn_transport_t *transport)
{
    rn_pkb_t *pkb;

    rn_tunnel_transport_valid(transport);

    /* remove transport from bundle */
    if (transport->transport_state == RN_TRANSPORT_STATE_BUNDLE_ALREADY_JOIN) {
        rn_assert(transport->belongs_to_bundle_id != RN_BUNDLE_ID_INVALID);
        rn_tunnel_bundle_remove_transport(tunnel, transport->belongs_to_bundle_id, transport->transport_id);
    }

    /* drain send fifo */
    while (!RN_GPFIFO_ISEMPTY(transport->send_fifo)) {
        pkb = rn_gpfifo_dequeue_p(transport->send_fifo);
        rn_assert(pkb != NULL);
        rn_assert(rn_pkb_pool_put_pkb(tunnel->pkb_pool, pkb) == RN_RETVALUE_OK);
    }

    /* need to free pkb */
    if (transport->cur_proc_frame) {
        rn_assert(rn_pkb_pool_put_pkb(tunnel->pkb_pool, transport->cur_proc_frame) == RN_RETVALUE_OK);
    }

    memset(RN_V2P(RN_P2V(transport) + offsetof(rn_transport_t, transport_state)), 0, sizeof(rn_transport_t) - offsetof(rn_transport_t, transport_state));

    transport->transport_state = RN_TRANSPORT_STATE_UNINIT;

    /*  */
    transport->belongs_to_bundle_id = RN_BUNDLE_ID_INVALID;

    /* reset key */
    rn_transport_tx_enable_aes_128(transport, tunnel->default_key);
    rn_transport_rx_enable_aes_128(transport, tunnel->default_key);

    /* reset bucket */
    single_token_bucket_init(&(transport->send_stb), 0, RN_CONFIG_TRANSPORT_BKT_MAX_BURST);
    transport->send_bps = tunnel->default_transport_send_bps;

    rn_dbg(RUN_DBGFLAG_TRANSPORT_DBG, "transport_id %d after reset: transport->send_fifo tail %d, head %d\n", transport->transport_id, transport->send_fifo->tail, transport->send_fifo->head);
}

/*
 *
 */
static void rn_transport_proc_1_frame(rn_transport_t *transport)
{
    rn_transport_frame_head_t *frame_head = transport->frame_head;
    int ret;

    rn_assert(frame_head != NULL);

    switch (frame_head->type) {
    case RN_TRANSPORT_FRAME_TYPE_DATA:
        if (transport->transport_state != RN_TRANSPORT_STATE_BUNDLE_ALREADY_JOIN) {
            /* this transport it not in any bundle, just discard this pkt
              don't do anything, it will be dorped after return to rn_transport_epoll_inst_cb() */
            transport->stat.drop_transport_not_in_bundle++;

            rn_err("transport id %d, drop session data, not in bundle.\n", transport->transport_id);
        } else {
            ret = tunnel_proc_recv_session_data(transport->tunnel, transport, frame_head, transport->cur_proc_frame);
            if (ret == RN_RETVALUE_OK) {
                /* transport->cur_proc_frame should clean, the frame is NOT belongs to this transport anymore */
                transport->cur_proc_frame = NULL;
            } else {

            }
        }

        break;

    case RN_TRANSPORT_FRAME_TYPE_BUNDLE_JOIN:
        /**/
        tunnel_proc_recv_bundle_join(transport->tunnel, transport, frame_head);
        break;
    case RN_TRANSPORT_FRAME_TYPE_SESSION_NEW:
        tunnel_proc_recv_session_new(transport->tunnel, transport, frame_head);
        break;
    case RN_TRANSPORT_FRAME_TYPE_SESSION_NEW_ACK:
        tunnel_proc_recv_session_new_ack(transport->tunnel, transport, frame_head);
        break;
    case RN_TRANSPORT_FRAME_TYPE_SESSION_DEL:
        tunnel_proc_recv_session_del(transport->tunnel, transport, frame_head);
        break;
    case RN_TRANSPORT_FRAME_TYPE_UPDATE_KEY:
        /* update transport rx key */
        rn_transport_rx_enable_aes_128(transport, (uint8_t *)(frame_head + 1));
        break;
    default:
        rn_transport_invalid_frame(transport);
        break;
    }

}

static void rn_transport_listener_epoll_inst_cb(rn_epoll_inst_t *epoll_inst)
{
    rn_transport_t *transport = RN_GETCONTAINER(epoll_inst, rn_transport_t, epoll_inst);

    vacc_host_read(&(transport->socket.vacc_host), NULL, 0);
}

static void rn_transport_epoll_inst_cb(rn_epoll_inst_t *epoll_inst)
{
    rn_transport_t *transport = RN_GETCONTAINER(epoll_inst, rn_transport_t, epoll_inst);
    rn_tunnel_t *tunnel = transport->tunnel;
    uint32_t i;
    int ret, left;

    rn_tunnel_transport_valid(transport);

    /* do recv */

    /* 1. get pkb */
    if (transport->cur_proc_frame == NULL) {
        transport->cur_proc_frame = rn_pkb_pool_get_pkb(tunnel->pkb_pool);
        /* todo */
        rn_assert(transport->cur_proc_frame != NULL);
    }

    /* 2. recv head*/
    if (transport->cur_proc_frame->cur_len < RN_TRANSPORT_FRAME_HEAD_LEN) {
        left = RN_TRANSPORT_FRAME_HEAD_LEN - transport->cur_proc_frame->cur_len;
        /* do recv */
        ret = rn_pkb_recv(transport->cur_proc_frame, left, &(transport->socket.vacc_host));
        if (ret < 0) {
            goto __pkt_recv_err;
        }

        //
        if (transport->cur_proc_frame->cur_len < RN_TRANSPORT_FRAME_HEAD_LEN) {
            transport->stat.head_not_complete++;
            return;
        }

        rn_assert(transport->frame_head == NULL);

        /* do aes dechiper for frame head */
        AES_ecb_encrypt(RN_PKB_HEAD(transport->cur_proc_frame), RN_PKB_HEAD(transport->cur_proc_frame),
            &(transport->aes_128_dec_key), AES_DECRYPT);

        transport->frame_head = RN_PKB_HEAD(transport->cur_proc_frame);

        /* check frame */
        if (transport->frame_head->magic != RN_TRANSPORT_PROTOCOL_MAGIC) {
            rn_transport_invalid_frame(transport);
            return;
        }
        if ((transport->frame_head->real_len > transport->frame_head->align_len)||
            (transport->frame_head->align_len - transport->frame_head->real_len) >= RN_TRANSPORT_PROTOCOL_PKTLEN_ALIGN) {
            rn_transport_invalid_frame(transport);
            return;
        }
        if ((transport->frame_head->align_len % RN_TRANSPORT_PROTOCOL_PKTLEN_ALIGN) != 0) {
            rn_transport_invalid_frame(transport);
            return;
        }
    }
    rn_assert(transport->frame_head != NULL);

    /* 3. recv body */
    if (transport->cur_proc_frame->cur_len < transport->frame_head->align_len) {
        left = transport->frame_head->align_len - transport->cur_proc_frame->cur_len;
        /* do recv */
        ret = rn_pkb_recv(transport->cur_proc_frame, left, &(transport->socket.vacc_host));
        if (ret < 0) {
            goto __pkt_recv_err;
        }
    }

    if (transport->cur_proc_frame->cur_len < transport->frame_head->align_len) {
        transport->stat.body_not_complete++;
        return;
    }

    rn_assert(transport->cur_proc_frame->cur_len == transport->frame_head->align_len);

    /* do aes dechiper for frame body */
    for (i = 0; i < ((transport->cur_proc_frame->cur_len - RN_TRANSPORT_FRAME_HEAD_LEN) / RN_TRANSPORT_PROTOCOL_PKTLEN_ALIGN); i++) {
        AES_ecb_encrypt(
            RN_PKB_HEAD(transport->cur_proc_frame) + RN_TRANSPORT_FRAME_HEAD_LEN + i * RN_TRANSPORT_PROTOCOL_PKTLEN_ALIGN,
            RN_PKB_HEAD(transport->cur_proc_frame) + RN_TRANSPORT_FRAME_HEAD_LEN + i * RN_TRANSPORT_PROTOCOL_PKTLEN_ALIGN,
            &(transport->aes_128_dec_key), AES_DECRYPT);
    }

    rn_transport_proc_1_frame(transport);

    /* one frame recv proc finish, do some reset */
    if (transport->cur_proc_frame) {
        rn_assert(rn_pkb_pool_put_pkb(tunnel->pkb_pool, transport->cur_proc_frame) == RN_RETVALUE_OK);
        transport->cur_proc_frame = NULL;
    }
    transport->frame_head = NULL;

    return;

__pkt_recv_err:
    /* todo: */
    if (ret == VACC_HOST_RET_PEERCLOSE) {
        /* peer close */
    } else {
        /* maybe some err, just return */
        transport->stat.vacc_recv_err++;
    }

    return;
}

/*
 * try to drain transport send fifo
 */
static void rn_transport_send_fifo_drain(rn_tunnel_t *tunnel, rn_transport_t *transport)
{
    int send_len_permit, ret;
    rn_pkb_t *pkb;

    if (!rn_transport_can_send(transport)) {
        return;
    }

    /* try to send pkt */
    while (1) {
        pkb = rn_gpfifo_peek_p(transport->send_fifo);
        if (pkb == NULL) {
            break;
        }
        /* calc credit */
        send_len_permit = single_token_bucket_consume(&(transport->send_stb), pkb->cur_len);
        if (send_len_permit) {
            /* do send */
            ret = rn_pkb_send(pkb, send_len_permit, &(transport->socket.vacc_host));
            rn_assert(ret != RN_RETVALUE_NOENOUGHSPACE);
            if (ret >= 0) {
                transport->stat.send_bytes += ret;
                if (pkb->cur_len == 0) {
                    /* all data in this pkt already send */

                    /* dequeue from send buf */
                    rn_gpfifo_dequeue_p(transport->send_fifo);

                    /* free this pkt */
                    rn_assert(rn_pkb_pool_put_pkb(tunnel->pkb_pool, pkb) == RN_RETVALUE_OK);

                    transport->stat.send_pkt++;
                } else {
                    /* data not send completed, maybe:
                  *  1. no enough credit
                  *  2. socket buffer in kernel is full
                  *  just wait for next loop
                  */
                    transport->stat.send_pkt_not_complete++;
                    break;
                }
            } else {
                if (ret == VACC_HOST_RET_PEERCLOSE) {
                    /* peer close */
                } else {
                    /* maybe some err, just return */
                    transport->stat.vacc_send_err++;
                }
                break;
            }
        } else {
            /* no enough credit */
            transport->stat.send_no_enough_credit++;
            break;
        }
    }
}

/*
 * transport send,
 * 1. pkt len align
 * 2. append frame header
 * 3. do cipher
 * 4. send fifo enqueue
 */
int rn_transport_send(rn_tunnel_t *tunnel, rn_transport_t *transport, rn_pkb_t *pkb, rn_transport_frame_type_e type, uint32_t *challenge)
{
    /**/
    uint32_t i, real_len = pkb->cur_len;
    rn_transport_frame_head_t *header;
    uint8_t key_buf[RN_AES_KEY_LEN];

    if (!rn_transport_can_send(transport)) {
        rn_warn("transport_id %d, drop packet type %s, transport->transport_state %d\n",
            transport->transport_id, rn_transport_frame_type_str(type), transport->transport_state);
        rn_assert(rn_pkb_pool_put_pkb(tunnel->pkb_pool, pkb) == RN_RETVALUE_OK);
        return RN_RETVALUE_OK;
    }

    rn_transport_send_fifo_drain(tunnel, transport);

    if (RN_GPFIFO_ISFULL(transport->send_fifo)) {
        return RN_RETVALUE_NOENOUGHSPACE;
    }

    rn_assert(pkb->cur_off >= RN_TRANSPORT_FRAME_HEAD_LEN);

    if (type == RN_TRANSPORT_FRAME_TYPE_UPDATE_KEY) {
        rn_assert(pkb->cur_len == RN_AES_KEY_LEN);
        memcpy(key_buf, RN_PKB_HEAD(pkb), RN_AES_KEY_LEN);
    }

    /* align to RN_TRANSPORT_PROTOCOL_PKTLEN_ALIGN */
    pkb->cur_len = (real_len + RN_TRANSPORT_PROTOCOL_PKTLEN_ALIGN - 1) & ~(RN_TRANSPORT_PROTOCOL_PKTLEN_ALIGN - 1);
    /* add transform frame header */
    pkb->cur_len += RN_TRANSPORT_FRAME_HEAD_LEN;
    pkb->cur_off -= RN_TRANSPORT_FRAME_HEAD_LEN;
    rn_assert(pkb->cur_len <= pkb->bufsize);
    real_len += RN_TRANSPORT_FRAME_HEAD_LEN;

    header = RN_PKB_HEAD(pkb);
    header->magic = RN_TRANSPORT_PROTOCOL_MAGIC;
    header->challenge = rand();
    header->align_len = pkb->cur_len;
    header->real_len = real_len;
    header->type = type;

    if (challenge) {
        *challenge = header->challenge;
    }

    /* do cipher */
    for (i = 0; i < (pkb->cur_len / RN_TRANSPORT_PROTOCOL_PKTLEN_ALIGN); i++) {
        AES_ecb_encrypt(
            RN_PKB_HEAD(pkb) + i * RN_TRANSPORT_PROTOCOL_PKTLEN_ALIGN,
            RN_PKB_HEAD(pkb) + i * RN_TRANSPORT_PROTOCOL_PKTLEN_ALIGN,
            &(transport->aes_128_enc_key), AES_ENCRYPT);
    }

    /* send fifo enqueue */
    rn_assert(rn_gpfifo_enqueue_p(transport->send_fifo, pkb) == RN_RETVALUE_OK);

    rn_dbg(RUN_DBGFLAG_TRANSPORT_DBG, "transport_id %d, type %s align_len 0x%x, real_len 0x%x\n",
        transport->transport_id, rn_transport_frame_type_str(type), pkb->cur_len, real_len);

    rn_transport_send_fifo_drain(tunnel, transport);

    if (type == RN_TRANSPORT_FRAME_TYPE_UPDATE_KEY) {
        /* update transport tx key */
        rn_transport_tx_enable_aes_128(transport, key_buf);
    }

    return RN_RETVALUE_OK;
}

static int rn_transport_polling(rn_tunnel_t *tunnel, rn_transport_t *transport, int cycle_ms)
{
    int n_token;

    /* fill new token */
    n_token = transport->send_bps / (1000 / cycle_ms);
    single_token_bucket_insert(&(transport->send_stb), n_token);

    /* try to drain send fifo */
    rn_transport_send_fifo_drain(tunnel, transport);

    return RN_RETVALUE_OK;
}

static int rn_transport_init(rn_socket_mngr_t *mngr, rn_socket_public_t *socket, void *cb_param)
{
    rn_tunnel_t *tunnel = (rn_tunnel_t *)cb_param;
    rn_transport_t *transport = RN_GETCONTAINER(socket, rn_transport_t, socket);
    int ret;

    rn_assert(transport->transport_state == RN_TRANSPORT_STATE_UNINIT);

    switch (socket->vacc_host.insttype) {
    case VACC_HOST_INSTTYPE_SERVER_LISTENER:
        /* add into epoll thread main loop */
        transport->epoll_inst.epoll_inst_cb = rn_transport_listener_epoll_inst_cb;
        transport->epoll_inst.fd = socket->vacc_host.sock_fd;
        ret = rn_epoll_thread_reg_inst(tunnel->epoll_thread, &(transport->epoll_inst));
        if (ret != RN_RETVALUE_OK) {
            /* todo: */
            rn_assert(0);
        }

        /* change to listening */
        transport->transport_state = RN_TRANSPORT_STATE_LISTENING;

        break;
    case VACC_HOST_INSTTYPE_SERVER_INST:
    case VACC_HOST_INSTTYPE_CLIENT_INST:
        /* add into epoll thread main loop */
        transport->epoll_inst.epoll_inst_cb = rn_transport_epoll_inst_cb;
        transport->epoll_inst.fd = socket->vacc_host.sock_fd;
        ret = rn_epoll_thread_reg_inst(tunnel->epoll_thread, &(transport->epoll_inst));
        if (ret != RN_RETVALUE_OK) {
            /* todo: */
            rn_assert(0);
        }

        rn_transport_reset(tunnel, transport);

        /* change to connected */
        transport->transport_state = RN_TRANSPORT_STATE_CONNECTED;

        break;
    default:
        rn_assert(0);
    }

    return RN_RETVALUE_OK;
}

static int rn_transport_uninit(rn_socket_mngr_t *mngr, rn_socket_public_t *socket, void *cb_param)
{
    rn_tunnel_t *tunnel = (rn_tunnel_t *)cb_param;
    rn_transport_t *transport = RN_GETCONTAINER(socket, rn_transport_t, socket);
    int ret;

    switch (socket->vacc_host.insttype) {
    case VACC_HOST_INSTTYPE_SERVER_LISTENER:
        rn_assert(transport->transport_state == RN_TRANSPORT_STATE_LISTENING);
        /* fall though */
    case VACC_HOST_INSTTYPE_SERVER_INST:
    case VACC_HOST_INSTTYPE_CLIENT_INST:
        rn_assert(transport->transport_state != RN_TRANSPORT_STATE_UNINIT);
        /* remove from epoll thread main loop */
        ret = rn_epoll_thread_reg_uninst(tunnel->epoll_thread, &(transport->epoll_inst));
        if (ret != RN_RETVALUE_OK) {
            /* todo: */
            rn_assert(0);
        }

        rn_transport_reset(tunnel, transport);

        break;
    default:
        rn_assert(0);
    }

    return RN_RETVALUE_OK;
}

int rn_tunnel_transport_polling_all(rn_tunnel_t *tunnel, int cycle_ms)
{
    rn_socket_public_t *p, *n;
    rn_socket_mngr_t *mngr = &(tunnel->socket_mngr);
    rn_transport_t *transport;

    rn_assert((mngr->n_listen + mngr->n_srv_inst + mngr->n_client_inst + RN_GPFIFO_CUR_LEN(mngr->free_fifo)) == mngr->unit_num);

    /* server inst list: */
    if (mngr->n_srv_inst) {
        RN_LISTENTRYWALK_SAVE(p, n, &(mngr->srv_inst_list), list_entry) {
            rn_assert(p->vacc_host.insttype == VACC_HOST_INSTTYPE_SERVER_INST);
            transport = RN_GETCONTAINER(p, rn_transport_t, socket);
            rn_transport_polling(tunnel, transport, cycle_ms);
        }
    }
    /* client inst list: */
    if (mngr->n_client_inst) {
        RN_LISTENTRYWALK_SAVE(p, n, &(mngr->client_inst_list), list_entry) {
            rn_assert(p->vacc_host.insttype == VACC_HOST_INSTTYPE_CLIENT_INST);
            transport = RN_GETCONTAINER(p, rn_transport_t, socket);
            rn_transport_polling(tunnel, transport, cycle_ms);
        }
    }

    return RN_RETVALUE_OK;
}

rn_transport_id rn_tunnel_bundle_transport_select(rn_tunnel_t *tunnel, rn_bundle_id bundle_id)
{
    rn_bundle_t *bundle = &(tunnel->bundle_list[bundle_id]);
    uint32_t idx;
    rn_assert(bundle->valid == 1);
    rn_assert(bundle->n_transport > 0);

    rn_assert((bundle_id >= 0) && (bundle_id < RN_CONFIG_TUNNEL_BUNDLE_MAX));

    idx = rand() % bundle->n_transport;

    return bundle->transport_list[idx];
}

/*
 * find transport in bundle
 */
int rn_tunnel_bundle_find_transport(rn_tunnel_t *tunnel, rn_bundle_id bundle_id, rn_transport_id transport_id)
{
    rn_bundle_t *bundle = &(tunnel->bundle_list[bundle_id]);
    uint32_t i;

    rn_assert((bundle_id >= 0) && (bundle_id < RN_CONFIG_TUNNEL_BUNDLE_MAX));

    for (i = 0; i < bundle->n_transport; i++) {
        if (bundle->transport_list[i] == transport_id) {
            return i;
        }
    }

    return RN_RETVALUE_NO_SUCH_TRANSPORT;
}

int rn_tunnel_bundle_insert_transport(rn_tunnel_t *tunnel, rn_bundle_id bundle_id, rn_transport_id transport_id)
{
    rn_bundle_t *bundle = &(tunnel->bundle_list[bundle_id]);
    rn_transport_t *transport = rn_tunnel_get_transport(tunnel, transport_id);

    rn_assert((bundle_id >= 0) && (bundle_id < RN_CONFIG_TUNNEL_BUNDLE_MAX));
    rn_assert((transport_id >= 0) && (transport_id < tunnel->n_transport));

    if (rn_tunnel_bundle_find_transport(tunnel, bundle_id, transport_id) >= 0) {
        rn_warn("transport id %d already in bundle %d\n", transport_id, bundle_id);
        return RN_RETVALUE_OK;
    }

    if (bundle->n_transport == RN_MAX_TRANSPORT_PER_BUNDLE) {
        return RN_RETVALUE_NOENOUGHRES;
    }

    bundle->transport_list[bundle->n_transport] = transport_id;
    bundle->n_transport++;

    //
    transport->belongs_to_bundle_id = bundle_id;;
    transport->transport_state = RN_TRANSPORT_STATE_BUNDLE_ALREADY_JOIN;

    return RN_RETVALUE_OK;
}

int rn_tunnel_bundle_remove_transport(rn_tunnel_t *tunnel, rn_bundle_id bundle_id, rn_transport_id transport_id)
{
    rn_bundle_t *bundle = &(tunnel->bundle_list[bundle_id]);
    int idx;
    uint32_t i;

    rn_assert((bundle_id >= 0) && (bundle_id < RN_CONFIG_TUNNEL_BUNDLE_MAX));
    rn_assert((transport_id >= 0) && (transport_id < tunnel->n_transport));

    idx = rn_tunnel_bundle_find_transport(tunnel, bundle_id, transport_id);

    if (idx < 0) {
        rn_warn("transport id %d not in bundle %d/n", transport_id, bundle_id);
        return RN_RETVALUE_OK;
    }

    i = idx + 1;
    for (; i < bundle->n_transport; i++) {
        bundle->transport_list[i - 1] = bundle->transport_list[i];
    }

    bundle->n_transport--;

    if (bundle->n_transport == 0) {
        /* remove this bundle */
        rn_tunnel_bundle_del(tunnel, bundle->bundle_id);
    }

    return RN_RETVALUE_OK;
}

int rn_tunnel_bundle_local_agent_conn_inbundle(rn_tunnel_t *tunnel, rn_bundle_id bundle_id, rn_local_agent_conn_t *agent_conn)
{
    rn_bundle_t *bundle = &(tunnel->bundle_list[bundle_id]);
    rn_local_agent_conn_t *p;

    rn_assert((bundle_id >= 0) && (bundle_id < RN_CONFIG_TUNNEL_BUNDLE_MAX));
    rn_assert(bundle->valid == 1);

    RN_LISTENTRYWALK(p, &(bundle->agent_conn_list_head), bundle_link) {
        if (p == agent_conn) {
            return 1;
        }
    }

    return 0;
}

/*
 * find remote_agent_conn_id in bundle
 * local_agent_conn_id: if match, return local_agent_conn_id
 */
int rn_tunnel_bundle_remote_agent_conn_inbundle(rn_tunnel_t *tunnel, rn_bundle_id bundle_id, rn_local_agent_conn_id remote_agent_conn_id, rn_local_agent_conn_id *local_agent_conn_id)
{
    rn_bundle_t *bundle = &(tunnel->bundle_list[bundle_id]);
    rn_local_agent_conn_t *p;

    rn_assert((bundle_id >= 0) && (bundle_id < RN_CONFIG_TUNNEL_BUNDLE_MAX));
    rn_assert(bundle->valid == 1);

    RN_LISTENTRYWALK(p, &(bundle->agent_conn_list_head), bundle_link) {
        if (p->peer_agent_conn_id == remote_agent_conn_id) {
            if (local_agent_conn_id) {
                *local_agent_conn_id = p->local_agent_conn_id;
            }
            return 1;
        }
    }

    return 0;
}

int rn_tunnel_bundle_attach_agent_conn(rn_tunnel_t *tunnel, rn_bundle_id bundle_id, rn_local_agent_conn_t *agent_conn)
{
    rn_bundle_t *bundle = &(tunnel->bundle_list[bundle_id]);

    rn_assert(agent_conn->bundle_id == RN_BUNDLE_ID_INVALID);
    rn_assert((bundle_id >= 0) && (bundle_id < RN_CONFIG_TUNNEL_BUNDLE_MAX));
    rn_assert(bundle->valid == 1);

#ifdef RN_CONFIG_AGENT_CONN_CHECK
    /* check agent_conn already in bundle */
    rn_assert(rn_tunnel_bundle_local_agent_conn_inbundle(tunnel, bundle_id, agent_conn) == 0);
#endif

    bundle->n_agent_conn++;
    rn_listadd_tail(&(agent_conn->bundle_link), &(bundle->agent_conn_list_head));

    agent_conn->bundle_id = bundle_id;

    return RN_RETVALUE_OK;
}

int rn_tunnel_bundle_detach_agent_conn(rn_tunnel_t *tunnel, rn_bundle_id bundle_id, rn_local_agent_conn_t *agent_conn)
{
    rn_bundle_t *bundle = &(tunnel->bundle_list[bundle_id]);

    rn_assert(agent_conn->bundle_id == bundle_id);
    rn_assert((bundle_id >= 0) && (bundle_id < RN_CONFIG_TUNNEL_BUNDLE_MAX));
    rn_assert(bundle->valid == 1);

#ifdef RN_CONFIG_AGENT_CONN_CHECK
    /* check agent_conn already in bundle */
    rn_assert(rn_tunnel_bundle_local_agent_conn_inbundle(tunnel, bundle_id, agent_conn) == 1);
#endif

    bundle->n_agent_conn--;
    rn_listdel(&(agent_conn->bundle_link));

    agent_conn->bundle_id = RN_BUNDLE_ID_INVALID;

    return RN_RETVALUE_OK;
}

rn_bundle_id rn_tunnel_bundle_find(rn_tunnel_t *tunnel, char *ipstr_at_cli, char *ipstr_at_srv, uint32_t pid_at_cli)
{
    rn_bundle_id i;
    rn_bundle_t *bundle = tunnel->bundle_list;
    for (i = 0; i < RN_CONFIG_TUNNEL_BUNDLE_MAX; i++, bundle++) {
        if (bundle->valid == 0) {
            continue;
        }

        if (strncmp(bundle->ipstr_at_cli, ipstr_at_cli, sizeof(bundle->ipstr_at_cli))) {
            continue;
        }

        if (strncmp(bundle->ipstr_at_srv, ipstr_at_srv, sizeof(bundle->ipstr_at_srv))) {
            continue;
        }

        if (bundle->pid_at_cli != pid_at_cli) {
            continue;
        }

        break;
    }

    if (i == RN_CONFIG_TUNNEL_BUNDLE_MAX) {
        return RN_RETVALUE_NO_SUCH_BUNDLE;
    }

    return i;
}


rn_bundle_id rn_tunnel_bundle_new(rn_tunnel_t *tunnel, char *ipstr_at_cli, char *ipstr_at_srv, uint32_t pid_at_cli)
{
    rn_bundle_id i;
    rn_bundle_t *bundle = tunnel->bundle_list;

    rn_assert(rn_tunnel_bundle_find(tunnel, ipstr_at_cli, ipstr_at_srv, pid_at_cli) == RN_RETVALUE_NO_SUCH_BUNDLE);

    for (i = 0; i < RN_CONFIG_TUNNEL_BUNDLE_MAX; i++, bundle++) {
        if (bundle->valid == 0) {
            break;
        }
    }
    if (i == RN_CONFIG_TUNNEL_BUNDLE_MAX) {
        return RN_RETVALUE_NOENOUGHRES;
    }
    memset(bundle, 0, sizeof(rn_bundle_t));

    if (ipstr_at_cli) {
        strncpy(bundle->ipstr_at_cli, ipstr_at_cli, sizeof(bundle->ipstr_at_cli));
    }
    if (ipstr_at_srv) {
        strncpy(bundle->ipstr_at_srv, ipstr_at_srv, sizeof(bundle->ipstr_at_srv));
    }
    bundle->pid_at_cli = pid_at_cli;

    bundle->n_agent_conn = 0;
    rn_initlisthead(&(bundle->agent_conn_list_head));

    bundle->bundle_id = i;
    bundle->valid = 1;

    tunnel->n_bundle++;

    return i;
}

void rn_tunnel_bundle_del(rn_tunnel_t *tunnel, rn_bundle_id bundle_id)
{
    rn_bundle_t *bundle = &(tunnel->bundle_list[bundle_id]);

    rn_assert((bundle_id >= 0) && (bundle_id < RN_CONFIG_TUNNEL_BUNDLE_MAX));

    if (bundle->valid) {
        rn_local_agent_conn_t *p, *n;
        int cnt = 0, n_agent_conn = bundle->n_agent_conn;

        /* agent conn all belongs to this bundle need to close */
        RN_LISTENTRYWALK_SAVE(p, n, &(bundle->agent_conn_list_head), bundle_link) {
            vacc_host_destroy(&(p->socket.vacc_host));
            cnt++;
        }
        rn_assert(n_agent_conn == cnt);

        memset(bundle, 0, sizeof(rn_bundle_t));
        tunnel->n_bundle--;
    }
}

rn_tunnel_t * rn_tunnel_create(rn_epoll_thread_t *epoll_thread, rn_pkb_pool_t *pkb_pool, uint32_t n_transport, uint8_t *default_key, uint32_t default_transport_send_bps)
{
    uint32_t transport_size = sizeof(rn_transport_t);
    uint32_t total_size = sizeof(rn_tunnel_t) + transport_size * n_transport;
    uint32_t i;
    rn_tunnel_t *tunnel;
    int ret;

    RN_BUILD_BUG_ON(offsetof(rn_transport_t, socket) != 0);
    RN_BUILD_BUG_ON(RN_TRANSPORT_STATE_UNINIT != 0);
    RN_BUILD_BUG_ON(sizeof(rn_transport_frame_head_t) != RN_TRANSPORT_FRAME_HEAD_LEN);

    rn_assert(epoll_thread != NULL);

    tunnel = malloc(total_size);
    rn_assert(tunnel != NULL);
    memset(tunnel, 0, sizeof(rn_tunnel_t));

    /* init tunnel */
    ret = rn_socket_mngr_create(&(tunnel->socket_mngr), &(tunnel->transport_pool[0].socket),
        n_transport, transport_size, rn_transport_init, rn_transport_uninit, tunnel);
    rn_assert(ret == RN_RETVALUE_OK);

    tunnel->epoll_thread = epoll_thread;
    tunnel->pkb_pool = pkb_pool;
    for (i = 0; i < RN_CONFIG_TUNNEL_BUNDLE_MAX; i++) {
        tunnel->bundle_list[i].bundle_id = i;
    }
    if (default_key) {
        memcpy(tunnel->default_key, default_key, sizeof(tunnel->default_key));
    }
    tunnel->default_transport_send_bps = default_transport_send_bps;
    tunnel->n_transport = n_transport;
    for (i = 0; i < n_transport; i++) {
        tunnel->transport_pool[i].transport_id = i;
        tunnel->transport_pool[i].tunnel = tunnel;
        tunnel->transport_pool[i].send_fifo = rn_gpfifo_create(RN_CONFIG_TRANSPORT_SEND_FIFO_DEPTH, sizeof(rn_pkb_t *));
        rn_assert(tunnel->transport_pool[i].send_fifo != NULL);
    }

    return tunnel;
}

int rn_tunnel_destroy(rn_tunnel_t *tunnel)
{
    int ret, i;

    ret = rn_socket_mngr_destroy(&(tunnel->socket_mngr));
    rn_assert(ret == RN_RETVALUE_OK);

    for (i = 0; i < tunnel->n_transport; i++) {
        rn_assert(RN_GPFIFO_ISEMPTY(tunnel->transport_pool[i].send_fifo));
        rn_gpfifo_destroy(tunnel->transport_pool[i].send_fifo);
    }

    free(tunnel);

    return RN_RETVALUE_OK;
}

