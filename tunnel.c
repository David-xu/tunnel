#include "pub.h"

int tunnel_proc_send_bundle_join(rn_tunnel_t *tunnel, rn_transport_t *transport, rn_pkb_t *pkb, char src_ipstr[], uint32_t pid_at_cli)
{
    rn_transport_frame_boundle_join_t *bundle_join_req = RN_PKB_HEAD(pkb);

    memset(bundle_join_req, 0, sizeof(rn_transport_frame_boundle_join_t));

    if (src_ipstr) {
        strncpy(bundle_join_req->src_ipstr, src_ipstr, sizeof(bundle_join_req->src_ipstr));
    }
    bundle_join_req->pid_at_cli = pid_at_cli;
    pkb->cur_len = sizeof(rn_transport_frame_boundle_join_t);

    return rn_transport_send(tunnel, transport, pkb, RN_TRANSPORT_FRAME_TYPE_BUNDLE_JOIN);
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
        transport->belongs_to_bundle_id = bundle_id;
    }

    /* join bundle */
    transport->transport_state = RN_TRANSPORT_STATE_BUNDLE_ALREADY_JOIN;

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
}

/*
 *
 */
static void rn_transport_proc_1_frame(rn_transport_t *transport)
{
    rn_transport_frame_head_t *frame_head = transport->frame_head;

    rn_assert(frame_head != NULL);

    switch (frame_head->type) {
    case RN_TRANSPORT_FRAME_TYPE_DATA:
        if (transport->transport_state != RN_TRANSPORT_STATE_BUNDLE_ALREADY_JOIN) {
            /* this transport it not in any bundle, just discard this pkt
              don't do anything, it will be dorped after return to rn_transport_epoll_inst_cb() */
            transport->stat.drop_transport_not_in_bundle++;
        } else {
            /* change len, detach head */
            transport->cur_proc_frame->cur_len = frame_head->real_len;
            transport->cur_proc_frame->cur_off += RN_TRANSPORT_FRAME_HEAD_LEN;
            transport->cur_proc_frame->cur_len -= RN_TRANSPORT_FRAME_HEAD_LEN;
            /* commit to upper protocol layer */
            /* todo */
            rn_assert(0);

            /* transport->cur_proc_frame should clean, the frame is NOT belongs to this transport anymore */
            transport->cur_proc_frame = NULL;
        }

        break;
    case RN_TRANSPORT_FRAME_TYPE_BUNDLE_JOIN:
        /**/
        tunnel_proc_recv_bundle_join(transport->tunnel, transport, frame_head);
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
        if (transport->frame_head->real_len > transport->frame_head->align_len) {
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
 * transport send,
 * 1. pkt len align
 * 2. append frame header
 * 3. do cipher
 * 4. send fifo enqueue
 */
int rn_transport_send(rn_tunnel_t *tunnel, rn_transport_t *transport, rn_pkb_t *pkb, rn_transport_frame_type_e type)
{
    /**/
    uint32_t i, real_len = pkb->cur_len;
    rn_transport_frame_head_t *header;
    uint8_t key_buf[RN_AES_KEY_LEN];

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
    header = RN_PKB_HEAD(pkb);

    header->magic = RN_TRANSPORT_PROTOCOL_MAGIC;
    header->challenge = rand();
    header->align_len = pkb->cur_len;
    header->real_len = real_len;
    header->type = type;

    /* do cipher */
    for (i = 0; i < (pkb->cur_len / RN_TRANSPORT_PROTOCOL_PKTLEN_ALIGN); i++) {
        AES_ecb_encrypt(
            RN_PKB_HEAD(pkb) + i * RN_TRANSPORT_PROTOCOL_PKTLEN_ALIGN,
            RN_PKB_HEAD(pkb) + i * RN_TRANSPORT_PROTOCOL_PKTLEN_ALIGN,
            &(transport->aes_128_enc_key), AES_ENCRYPT);
    }

    /* send fifo enqueue */
    rn_assert(rn_gpfifo_enqueue_p(transport->send_fifo, pkb) == RN_RETVALUE_OK);

    if (type == RN_TRANSPORT_FRAME_TYPE_UPDATE_KEY) {
        /* update transport tx key */
        rn_transport_tx_enable_aes_128(transport, key_buf);
    }

    return RN_RETVALUE_OK;
}

static int rn_transport_polling(rn_tunnel_t *tunnel, rn_transport_t *transport, int cycle_ms)
{
    int n_token, send_len_permit, ret;
    rn_pkb_t *pkb;

    /* fill new token */
    n_token = transport->send_bps / (1000 / cycle_ms);
    single_token_bucket_insert(&(transport->send_stb), n_token);

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
                    /* data not send completed, maybe no enough credit, just wait for next loop */
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

