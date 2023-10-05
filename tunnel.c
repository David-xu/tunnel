#include "pub.h"

static fgfw_tunnel_session_id fgfw_tunnel_session_find_by_session_key(fgfw_tunnel_t *tunnel, uint32_t session_key)
{
    fgfw_assert(session_key < FGFW_TUNNEL_SESSION_MAX);
    /* session_key is the remote session_id */
    return session_key;
}

static fgfw_tunnel_session_id fgfw_tunnel_session_open(fgfw_tunnel_t *tunnel, fgfw_tunnel_bundle_id bundle_id, uint32_t port, uint32_t new_session_key)
{
    fgfw_tunnel_session_t *new_session;

    if (tunnel->free_session_tail == tunnel->free_session_head) {
        return FGFW_RETVALUE_NOENOUGHRES;
    }

    fgfw_assert((bundle_id >= 0) && (bundle_id < FGFW_TUNNEL_BUNDLE_MAX));
    
    /* dequeue from free list */
    new_session = tunnel->free_session_list[tunnel->free_session_head % FGFW_TUNNEL_SESSION_MAX];
    fgfw_assert(new_session->session_state == FGFW_TUNNEL_SESSION_STATE_FREE);
    tunnel->free_session_head++;

    /**/
    new_session->session_state = FGFW_TUNNEL_SESSION_STATE_INIT;
    new_session->tunnel = tunnel;
    new_session->bundle_id = bundle_id;
    new_session->session_offset_send = 0;

    /* init session recv range mngr*/
    fgfw_range_res_init(&(new_session->recv_range), 0, 0);

    if (tunnel->mode == FGFW_WORKMODE_CLIENT) {
        /* get transport */
        fgfw_transport_id trans_id;
        fgfw_transport_t *transport;

        trans_id = fgfw_tunnel_bundle_get_transport_id(tunnel, bundle_id);
        transport = &(tunnel->transport_pool._transport_res[trans_id]);
        
        /* do session create */
        new_session->session_state = FGFW_TUNNEL_SESSION_STATE_CREATING;
        /* 1. send control pkt */
        tunnel_proc_send_req_session_new(tunnel, transport, port, new_session->id, &new_session->create_challenge);
        
        /* 2. wait for ack */
        while (new_session->session_state == FGFW_TUNNEL_SESSION_STATE_CREATING) {
            usleep(1000);
        }
    } else {
        /* server, session create no need to send any pkt */
        new_session->session_key = new_session_key;
        new_session->session_state = FGFW_TUNNEL_SESSION_STATE_READY;
    }

    if (new_session->session_state == FGFW_TUNNEL_SESSION_STATE_CREATE_FAILD) {
        /* enqueue into free list */
        tunnel->free_session_list[tunnel->free_session_tail % FGFW_TUNNEL_SESSION_MAX] = new_session;
        tunnel->free_session_tail++;
        fgfw_assert((tunnel->free_session_tail - tunnel->free_session_head) < FGFW_TUNNEL_SESSION_MAX);

        return new_session->create_ret;
    } else {
        /* change to ready */
        fgfw_assert(new_session->session_state == FGFW_TUNNEL_SESSION_STATE_READY);

        /**/
        fgfw_listadd_tail(&(new_session->node), &(tunnel->active_session_list));
        tunnel->n_active_session++;

        return new_session->id;
    }
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

    //
    fgfw_range_res_uninit(&(session->recv_range));

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

static int fgfw_tunnel_session_send(fgfw_tunnel_t *tunnel, fgfw_tunnel_session_id session_id, void *buf, int len)
{
    fgfw_tunnel_session_t *session = &(tunnel->_session_res[session_id]);
    fgfw_tunnel_protocol_pkt_head_t *pkt_head;
    fgfw_tunnel_protocol_pkt_session_data_t *session_data_head;
    fgfw_transport_t *transport;
    fgfw_transport_id trans_id;
    int ret, send_len = 0, left_len = len, cur_len;
    uint8_t sendbuf[FGFW_TRANSPORT_MAX_SEND_LEN];

    pkt_head = (fgfw_tunnel_protocol_pkt_head_t *)sendbuf;
    session_data_head = (fgfw_tunnel_protocol_pkt_session_data_t *)(pkt_head + 1);

    //
    if (session->session_state != FGFW_TUNNEL_SESSION_STATE_READY) {
        return FGFW_RETVALUE_SESSION_NOT_READY;
    }

    fgfw_assert((session->bundle_id >= 0) && (session->bundle_id < FGFW_TUNNEL_BUNDLE_MAX));

    while (left_len) {
        /* get transport */
        trans_id = fgfw_tunnel_bundle_get_transport_id(tunnel, session->bundle_id);
        transport = &(tunnel->transport_pool._transport_res[trans_id]);

        /**/
        cur_len = rand() % (FGFW_TRANSPORT_MAX_SEND_LEN - sizeof(fgfw_tunnel_protocol_pkt_head_t) - sizeof(fgfw_tunnel_protocol_pkt_session_data_t));
        if (cur_len > left_len) {
            cur_len = left_len;
        }

        pkt_head->tp_type = FGFW_TP_TYPE_SESSION_DATA;
        pkt_head->real_len = cur_len + sizeof(fgfw_tunnel_protocol_pkt_head_t) + sizeof(fgfw_tunnel_protocol_pkt_session_data_t);
        pkt_head->align_len = fgfw_tunnel_protocol_align(pkt_head->real_len);
        pkt_head->challenge = rand();

        session_data_head->magic = FGFW_TUNNEL_PROTOCOL_MAGIC;
        session_data_head->session_key = session->session_key;
        session_data_head->session_offset = session->session_offset_send + send_len;

        memcpy(session_data_head + 1, buf + send_len, cur_len);

        /* do send */
        ret = fgfw_transport_send(transport, buf, pkt_head->align_len);
        if (ret) {
            fgfw_err("fgfw_transport_send() return %d\n", ret);
        }

        send_len += cur_len;
        left_len -= cur_len;
    }
    
    session->session_offset_send += len;

    return FGFW_RETVALUE_OK;
}

static int fgfw_tunnel_session_recv_1copy(fgfw_tunnel_t *tunnel, fgfw_tunnel_session_id session_id, uint64_t session_offset, void *buf, uint64_t len)
{
    fgfw_tunnel_session_t *session = &(tunnel->_session_res[session_id]);
    uint64_t first, second;
    uint64_t offset = session_offset + len - session->recv_ring_head, size;
    int ret;

    fgfw_assert(session_id == session->id);

    if (offset >= FGFW_TUNNEL_SESSION_RECV_RING_BUF_SIZE) {
        fgfw_err("session id %d, session_offset 0x%lx, len 0x%lx, session->recv_ring_head 0x%lx\n",
            session_id, session_offset, len, session->recv_ring_head);
        fgfw_assert(0);
    }
    /* insert into range mngr */
    fgfw_range_res_free(&(session->recv_range), session_offset, len);
    /* copy into ring buf */
    first = FGFW_TUNNEL_SESSION_RECV_RING_BUF_SIZE - (session_offset % FGFW_TUNNEL_SESSION_RECV_RING_BUF_SIZE);
    if (first > len) {
        first = len;
    }
    second = len - first;
    memcpy(&session->recv_ring_buf[session_offset % FGFW_TUNNEL_SESSION_RECV_RING_BUF_SIZE], buf, first);
    if (second) {
        memcpy(session->recv_ring_buf, buf + first, second);
    }

    /*  */
    size = 0;
    ret = fgfw_range_res_alloc_specified(&(session->recv_range), session->recv_ring_tail, &size);
    if (ret == 0) {
        session->recv_ring_tail += size;
    } else if (ret == -3) {
        fgfw_err("session_id %d, over lap, something wrong.\n", session_id);
        fgfw_assert(0);
    } else {

    }

    return FGFW_RETVALUE_OK;
}

static int fgfw_tunnel_session_recv(fgfw_tunnel_t *tunnel, fgfw_tunnel_session_id session_id, uint64_t session_offset, void *buf_first, int first_len, void *buf_second, int second_len)
{
    uint64_t total_len = first_len + second_len;
    uint8_t tmpbuf[total_len];

    memcpy(tmpbuf, buf_first, first_len);
    memcpy(tmpbuf + first_len, buf_second, second_len);
    return fgfw_tunnel_session_recv_1copy(tunnel, session_id, session_offset, tmpbuf, total_len);
}

fgfw_tunnel_bundle_id fgfw_tunnel_bundle_find(fgfw_tunnel_t *tunnel, char *ipstr_at_cli, char *ipstr_at_srv, uint32_t pid_at_cli)
{
    fgfw_tunnel_bundle_id i;
    fgfw_tunnel_bundle_t *bundle = tunnel->bundle_list;
    for (i = 0; i < FGFW_TUNNEL_BUNDLE_MAX; i++, bundle++) {
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

    if (i == FGFW_TUNNEL_BUNDLE_MAX) {
        return FGFW_RETVALUE_NO_SUCH_BUNDLE;
    }

    return i;
}

fgfw_tunnel_bundle_id fgfw_tunnel_bundle_new(fgfw_tunnel_t *tunnel, char *ipstr_at_cli, char *ipstr_at_srv, uint32_t pid_at_cli)
{
    fgfw_tunnel_bundle_id i;
    fgfw_tunnel_bundle_t *bundle = tunnel->bundle_list;

    fgfw_assert(fgfw_tunnel_bundle_find(tunnel, ipstr_at_cli, ipstr_at_srv, pid_at_cli) == FGFW_RETVALUE_NO_SUCH_BUNDLE);

    for (i = 0; i < FGFW_TUNNEL_BUNDLE_MAX; i++, bundle++) {
        if (bundle->valid == 0) {
            break;
        }
    }
    if (i == FGFW_TUNNEL_BUNDLE_MAX) {
        return FGFW_RETVALUE_NOENOUGHRES;
    }
    memset(bundle, 0, sizeof(fgfw_tunnel_bundle_t));

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

void fgfw_tunnel_bundle_del(fgfw_tunnel_t *tunnel, fgfw_tunnel_bundle_id bundle_id)
{
    fgfw_tunnel_bundle_t *bundle = &(tunnel->bundle_list[bundle_id]);

    fgfw_assert((bundle_id >= 0) && (bundle_id < FGFW_TUNNEL_BUNDLE_MAX));

    if (bundle->valid) {
        memset(bundle, 0, sizeof(fgfw_tunnel_bundle_t));
        tunnel->n_bundle--;
    }
}

int fgfw_tunnel_bundle_find_transport(fgfw_tunnel_t *tunnel, fgfw_tunnel_bundle_id bundle_id, fgfw_transport_id transport_id)
{
    fgfw_tunnel_bundle_t *bundle = &(tunnel->bundle_list[bundle_id]);
    uint32_t i;

    fgfw_assert((bundle_id >= 0) && (bundle_id < FGFW_TUNNEL_BUNDLE_MAX));

    for (i = 0; i < bundle->n_transport; i++) {
        if (bundle->transport_list[i] == transport_id) {
            return i;
        }
    }

    return FGFW_RETVALUE_NO_SUCH_TRANSPORT;
}

int fgfw_tunnel_bundle_insert_transport(fgfw_tunnel_t *tunnel, fgfw_tunnel_bundle_id bundle_id, fgfw_transport_id transport_id)
{
    fgfw_tunnel_bundle_t *bundle = &(tunnel->bundle_list[bundle_id]);

    fgfw_assert((bundle_id >= 0) && (bundle_id < FGFW_TUNNEL_BUNDLE_MAX));
    fgfw_assert((transport_id >= 0) && (transport_id < FGFW_MAX_TRANSPORT));

    if (fgfw_tunnel_bundle_find_transport(tunnel, bundle_id, transport_id) >= 0) {
        fgfw_warn("transport id %d already in bundle %d\n", transport_id, bundle_id);
        return FGFW_RETVALUE_OK;
    }

    if (bundle->n_transport == FGFW_TUNNEL_MAX_TRANSPORT_PER_BUNDLE) {
        return FGFW_RETVALUE_NOENOUGHRES;
    }

    bundle->transport_list[bundle->n_transport] = transport_id;
    bundle->n_transport++;

    return FGFW_RETVALUE_OK;
}

int fgfw_tunnel_bundle_remove_transport(fgfw_tunnel_t *tunnel, fgfw_tunnel_bundle_id bundle_id, fgfw_transport_id transport_id)
{
    fgfw_tunnel_bundle_t *bundle = &(tunnel->bundle_list[bundle_id]);
    int idx;
    uint32_t i;

    fgfw_assert((bundle_id >= 0) && (bundle_id < FGFW_TUNNEL_BUNDLE_MAX));
    fgfw_assert((transport_id >= 0) && (transport_id < FGFW_MAX_TRANSPORT));

    idx = fgfw_tunnel_bundle_find_transport(tunnel, bundle_id, transport_id);

    if (idx < 0) {
        fgfw_warn("transport id %d not in bundle %d/n", transport_id, bundle_id);
        return FGFW_RETVALUE_OK;
    }

    i = idx + 1;
    for (; i < bundle->n_transport; i++) {
        bundle->transport_list[i - 1] = bundle->transport_list[i];
    }

    bundle->n_transport--;

    return FGFW_RETVALUE_OK;
}

fgfw_transport_id fgfw_tunnel_bundle_get_transport_id(fgfw_tunnel_t *tunnel, fgfw_tunnel_bundle_id bundle_id)
{
    fgfw_tunnel_bundle_t *bundle = &(tunnel->bundle_list[bundle_id]);
    fgfw_transport_id ret;

    fgfw_assert((bundle_id >= 0) && (bundle_id < FGFW_TUNNEL_BUNDLE_MAX));

    if (bundle->n_transport == 0) {
        return FGFW_TRANSPORT_ID_INVALID;
    }

    ret = bundle->transport_list[bundle->transport_idx % bundle->n_transport];
    bundle->transport_idx++;

    return ret;
}

static void tunnel_transport_conn_cb(fgfw_epoll_inst_t *epoll_inst)
{
    fgfw_transport_t *transport = FGFW_GETCONTAINER(epoll_inst, fgfw_transport_t, epoll_inst);
    /*  */
    vacc_host_read(&(transport->conn));
}

static vacc_host_t* tunnel_transport_get(struct _vacc_host *vacc_host, void *opaque)
{
    fgfw_tunnel_t *tunnel = (fgfw_tunnel_t *)opaque;
    fgfw_transport_t *transport;
    fgfw_transport_id transport_id;

    /* alloc new transport */
    transport_id = fgfw_transport_pool_get(&(tunnel->transport_pool));
    if (transport_id < 0) {
        fgfw_err("fgfw_transport_pool_get() return %d\n", transport_id);
        return NULL;
    }

    /* reset transport */
    transport = &(tunnel->transport_pool._transport_res[transport_id]);

    transport->pending_buf_tail = transport->pending_buf_head = 0;
    transport->align_tmp_buf_len = 0;
    transport->bundle_id = FGFW_BUNDLE_ID_INVALID;

    //
    single_token_bucket_init(&(transport->send_stb), 0, 1000);
    transport->send_bps = FGFW_TRANSPORT_DEFAULT_SEND_BPS;

    /* set aes key */
    fgfw_transport_enable_aes_128(transport, tunnel->default_key);

    return &(transport->conn);
}

static void tunnel_transport_put(struct _vacc_host *vacc_host, void *opaque)
{
    fgfw_tunnel_t *tunnel = (fgfw_tunnel_t *)opaque;
    fgfw_transport_t *transport = FGFW_GETCONTAINER(vacc_host, fgfw_transport_t, conn);
    int ret;

    /* free transport */
    ret = fgfw_transport_pool_put(&(tunnel->transport_pool), transport->transport_id);
    fgfw_assert(ret == FGFW_RETVALUE_OK);
}

static int tunnel_transport_init(struct _vacc_host *vacc_host, void *opaque)
{
    fgfw_tunnel_t *tunnel = (fgfw_tunnel_t *)opaque;
    fgfw_transport_t *transport = FGFW_GETCONTAINER(vacc_host, fgfw_transport_t, conn);

    switch (vacc_host->insttype) {
    case VACC_HOST_INSTTYPE_SERVER_LISTENER:
        fgfw_log("%s listen socket init, transport_id %d\n",
            vacc_host->transtype == VACC_HOST_TRANSTYPE_TCP ? "TCP" :
            vacc_host->transtype == VACC_HOST_TRANSTYPE_UDS ? "UDS" :
            vacc_host->transtype == VACC_HOST_TRANSTYPE_UDP ? "UDP" :
            "UNKNOWN",
            transport->transport_id);
        break;
    case VACC_HOST_INSTTYPE_SERVER_INST:
        fgfw_log("%s server inst connect, transport_id %d\n",
            vacc_host->transtype == VACC_HOST_TRANSTYPE_TCP ? "TCP" :
            vacc_host->transtype == VACC_HOST_TRANSTYPE_UDS ? "UDS" :
            vacc_host->transtype == VACC_HOST_TRANSTYPE_UDP ? "UDP" :
            "UNKNOWN",
            transport->transport_id);
        if (vacc_host->transtype == VACC_HOST_TRANSTYPE_TCP) {
            struct in_addr in = vacc_host->u.tcp.cli_addr.sin_addr;
            unsigned short port = ntohs(vacc_host->u.tcp.cli_addr.sin_port);
            char ipstr[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &in, ipstr, sizeof(ipstr));
            fgfw_log("\t\tclient: %s(%d)\n", ipstr, port);
        } else if (vacc_host->transtype == VACC_HOST_TRANSTYPE_UDS) {

        }

        break;
    case VACC_HOST_INSTTYPE_CLIENT_INST:
        fgfw_log("%s client inst connect, transport_id %d\n",
            vacc_host->transtype == VACC_HOST_TRANSTYPE_TCP ? "TCP" :
            vacc_host->transtype == VACC_HOST_TRANSTYPE_UDS ? "UDS" :
            vacc_host->transtype == VACC_HOST_TRANSTYPE_UDP ? "UDP" :
            "UNKNOWN",
            transport->transport_id);
        break;
    default:
        fgfw_log("vacc_host_init() unknown inst type %d\n", vacc_host->insttype);
        return -1;
    }

    /* reg into epoll thread mngr */
    transport->epoll_inst.fd = vacc_host->sock_fd;
    transport->epoll_inst.epoll_inst_cb = tunnel_transport_conn_cb;
    fgfw_epoll_thread_reg_inst(&(tunnel->epoll_thread), &(transport->epoll_inst));

    /* add into active list */
    fgfw_listadd_tail(&(transport->node), &(tunnel->active_transport_list));
    tunnel->n_active_transport++;

    if (tunnel->mode == FGFW_WORKMODE_CLIENT) {
        /**/
        uint8_t new_key[16] = {0};
        uint32_t i;
        if (tunnel->transport_key_enable) {
            for (i = 0; i < sizeof(new_key) / 2; i++) {
                ((uint16_t *)new_key)[i] = rand();
            }
            tunnel_proc_send_req_bundle_join(tunnel, transport, NULL, getpid(), sizeof(new_key), new_key);
        } else {
            tunnel_proc_send_req_bundle_join(tunnel, transport, NULL, getpid(), 0, NULL);
        }

        fgfw_tunnel_bundle_insert_transport(tunnel, 0, transport->transport_id);
    }

    return 0;
}

static int tunnel_transport_uninit(struct _vacc_host *vacc_host, void *opaque)
{
    fgfw_tunnel_t *tunnel = (fgfw_tunnel_t *)opaque;
    fgfw_transport_t *transport = FGFW_GETCONTAINER(vacc_host, fgfw_transport_t, conn);

    switch (vacc_host->insttype) {
    case VACC_HOST_INSTTYPE_SERVER_LISTENER:
        fgfw_log("%s listen socket uninit, transport_id %d\n",
            vacc_host->transtype == VACC_HOST_TRANSTYPE_TCP ? "TCP" :
            vacc_host->transtype == VACC_HOST_TRANSTYPE_UDS ? "UDS" :
            vacc_host->transtype == VACC_HOST_TRANSTYPE_UDP ? "UDP" :
            "UNKNOWN",
            transport->transport_id);
        break;
    case VACC_HOST_INSTTYPE_SERVER_INST:
        fgfw_log("%s server inst disconnect, transport_id %d\n",
            vacc_host->transtype == VACC_HOST_TRANSTYPE_TCP ? "TCP" :
            vacc_host->transtype == VACC_HOST_TRANSTYPE_UDS ? "UDS" :
            vacc_host->transtype == VACC_HOST_TRANSTYPE_UDP ? "UDP" :
            "UNKNOWN",
            transport->transport_id);
        break;
    case VACC_HOST_INSTTYPE_CLIENT_INST:
        fgfw_log("%s client inst disconnect, transport_id %d\n",
            vacc_host->transtype == VACC_HOST_TRANSTYPE_TCP ? "TCP" :
            vacc_host->transtype == VACC_HOST_TRANSTYPE_UDS ? "UDS" :
            vacc_host->transtype == VACC_HOST_TRANSTYPE_UDP ? "UDP" :
            "UNKNOWN",
            transport->transport_id);
        break;
    default:
        fgfw_log("vacc_host_init() unknown inst type %d\n", vacc_host->insttype);
        return -1;
    }

    /* remove from epoll thread mngr */
    fgfw_epoll_thread_reg_uninst(&(tunnel->epoll_thread), &(transport->epoll_inst));
    transport->epoll_inst.fd = -1;
    transport->epoll_inst.epoll_inst_cb = NULL;

    /* remove from active list */
    fgfw_listdel(&(transport->node));
    tunnel->n_active_transport--;

    return 0;
}

static int tunnel_transport_recv(struct _vacc_host *vacc_host, void *opaque, void *buf, uint32_t len)
{
    fgfw_tunnel_t *tunnel = (fgfw_tunnel_t *)opaque;
    fgfw_transport_t *transport = FGFW_GETCONTAINER(vacc_host, fgfw_transport_t, conn);
    int ret;

    ret = fgfw_transport_recv(transport, buf, len);
    if (ret < 0) {
        fgfw_err("ret %d\n", ret);
        fgfw_assert(0);
    }
    /*  */

    tunnel_transport_proc_one_pkt(tunnel, transport);

    return 0;
}

int fgfw_tunnel_create(fgfw_tunnel_t *tunnel, int mode, char *serv_ip, int n_port, int port_list[], uint8_t default_key[])
{
    int ret, i;
    vacc_host_t *vacc_host;
    fgfw_transport_t *transport;
    vacc_host_create_param_t param;

    if ((mode != FGFW_WORKMODE_SERVER) && (mode != FGFW_WORKMODE_CLIENT)) {
        return FGFW_RETVALUE_INVALID_PARAM;
    }

    memset(tunnel, 0, sizeof(fgfw_tunnel_t));

    memcpy(tunnel->default_key, default_key, sizeof(tunnel->default_key));

    tunnel->n_active_session = 0;
    fgfw_initlisthead(&(tunnel->active_session_list));

    tunnel->n_active_transport = 0;
    fgfw_initlisthead(&(tunnel->active_transport_list));

    tunnel->n_listen_transport = 0;
    fgfw_initlisthead(&(tunnel->listen_transport_list));

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

    fgfw_transport_pool_init(&(tunnel->transport_pool));

    if (mode == FGFW_WORKMODE_SERVER) {
        /* create listen socket */
        for (i = 0; i < n_port; i++) {
            memset(&param, 0, sizeof(param));
            param.transtype = VACC_HOST_TRANSTYPE_TCP;
            param.insttype = VACC_HOST_INSTTYPE_SERVER_LISTENER;
            param.cb_get = tunnel_transport_get;
            param.cb_put = tunnel_transport_put;
            param.cb_init = tunnel_transport_init;
            param.cb_uninit = tunnel_transport_uninit;
            param.cb_recv = tunnel_transport_recv;
            param.proto_abs.enable = 0;
            param.opaque = tunnel;
            strncpy(param.u.tcp.srv_ip, serv_ip, sizeof(param.u.tcp.srv_ip));
            param.u.tcp.srv_port = port_list[i];

            vacc_host = tunnel_transport_get(NULL, tunnel);
            ret = vacc_host_create(vacc_host, &param);
            if (ret != VACC_HOST_RET_OK) {
                fgfw_err("vacc_host_create() return %d\n", ret);
                return FGFW_RETVALUE_ERR;
            }

            /* add into listen list */
            transport = FGFW_GETCONTAINER(vacc_host, fgfw_transport_t, conn);
            fgfw_listadd_tail(&(transport->node), &(tunnel->listen_transport_list));
            tunnel->n_listen_transport++;
        }
    } else {
  
    }

    tunnel->mode = mode;

    tunnel->session_open = fgfw_tunnel_session_open;
    tunnel->session_close = fgfw_tunnel_session_close;
    tunnel->session_send = fgfw_tunnel_session_send;
    tunnel->session_recv = fgfw_tunnel_session_recv;

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

int fgfw_tunnel_connect_to_serv(fgfw_tunnel_t *tunnel, char *serv_ip, int n_port, int port_list[])
{
    vacc_host_t *vacc_host;
    vacc_host_create_param_t param;
    int i, ret;

    fgfw_assert(tunnel->mode == FGFW_WORKMODE_CLIENT);

    /* create bundle */
    fgfw_tunnel_bundle_new(tunnel, NULL, NULL, 0);

    /* connect to tunnel sock */
    for (i = 0; i < n_port; i++) {
        vacc_host = tunnel_transport_get(NULL, tunnel);
        if (vacc_host == NULL) {
            return FGFW_RETVALUE_NOENOUGHRES;
        }

        memset(&param, 0, sizeof(param));
        /* connect to localhots:port */
        param.transtype = VACC_HOST_TRANSTYPE_TCP;
        param.insttype = VACC_HOST_INSTTYPE_CLIENT_INST;
        param.cb_get = tunnel_transport_get;
        param.cb_put = tunnel_transport_put;
        param.cb_init = tunnel_transport_init;
        param.cb_uninit = tunnel_transport_uninit;
        param.cb_recv = tunnel_transport_recv;
        param.proto_abs.enable = 0;
        param.opaque = tunnel;
        strncpy(param.u.tcp.srv_ip, serv_ip, sizeof(param.u.tcp.srv_ip));
        param.u.tcp.srv_port = port_list[i];

        ret = vacc_host_create(vacc_host, &param);
        if (ret != VACC_HOST_RET_OK) {
            fgfw_log("vacc_host_create() return %d\n", ret);
            tunnel_transport_put(vacc_host, tunnel);
            return FGFW_RETVALUE_ERR;
        }
    }

    return FGFW_RETVALUE_OK;
}

/****************************************************************************************
 * tunnel protocol proc
 */

int tunnel_proc_send_req_bundle_join(fgfw_tunnel_t *tunnel, fgfw_transport_t *transport, char src_ipstr[], uint32_t pid_at_cli, int key_len, uint8_t key[])
{
    int ret, len = sizeof(fgfw_tunnel_protocol_pkt_head_t) + sizeof(fgfw_tunnel_protocol_pkt_bundle_join_req_t);
    uint8_t sendbuf[len];
    fgfw_tunnel_protocol_pkt_head_t *pkt_head = (fgfw_tunnel_protocol_pkt_head_t *)sendbuf;
    fgfw_tunnel_protocol_pkt_bundle_join_req_t *bundle_join_req = (fgfw_tunnel_protocol_pkt_bundle_join_req_t *)(pkt_head + 1);

    memset(sendbuf, 0, len);

    fgfw_assert(key_len <= (int)sizeof(bundle_join_req->key));

    pkt_head->tp_type = FGFW_TP_TYPE_REQ_BUNDLE_JOIN;
    pkt_head->real_len = len;
    pkt_head->align_len = fgfw_tunnel_protocol_align(pkt_head->real_len);
    pkt_head->challenge = rand();

    bundle_join_req->magic = FGFW_TUNNEL_PROTOCOL_MAGIC;
    if (src_ipstr) {
        strncpy(bundle_join_req->src_ipstr, src_ipstr, sizeof(bundle_join_req->src_ipstr));
    }
    bundle_join_req->pid_at_cli = pid_at_cli;
    bundle_join_req->key_len = key_len;
    if (key_len) {
        memcpy(bundle_join_req->key, key, key_len);
    }

    /* do send */
    ret = fgfw_transport_send(transport, sendbuf, pkt_head->align_len);
    if (ret) {
        fgfw_err("fgfw_transport_send() return %d\n", ret);
        return ret;
    }

    return len;
}

int tunnel_proc_send_resp_bundle_join(fgfw_tunnel_t *tunnel, fgfw_transport_t *transport, uint32_t challenge, int ret, uint32_t bundle_id)
{
    int len = sizeof(fgfw_tunnel_protocol_pkt_head_t) + sizeof(fgfw_tunnel_protocol_pkt_bundle_join_resp_t);
    uint8_t sendbuf[len];
    fgfw_tunnel_protocol_pkt_head_t *pkt_head = (fgfw_tunnel_protocol_pkt_head_t *)sendbuf;
    fgfw_tunnel_protocol_pkt_bundle_join_resp_t *bundle_join_resp = (fgfw_tunnel_protocol_pkt_bundle_join_resp_t *)(pkt_head + 1);

    memset(sendbuf, 0, len);

    pkt_head->tp_type = FGFW_TP_TYPE_RESP_BUNDLE_JOIN_ACK;
    pkt_head->real_len = len;
    pkt_head->align_len = fgfw_tunnel_protocol_align(pkt_head->real_len);
    pkt_head->challenge = challenge;

    bundle_join_resp->magic = FGFW_TUNNEL_PROTOCOL_MAGIC;
    bundle_join_resp->ret = ret;
    bundle_join_resp->bundle_id = bundle_id;

    /* do send */
    ret = fgfw_transport_send(transport, sendbuf, pkt_head->align_len);
    if (ret) {
        fgfw_err("fgfw_transport_send() return %d\n", ret);
        return ret;
    }

    return len;
}

int tunnel_proc_send_req_session_new(fgfw_tunnel_t *tunnel, fgfw_transport_t *transport, uint32_t port, fgfw_tunnel_session_id orig_session_id, uint32_t *create_challenge)
{
    int ret, len = sizeof(fgfw_tunnel_protocol_pkt_head_t) + sizeof(fgfw_tunnel_protocol_pkt_session_new_req_t);
    uint8_t sendbuf[len];
    fgfw_tunnel_protocol_pkt_head_t *pkt_head = (fgfw_tunnel_protocol_pkt_head_t *)sendbuf;
    fgfw_tunnel_protocol_pkt_session_new_req_t *session_new_req = (fgfw_tunnel_protocol_pkt_session_new_req_t *)(pkt_head + 1);

    memset(sendbuf, 0, len);

    pkt_head->tp_type = FGFW_TP_TYPE_REQ_SESSION_NEW;
    pkt_head->real_len = len;
    pkt_head->align_len = fgfw_tunnel_protocol_align(pkt_head->real_len);
    pkt_head->challenge = rand();

    session_new_req->magic = FGFW_TUNNEL_PROTOCOL_MAGIC;
    session_new_req->port = port;
    session_new_req->orig_session_id = orig_session_id;

    /* save challenge */
    *create_challenge = pkt_head->challenge;

    /* do send */
    ret = fgfw_transport_send(transport, sendbuf, pkt_head->align_len);
    if (ret) {
        fgfw_err("fgfw_transport_send() return %d\n", ret);
        return ret;
    }

    return len;
}

int tunnel_proc_send_resp_session_new(fgfw_tunnel_t *tunnel, fgfw_transport_t *transport, uint32_t challenge, int ret, uint32_t session_key)
{
    int len = sizeof(fgfw_tunnel_protocol_pkt_head_t) + sizeof(fgfw_tunnel_protocol_pkt_session_new_resp_t);
    uint8_t sendbuf[len];
    fgfw_tunnel_protocol_pkt_head_t *pkt_head = (fgfw_tunnel_protocol_pkt_head_t *)sendbuf;
    fgfw_tunnel_protocol_pkt_session_new_resp_t *session_new_resp = (fgfw_tunnel_protocol_pkt_session_new_resp_t *)(pkt_head + 1);

    memset(sendbuf, 0, len);

    pkt_head->tp_type = FGFW_TP_TYPE_RESP_SESSION_NEW_ACK;
    pkt_head->real_len = len;
    pkt_head->align_len = fgfw_tunnel_protocol_align(pkt_head->real_len);
    pkt_head->challenge = challenge;

    session_new_resp->magic = FGFW_TUNNEL_PROTOCOL_MAGIC;
    session_new_resp->ret = ret;
    session_new_resp->session_key = session_key;

    /* do send */
    ret = fgfw_transport_send(transport, sendbuf, pkt_head->align_len);
    if (ret) {
        fgfw_err("fgfw_transport_send() return %d\n", ret);
        return ret;
    }

    return len;
}

int tunnel_transport_proc_one_pkt(fgfw_tunnel_t *tunnel, fgfw_transport_t *transport)
{
    fgfw_tunnel_protocol_pkt_head_t *pkt_head;
    uint32_t avail_len = transport->recv_buf_tail - transport->recv_buf_head;

    if (avail_len == 0) {
        return FGFW_RETVALUE_OK;
    }

    fgfw_assert((transport->recv_buf_tail & (FGFW_TUNNEL_PROTOCOL_PKTLEN_ALIGN - 1)) == 0);
    fgfw_assert((transport->recv_buf_head & (FGFW_TUNNEL_PROTOCOL_PKTLEN_ALIGN - 1)) == 0);

    pkt_head = (fgfw_tunnel_protocol_pkt_head_t *)&(transport->recv_buf[transport->recv_buf_head % FGFW_TUNNEL_PROTOCOL_PKTLEN_ALIGN]);
    if (pkt_head->align_len > avail_len) {
        /* pkt is not complete, need to wait more */
        return FGFW_RETVALUE_PKT_INCOMPLETE;
    }

    switch (pkt_head->tp_type) {
    case FGFW_TP_TYPE_REQ_BUNDLE_JOIN:
    {
        uint32_t offset;
        fgfw_tunnel_bundle_id bundle_id;
        fgfw_tunnel_protocol_pkt_bundle_join_req_t *bundle_join_req;
        int ret;

        offset = transport->recv_buf_head + sizeof(fgfw_tunnel_protocol_pkt_head_t);
        bundle_join_req = (fgfw_tunnel_protocol_pkt_bundle_join_req_t *)&(transport->recv_buf[offset % FGFW_TRANSPORT_RECVBUF_SIZE]);

        if (tunnel->mode != FGFW_WORKMODE_SERVER) {
            ret = FGFW_RETVALUE_ERR;
            fgfw_err("tunnel in client mode, transport %d.\n", transport->transport_id);
        } else if (tunnel->local_agent == NULL) {
            ret = FGFW_RETVALUE_ERR;
            fgfw_err("tunnel local_agent not set, transport %d\n", transport->transport_id);
        } else if (bundle_join_req->magic != FGFW_TUNNEL_PROTOCOL_MAGIC) {
            ret = FGFW_RETVALUE_PROTO_ERR;
            fgfw_err("invalid magic 0x%x\n, transport %d\n", bundle_join_req->magic, transport->transport_id);
        } else {
            struct in_addr in = transport->conn.u.tcp.cli_addr.sin_addr;
            char ipstr[INET_ADDRSTRLEN];

            inet_ntop(AF_INET, &in, ipstr, sizeof(ipstr));

            bundle_id = fgfw_tunnel_bundle_find(tunnel, bundle_join_req->src_ipstr, ipstr, bundle_join_req->pid_at_cli);
            if (bundle_id < 0) {
                bundle_id = fgfw_tunnel_bundle_new(tunnel, bundle_join_req->src_ipstr, ipstr, bundle_join_req->pid_at_cli);
                if (bundle_id < 0) {
                    fgfw_err("no enough bundle resouce.\n");
                    fgfw_assert(0);
                }
            }
            ret = fgfw_tunnel_bundle_insert_transport(tunnel, bundle_id, transport->transport_id);
            if (ret < 0) {
                fgfw_err("too many transport in bundle %d.\n", bundle_id);
                fgfw_assert(0);
            } else {
                fgfw_log("bundle: ipstr_at_cli %s, ipstr_at_srv %s, pid %d, add new transport %d, bundle idx %d\n",
                    bundle_join_req->src_ipstr, ipstr, bundle_join_req->pid_at_cli, transport->transport_id, ret);
                ret = FGFW_RETVALUE_OK;
            }
        }

        /* send ack */
        tunnel_proc_send_resp_bundle_join(tunnel, transport, pkt_head->challenge, ret, bundle_id);

        /* pkt already comsumed */
        transport->recv_buf_head += pkt_head->align_len;

        break;
    }
    case FGFW_TP_TYPE_REQ_SESSION_NEW:
    {
        uint32_t offset;
        fgfw_tunnel_protocol_pkt_session_new_req_t *session_new_req;
        int ret;

        offset = transport->recv_buf_head + sizeof(fgfw_tunnel_protocol_pkt_head_t);
        session_new_req = (fgfw_tunnel_protocol_pkt_session_new_req_t *)&(transport->recv_buf[offset % FGFW_TRANSPORT_RECVBUF_SIZE]);

        if (tunnel->mode != FGFW_WORKMODE_SERVER) {
            ret = FGFW_RETVALUE_ERR;
            fgfw_err("tunnel in client mode, transport %d.\n", transport->transport_id);
        } else if (tunnel->local_agent == NULL) {
            ret = FGFW_RETVALUE_ERR;
            fgfw_err("tunnel local_agent not set, transport %d\n", transport->transport_id);
        } else if (session_new_req->magic != FGFW_TUNNEL_PROTOCOL_MAGIC) {
            ret = FGFW_RETVALUE_PROTO_ERR;
            fgfw_err("invalid magic 0x%x\n, transport %d\n", session_new_req->magic, transport->transport_id);
        } else {
            fgfw_tunnel_session_id new_session_id;

            /* session open, server */
            new_session_id = tunnel->session_open(tunnel, transport->bundle_id, -1, session_new_req->orig_session_id);
            if (new_session_id < 0) {
                ret = FGFW_RETVALUE_SESSION_CREATE_FAILD;
            } else {
                /* create local agent conn */
                ret = tunnel->local_agent->local_conn_open(tunnel->local_agent, new_session_id, session_new_req->port);
            }
        }

        /* send ack */
        tunnel_proc_send_resp_session_new(tunnel, transport, pkt_head->challenge, ret, session_new_req->orig_session_id);
        
        /* pkt already comsumed */
        transport->recv_buf_head += pkt_head->align_len;
        break;
    }
    case FGFW_TP_TYPE_REQ_SESSION_DEL:
        break;
    case FGFW_TP_TYPE_RESP_BUNDLE_JOIN_ACK:
    {
        uint32_t offset;
        fgfw_tunnel_protocol_pkt_bundle_join_resp_t *bundle_resp;

        offset = transport->recv_buf_head + sizeof(fgfw_tunnel_protocol_pkt_head_t);
        bundle_resp = (fgfw_tunnel_protocol_pkt_bundle_join_resp_t *)&(transport->recv_buf[offset % FGFW_TRANSPORT_RECVBUF_SIZE]);
        if (tunnel->mode != FGFW_WORKMODE_CLIENT) {
            fgfw_err("tunnel in server mode, transport %d.\n", transport->transport_id);
        } else {
            fgfw_assert(bundle_resp->bundle_id < FGFW_TUNNEL_BUNDLE_MAX);

            if (bundle_resp->ret) {                
                fgfw_err("bundle join resp ret %d, transport %d\n",
                    bundle_resp->ret, transport->transport_id);
            } else if (bundle_resp->magic != FGFW_TUNNEL_PROTOCOL_MAGIC) {
                fgfw_err("invalid magic 0x%x\n, transport %d\n", bundle_resp->magic, transport->transport_id);
#if 0
            } else if (pkt_head->challenge != orig_session->create_challenge) {
#endif
            } else {
                fgfw_log("bundle join resp ok, return bundle_id %d, transport %d.\n",
                    bundle_resp->bundle_id, transport->transport_id);
            }
        }

        /* pkt already comsumed */
        transport->recv_buf_head += pkt_head->align_len;
        break;
    }
    case FGFW_TP_TYPE_RESP_SESSION_NEW_ACK:
    {
        uint32_t offset;
        fgfw_tunnel_protocol_pkt_session_new_resp_t *session_new_resp;
        fgfw_tunnel_session_t *orig_session;
        offset = transport->recv_buf_head + sizeof(fgfw_tunnel_protocol_pkt_head_t);
        session_new_resp = (fgfw_tunnel_protocol_pkt_session_new_resp_t *)&(transport->recv_buf[offset % FGFW_TRANSPORT_RECVBUF_SIZE]);
        if (tunnel->mode != FGFW_WORKMODE_CLIENT) {
            fgfw_err("tunnel in server mode, transport %d.\n", transport->transport_id);
        } else {
            fgfw_assert((session_new_resp->orig_session_id >= 0) && (session_new_resp->orig_session_id < FGFW_TUNNEL_SESSION_MAX));
            orig_session = &(tunnel->_session_res[session_new_resp->orig_session_id]);
            fgfw_assert(orig_session->session_state == FGFW_TUNNEL_SESSION_STATE_CREATING);

            if (session_new_resp->ret) {
                orig_session->create_ret = session_new_resp->ret;
                orig_session->session_state = FGFW_TUNNEL_SESSION_STATE_CREATE_FAILD;
                
                fgfw_err("session new resp ret %d, transport %d, orig session id %d\n",
                    session_new_resp->ret, transport->transport_id, session_new_resp->orig_session_id);
            } else if (pkt_head->challenge != orig_session->create_challenge) {
                orig_session->create_ret = FGFW_RETVALUE_CHALLENGE_NOT_MATCH;
                orig_session->session_state = FGFW_TUNNEL_SESSION_STATE_CREATE_FAILD;

                fgfw_err("session new resp ret %d, transport %d, orig session id %d, challenge not match 0x%x != 0x%x\n",
                    session_new_resp->ret, transport->transport_id, session_new_resp->orig_session_id,
                    pkt_head->challenge, orig_session->create_challenge);
            } else {
                orig_session->session_state = FGFW_TUNNEL_SESSION_STATE_READY;
                orig_session->session_key = session_new_resp->session_key;
            }
        }

        /* pkt already comsumed */
        transport->recv_buf_head += pkt_head->align_len;

        break;
    }
    case FGFW_TP_TYPE_RESP_SESSION_DEL_ACK:
        break;
    case FGFW_TP_TYPE_SESSION_DATA:
    {
        fgfw_tunnel_session_id dest_session_id;
        fgfw_tunnel_protocol_pkt_session_data_t *session_data_head;
        void *buf_fitst, *buf_second;
        int first_len, second_len;
        uint32_t offset;
        int ret;

        offset = transport->recv_buf_head + sizeof(fgfw_tunnel_protocol_pkt_head_t);
        session_data_head = (fgfw_tunnel_protocol_pkt_session_data_t *)&(transport->recv_buf[offset % FGFW_TRANSPORT_RECVBUF_SIZE]);
        if (session_data_head->magic != FGFW_TUNNEL_PROTOCOL_MAGIC) {
            fgfw_err("invalid magic 0x%x, just stop\n", session_data_head->magic);
            fgfw_assert(0);
        }

        offset += sizeof(fgfw_tunnel_protocol_pkt_session_data_t);
        buf_fitst = &(transport->recv_buf[offset % FGFW_TRANSPORT_RECVBUF_SIZE]);
        first_len = FGFW_TRANSPORT_RECVBUF_SIZE - (offset % FGFW_TRANSPORT_RECVBUF_SIZE);
        if ((uint32_t)first_len > pkt_head->real_len) {
            first_len = pkt_head->real_len;
        }
        second_len = pkt_head->real_len - first_len;
        if (second_len) {
            buf_second = transport->recv_buf;
        }
        dest_session_id = fgfw_tunnel_session_find_by_session_key(tunnel, session_data_head->session_key);
        if (dest_session_id < 0) {
            fgfw_err("can't find session, session key 0x%x\n", session_data_head->session_key);
            fgfw_assert(0);
        }
        ret = tunnel->session_recv(tunnel, dest_session_id, session_data_head->session_offset, buf_fitst, first_len, buf_second, second_len);
        if (ret == FGFW_RETVALUE_OK) {
            transport->recv_buf_head += pkt_head->align_len;
        } else {
            /* todo: */
            fgfw_assert(0);
        }
        break;
    }
    default:
        fgfw_err("invalid type 0x%x, just stop\n", pkt_head->tp_type);
        fgfw_assert(0);
    }

    return FGFW_RETVALUE_OK;
}
