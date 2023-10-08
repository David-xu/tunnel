#include "pub.h"

static void local_agent_conn_cb(fgfw_epoll_inst_t *epoll_inst)
{
    fgfw_local_agent_conn_t *inst = FGFW_GETCONTAINER(epoll_inst, fgfw_local_agent_conn_t, epoll_inst);
    /*  */
    vacc_host_read(&(inst->vacc_host));
}

static int local_agent_vacc_host_recv(struct _vacc_host *vacc_host, void *opaque, void *buf, uint32_t len)
{
    fgfw_local_agent_t *local_agent = (fgfw_local_agent_t *)opaque;   
    fgfw_local_agent_conn_t *inst = FGFW_GETCONTAINER(vacc_host, fgfw_local_agent_conn_t, vacc_host);
    fgfw_assert(local_agent == inst->local_agent);

    fgfw_log("len %d\n", len);
    // fgfw_hexdump(buf, len);

    local_agent->tunnel->session_send(local_agent->tunnel, inst->session_id, buf, len);

    return 0;
}

static vacc_host_t* local_agent_vacc_host_get(struct _vacc_host *vacc_host, void *opaque)
{
    fgfw_local_agent_t *local_agent = (fgfw_local_agent_t *)opaque;
    fgfw_local_agent_conn_t *inst, *listen_inst = NULL;

    if (vacc_host) {
        listen_inst = FGFW_GETCONTAINER(vacc_host, fgfw_local_agent_conn_t, vacc_host);
    }

    if (local_agent->free_local_conn_tail == local_agent->free_local_conn_head) {
        fgfw_err("no enough inst\n");
        return NULL;
    }

    /* alloc new inst */
    inst = local_agent->free_local_conn[local_agent->free_local_conn_head % FGFW_LOCAL_AGENT_MAX_CONN];
    local_agent->free_local_conn_head++;

    if (listen_inst) {
        inst->listen_port = listen_inst->listen_port;
    }

    return &(inst->vacc_host);
}

static void local_agent_vacc_host_put(struct _vacc_host *vacc_host, void *opaque)
{
    fgfw_local_agent_t *local_agent = (fgfw_local_agent_t *)opaque;
    fgfw_local_agent_conn_t *inst = FGFW_GETCONTAINER(vacc_host, fgfw_local_agent_conn_t, vacc_host);

    if ((local_agent->free_local_conn_tail - local_agent->free_local_conn_head) >= FGFW_LOCAL_AGENT_MAX_CONN) {
        fgfw_err("inst pool full\n");
        return;
    }

    /* free */
    local_agent->free_local_conn[local_agent->free_local_conn_tail % FGFW_LOCAL_AGENT_MAX_CONN] = inst;
    local_agent->free_local_conn_tail++;
}

static int local_agent_vacc_host_init(struct _vacc_host *vacc_host, void *opaque)
{
    fgfw_local_agent_t *local_agent = (fgfw_local_agent_t *)opaque;
    fgfw_local_agent_conn_t *inst = FGFW_GETCONTAINER(vacc_host, fgfw_local_agent_conn_t, vacc_host);

    switch (vacc_host->insttype) {
    case VACC_HOST_INSTTYPE_SERVER_LISTENER:
        fgfw_assert(local_agent->mode == FGFW_WORKMODE_CLIENT);
        fgfw_log("%s listen socket init, conn_id %d\n",
            vacc_host->transtype == VACC_HOST_TRANSTYPE_TCP ? "TCP" :
            vacc_host->transtype == VACC_HOST_TRANSTYPE_UDS ? "UDS" :
            vacc_host->transtype == VACC_HOST_TRANSTYPE_UDP ? "UDP" :
            "UNKNOWN",
            inst->conn_id);
        break;
    case VACC_HOST_INSTTYPE_SERVER_INST:
        fgfw_assert(local_agent->mode == FGFW_WORKMODE_CLIENT);
        fgfw_log("%s server inst connect, conn_id %d\n",
            vacc_host->transtype == VACC_HOST_TRANSTYPE_TCP ? "TCP" :
            vacc_host->transtype == VACC_HOST_TRANSTYPE_UDS ? "UDS" :
            vacc_host->transtype == VACC_HOST_TRANSTYPE_UDP ? "UDP" :
            "UNKNOWN",
            inst->conn_id);
        if (vacc_host->transtype == VACC_HOST_TRANSTYPE_TCP) {
            struct in_addr in = vacc_host->u.tcp.cli_addr.sin_addr;
            char ipstr[INET_ADDRSTRLEN];
            unsigned short port;
            port = ntohs(vacc_host->u.tcp.cli_addr.sin_port);
            inet_ntop(AF_INET, &in, ipstr, sizeof(ipstr));
            fgfw_log("\t\tclient: %s(%d)\n", ipstr, port);
        } else if (vacc_host->transtype == VACC_HOST_TRANSTYPE_UDS) {

        }

        if (local_agent->mode == FGFW_WORKMODE_CLIENT) {
            fgfw_assert(local_agent->tunnel->n_bundle == 1);
            /* new connection, create new tunnel session, client */
            inst->session_id = local_agent->tunnel->session_open(local_agent->tunnel, inst->conn_id, 0,
                inst->listen_port + local_agent->port_agent_offset);
            if (inst->session_id < 0) {
                fgfw_err("inst conn_id %d session create faild, ret %d\n", inst->conn_id, inst->session_id);
            } else {
                fgfw_log("inst conn_id %d, create new session, session id %d\n", inst->conn_id, inst->session_id);
            }
        }

        break;
    case VACC_HOST_INSTTYPE_CLIENT_INST:
        fgfw_assert(local_agent->mode == FGFW_WORKMODE_SERVER);
        fgfw_log("%s client inst connect, conn_id %d\n",
            vacc_host->transtype == VACC_HOST_TRANSTYPE_TCP ? "TCP" :
            vacc_host->transtype == VACC_HOST_TRANSTYPE_UDS ? "UDS" :
            vacc_host->transtype == VACC_HOST_TRANSTYPE_UDP ? "UDP" :
            "UNKNOWN",
            inst->conn_id);
        break;
    default:
        fgfw_log("vacc_host_init() unknown inst type %d\n", vacc_host->insttype);
        return -1;
    }

    /* reg into epoll thread mngr */
    inst->epoll_inst.fd = vacc_host->sock_fd;
    inst->epoll_inst.epoll_inst_cb = local_agent_conn_cb;
    fgfw_epoll_thread_reg_inst(&(local_agent->epoll_thread), &(inst->epoll_inst));

    /* add into active list */
    fgfw_listadd_tail(&(inst->node), &(local_agent->active_local_conn));
    local_agent->n_active_local_conn++;

    return 0;
}

static int local_agent_vacc_host_uninit(struct _vacc_host *vacc_host, void *opaque)
{
    fgfw_local_agent_t *local_agent = (fgfw_local_agent_t *)opaque;
    fgfw_local_agent_conn_t *inst = FGFW_GETCONTAINER(vacc_host, fgfw_local_agent_conn_t, vacc_host);

    switch (vacc_host->insttype) {
    case VACC_HOST_INSTTYPE_SERVER_LISTENER:
        fgfw_log("%s listen socket uninit, conn_id %d\n",
            vacc_host->transtype == VACC_HOST_TRANSTYPE_TCP ? "TCP" :
            vacc_host->transtype == VACC_HOST_TRANSTYPE_UDS ? "UDS" :
            vacc_host->transtype == VACC_HOST_TRANSTYPE_UDP ? "UDP" :
            "UNKNOWN",
            inst->conn_id);
        break;
    case VACC_HOST_INSTTYPE_SERVER_INST:
        fgfw_log("%s server inst disconnect, conn_id %d\n",
            vacc_host->transtype == VACC_HOST_TRANSTYPE_TCP ? "TCP" :
            vacc_host->transtype == VACC_HOST_TRANSTYPE_UDS ? "UDS" :
            vacc_host->transtype == VACC_HOST_TRANSTYPE_UDP ? "UDP" :
            "UNKNOWN",
            inst->conn_id);
        break;
    case VACC_HOST_INSTTYPE_CLIENT_INST:
        fgfw_log("%s client inst disconnect, conn_id %d\n",
            vacc_host->transtype == VACC_HOST_TRANSTYPE_TCP ? "TCP" :
            vacc_host->transtype == VACC_HOST_TRANSTYPE_UDS ? "UDS" :
            vacc_host->transtype == VACC_HOST_TRANSTYPE_UDP ? "UDP" :
            "UNKNOWN",
            inst->conn_id);
        break;
    default:
        fgfw_log("vacc_host_init() unknown inst type %d\n", vacc_host->insttype);
        return -1;
    }

    /* destroy tunnel session */
    if (inst->session_id < 0) {
        fgfw_log("inst conn_id %d, session_id invalid %d\n", inst->conn_id);
    } else {
        int ret;
        ret = local_agent->tunnel->session_close(local_agent->tunnel, inst->session_id);
        if (ret < 0) {
            fgfw_err("inst conn_id %d, session close return %d\n", inst->conn_id, ret);
        }
    }

    /* remove from epoll thread mngr */
    fgfw_epoll_thread_reg_uninst(&(local_agent->epoll_thread), &(inst->epoll_inst));
    inst->epoll_inst.fd = -1;
    inst->epoll_inst.epoll_inst_cb = NULL;

    /* remove from active list */
    fgfw_listdel(&(inst->node));
    local_agent->n_active_local_conn--;

    return 0;
}

static fgfw_local_agent_conn_id local_agent_conn_open(fgfw_local_agent_t *local_agent, fgfw_tunnel_session_id session_id, uint32_t port)
{
    fgfw_local_agent_conn_t *inst;
    vacc_host_t *vacc_host;
    vacc_host_create_param_t param;
    int ret;

    fgfw_assert(local_agent->mode == FGFW_WORKMODE_SERVER);

    vacc_host = local_agent_vacc_host_get(NULL, local_agent);
    if (vacc_host == NULL) {
        return FGFW_AGENT_CONN_ID_INVALID;
    }

    inst = FGFW_GETCONTAINER(vacc_host, fgfw_local_agent_conn_t, vacc_host);

    /* connect to localhots:port */
    param.transtype = VACC_HOST_TRANSTYPE_TCP;
    param.insttype = VACC_HOST_INSTTYPE_CLIENT_INST;
    param.cb_get = local_agent_vacc_host_get;
    param.cb_put = local_agent_vacc_host_put;
    param.cb_init = local_agent_vacc_host_init;
    param.cb_uninit = local_agent_vacc_host_uninit;
    param.cb_recv = local_agent_vacc_host_recv;
    param.proto_abs.enable = 0;
#if FGFW_CONFIG_SOCKBUFSIZE
    param.sendbuf_size = FGFW_CONFIG_SOCKBUFSIZE;
    param.recvbuf_size = FGFW_CONFIG_SOCKBUFSIZE;
#endif
    param.opaque = local_agent;
    strncpy(param.u.tcp.srv_ip, "127.0.0.1", sizeof(param.u.tcp.srv_ip));
    param.u.tcp.srv_port = port;

    ret = vacc_host_create(vacc_host, &param);
    if (ret != VACC_HOST_RET_OK) {
        fgfw_log("vacc_host_create() return %d\n", ret);
        local_agent_vacc_host_put(vacc_host, local_agent);
        return FGFW_RETVALUE_ERR;
    }

    inst->session_id = session_id;
    fgfw_log("local agent conn ok, dest port %d, session id %d\n", port, session_id);

    return inst->conn_id;
}
static int local_agent_conn_close(fgfw_local_agent_t *local_agent, fgfw_local_agent_conn_id id)
{
    fgfw_local_agent_conn_t *inst = &(local_agent->local_conn_pool[id]);
    int ret;

    fgfw_assert((id >= 0) && (id < FGFW_LOCAL_AGENT_MAX_CONN));

    ret = vacc_host_destroy(&(inst->vacc_host));
    if (ret) {
        fgfw_err("vacc_host_destroy() return %d\n", ret);
        return FGFW_RETVALUE_ERR;
    }
    
    return FGFW_RETVALUE_OK;
}

static int local_agent_conn_send(fgfw_local_agent_t *local_agent, fgfw_local_agent_conn_id id, void *buf, int len)
{
    fgfw_local_agent_conn_t *inst = &(local_agent->local_conn_pool[id]);
    int ret;

    fgfw_assert((id >= 0) && (id < FGFW_LOCAL_AGENT_MAX_CONN));

    ret = vacc_host_write(&(inst->vacc_host), buf, len);
    if (ret) {
        fgfw_err("agent conn id %d: vacc_host_write() return %d\n", inst->conn_id, ret);
    } else {
        fgfw_dbg(FGFW_DBGFLAG_AGENT_CONN, "agent conn id %d, send %d.\n", inst->conn_id, len);
    }

    return FGFW_RETVALUE_OK;
}

int fgfw_local_agent_create(fgfw_local_agent_t *local_agent, int mode, int port_agent_offset, fgfw_tunnel_t *tunnel, int n_local_agent_port, int local_agent_port_list[])
{
    int ret, i;
    vacc_host_create_param_t param;

    memset(local_agent, 0, sizeof(fgfw_local_agent_t));

    local_agent->mode = mode;
    local_agent->port_agent_offset = port_agent_offset;
    local_agent->tunnel = tunnel;

    local_agent->local_conn_open = local_agent_conn_open;
    local_agent->local_conn_close = local_agent_conn_close;
    local_agent->local_conn_send = local_agent_conn_send;

    local_agent->n_active_local_conn = 0;
    fgfw_initlisthead(&(local_agent->active_local_conn));

    local_agent->n_listen_local_conn = 0;
    fgfw_initlisthead(&(local_agent->listen_local_conn));

    /* init free conn pool */
    for (i = 0; i < FGFW_LOCAL_AGENT_MAX_CONN; i++) {
        local_agent->local_conn_pool[i].conn_id = i;
        local_agent->local_conn_pool[i].local_agent = local_agent;
        local_agent->free_local_conn[i] = &(local_agent->local_conn_pool[i]);
    }
    local_agent->free_local_conn_tail = FGFW_LOCAL_AGENT_MAX_CONN;
    local_agent->free_local_conn_head = 0;

    /* create epoll thread */
    ret = fgfw_epoll_thread_create(&(local_agent->epoll_thread));
    if (ret) {
        fgfw_err("fgfw_epoll_thread_create() return %d\n", ret);
        return ret;
    }

    /* create listen socket */
    for (i = 0; i < n_local_agent_port; i++) {
        fgfw_local_agent_conn_t *inst;
        vacc_host_t *vacc_host;
        memset(&param, 0, sizeof(param));
        param.transtype = VACC_HOST_TRANSTYPE_TCP;
        param.insttype = VACC_HOST_INSTTYPE_SERVER_LISTENER;
        param.cb_get = local_agent_vacc_host_get;
        param.cb_put = local_agent_vacc_host_put;
        param.cb_init = local_agent_vacc_host_init;
        param.cb_uninit = local_agent_vacc_host_uninit;
        param.cb_recv = local_agent_vacc_host_recv;
        param.proto_abs.enable = 0;
#if FGFW_CONFIG_SOCKBUFSIZE
        param.sendbuf_size = FGFW_CONFIG_SOCKBUFSIZE;
        param.recvbuf_size = FGFW_CONFIG_SOCKBUFSIZE;
#endif
        param.opaque = local_agent;
        strncpy(param.u.tcp.srv_ip, "127.0.0.1", sizeof(param.u.tcp.srv_ip));
        param.u.tcp.srv_port = local_agent_port_list[i];

        vacc_host = local_agent_vacc_host_get(NULL, local_agent);
        ret = vacc_host_create(vacc_host, &param);
        if (ret != VACC_HOST_RET_OK) {
            fgfw_err("vacc_host_create() return %d\n", ret);
            local_agent_vacc_host_put(vacc_host, local_agent);
            return FGFW_RETVALUE_ERR;
        }

        /* add into listen list */
        inst = FGFW_GETCONTAINER(vacc_host, fgfw_local_agent_conn_t, vacc_host);
        fgfw_listadd_tail(&(inst->node), &(local_agent->listen_local_conn));
        local_agent->n_listen_local_conn++;

        /* save listen port */
        inst->listen_port = local_agent_port_list[i];
    }

    return FGFW_RETVALUE_OK;
}

int fgfw_local_agent_destroy(fgfw_local_agent_t *local_agent)
{
    fgfw_local_agent_conn_t *p, *n;

    FGFW_LISTENTRYWALK_SAVE(p, n, &(local_agent->active_local_conn), node) {
        local_agent->local_conn_close(local_agent, p->conn_id);
    }

    fgfw_epoll_thread_destroy(&(local_agent->epoll_thread));

    return FGFW_RETVALUE_OK;
}