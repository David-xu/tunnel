#include "pub.h"

static vacc_host_t* local_agent_vacc_host_get(struct _vacc_host *vacc_host, void *opaque)
{
    fgfw_local_agent_t *local_agent = (fgfw_local_agent_t *)opaque;
    fgfw_local_agent_conn_t *inst;

    if (local_agent->free_local_conn_tail == local_agent->free_local_conn_head) {
        fgfw_err("no enough inst\n");
        return NULL;
    }

    /* alloc new inst */
    inst = local_agent->free_local_conn[local_agent->free_local_conn_head % FGFW_LOCAL_AGENT_MAX_CONN];
    local_agent->free_local_conn_head++;

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

int fgfw_local_agent_create(fgfw_local_agent_t *local_agent, fgfw_tunnel_t *tunnel, int n_local_agent_port, int local_agent_port_list[])
{
    int ret, i;
    vacc_host_create_param_t param;

    memset(local_agent, 0, sizeof(fgfw_local_agent_t));

    local_agent->n_active_local_conn = 0;
    fgfw_initlisthead(&(local_agent->active_local_conn));

    local_agent->n_listen_local_conn = 0;
    fgfw_initlisthead(&(local_agent->listen_local_conn));

    /* init free conn pool */
    for (i = 0; i < FGFW_LOCAL_AGENT_MAX_CONN; i++) {
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
        vacc_host_t *vacc_host;
        memset(&param, 0, sizeof(param));
        param.transtype = VACC_HOST_TRANSTYPE_TCP;
        param.insttype = VACC_HOST_INSTTYPE_SERVER_LISTENER;
        param.cb_get = local_agent_vacc_host_get;
        param.cb_put = local_agent_vacc_host_put;
#if 0
        param.cb_init = ;
        param.cb_uninit = ;
        param.cb_recv = ;
        param.cb_recv_ex = ;
        param.proto_abs.head_len = ;
        param.proto_abs.pkg_max_len = ;
        param.proto_abs.get_payload_len = ;
#endif
        param.opaque = local_agent;
        strncpy(param.u.tcp.srv_ip, "127.0.0.1", sizeof(param.u.tcp.srv_ip));
        param.u.tcp.srv_port = local_agent_port_list[i];

        vacc_host = local_agent_vacc_host_get(NULL, local_agent);
        ret = vacc_host_create(vacc_host, &param);
        if (ret != VACC_HOST_RET_OK) {
            fgfw_err("vacc_host_create() return %d\n", ret);
            return FGFW_RETVALUE_ERR;
        }
    }

    return FGFW_RETVALUE_OK;
}

int fgfw_local_agent_destroy(fgfw_local_agent_t *local_agent)
{
    fgfw_epoll_thread_destroy(&(local_agent->epoll_thread));

    return FGFW_RETVALUE_OK;
}