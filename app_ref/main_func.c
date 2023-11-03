#include "pub.h"

running_ctx_t g_ctx;

static int tb_insert_timer_1ms(void *param)
{
    running_ctx_t *ctx = (running_ctx_t *)param;

    rn_tunnel_transport_polling_all(ctx->tunnel, RN_CONFIG_TOKEN_FILL_CYCLE_MS);
    rn_agent_conn_polling_all(ctx->local_agent, RN_CONFIG_TOKEN_FILL_CYCLE_MS);

    return 0;
}

void mainfunc_init(void)
{
    /* set default key */
    memset(g_ctx.default_key, 0, sizeof(g_ctx.default_key));
    strncpy((char *)g_ctx.default_key, "abcd01234567ef", sizeof(g_ctx.default_key));

    strncpy(g_ctx.serv_ip, "8.218.56.30", sizeof(g_ctx.serv_ip));
    g_ctx.n_port = 4;
    g_ctx.port_list[0] = 40000;
    g_ctx.port_list[1] = 40001;
    g_ctx.port_list[2] = 50002;
    g_ctx.port_list[3] = 50003;

    g_ctx.transport_send_bps = 100000;

    g_ctx.n_local_agent_port = 1;
    g_ctx.local_agent_port_list[0] = 3000;

    g_ctx.port_agent_offset = 1;

    srand(time(0));
}

void mainfunc_client_run(void)
{
    /* create epoll_thread */
    rn_assert(rn_epoll_thread_create(&(g_ctx.epoll_thread)) == RN_RETVALUE_OK);

    /* create global pkb pool */
    g_ctx.pkb_pool = rn_pkb_pool_create(RN_CONFIG_MAX_PKB_NUM, RN_CONFIG_PKB_SIZE);
    rn_assert(g_ctx.pkb_pool != NULL);

    int i, ret;
    rn_socket_public_t *p, *n;
    rn_transport_t *transport;
    rn_bundle_id client_bundle_id;

    running_ctx_t *ctx = &(g_ctx);

    /* create tunnel */
    ctx->tunnel = rn_tunnel_create(&(ctx->epoll_thread), ctx->pkb_pool, RN_CONFIG_MAX_TUNNEL_TRANSPORT, ctx->default_key, ctx->transport_send_bps);
    /* connect to server's transport socket */
    for (i = 0; i < ctx->n_port; i++) {
        /* connect */
        ret = rn_socket_mngr_connect(&(ctx->tunnel->socket_mngr), ctx->serv_ip, ctx->port_list[i], RN_CONFIG_SOCKET_BUF_SIZE, NULL);
        if (ret != RN_RETVALUE_OK) {
            rn_err("connect to %s %d faild.\n", ctx->serv_ip, ctx->port_list[i]);
            return;
        }
    }
    /* bundle create */
    client_bundle_id = rn_tunnel_bundle_new(ctx->tunnel, NULL, NULL, 0);
    rn_assert(client_bundle_id == 0);
    /* all transport need to do 'bundle join' */
    rn_assert(ctx->tunnel->socket_mngr.n_client_inst == ctx->n_port);
    RN_LISTENTRYWALK_SAVE(p, n, &(ctx->tunnel->socket_mngr.client_inst_list), list_entry) {
        rn_assert(p->vacc_host.insttype == VACC_HOST_INSTTYPE_CLIENT_INST);
        /* send msg */
        transport = RN_GETCONTAINER(p, rn_transport_t, socket);
        ret = tunnel_proc_send_bundle_join(ctx->tunnel, transport, NULL, getpid());
        rn_assert(ret == RN_RETVALUE_OK);
        /* local transport join bundle */
        rn_tunnel_bundle_insert_transport(ctx->tunnel, client_bundle_id, transport->transport_id);
    }

    /* create local_agent */
    ctx->local_agent = rn_local_agent_create(ctx->tunnel, &(ctx->epoll_thread), ctx->pkb_pool, RN_CONFIG_MAX_AGENT_CONN_CLIENT, ctx->port_agent_offset);
    /* create all listener */
    for (i = 0; i < ctx->n_local_agent_port; i++) {
        rn_socket_mngr_listen_add(&(ctx->local_agent->socket_mngr), "127.0.0.1", ctx->local_agent_port_list[i], RN_CONFIG_SOCKET_BUF_SIZE);
    }

    /* set local_agent in tunnel */
    ctx->tunnel->local_agent = ctx->local_agent;

    g_ctx.transport_polling_timer_id = rn_timerfw_add_timer(&(g_ctx.epoll_thread), 1000, RN_CONFIG_TOKEN_FILL_CYCLE_MS * 1000, tb_insert_timer_1ms, &g_ctx);
    rn_assert(g_ctx.transport_polling_timer_id >= 0);
}