#ifndef _TRANSPORT_H_
#define _TRANSPORT_H_

#define FGFW_MAX_TRANSPORT          256
#define FGFW_TRANSPORT_DESCLEN      256
#define FGFW_PENDING_BUFSIZE        (1 * 1024 * 1024)

typedef struct _fgfw_transport {
    vacc_host_t conn;
    char conn_desc[FGFW_TRANSPORT_DESCLEN];
    
    single_token_bucket_t   send_stb;

    uint32_t    pending_buf_tail, pending_buf_head;
    uint8_t     pending_buf[FGFW_PENDING_BUFSIZE];
} fgfw_transport_t;

static inline int fgfw_transport_get_pending_num(fgfw_transport_t *transport)
{
    return (transport->pending_buf_tail - transport->pending_buf_head);
}

typedef struct _fgfw_transport_pool {
    fgfw_transport_t        _transport_res[FGFW_MAX_TRANSPORT];
    fgfw_transport_t        *free_list[FGFW_MAX_TRANSPORT];
    uint32_t        free_tail, free_head;
} fgfw_transport_pool_t;

/*
 * return: 0
 *         FGFW_RETVALUE_NOENOUGHRES
 */
int fgfw_transport_send(fgfw_transport_t *transport, void *buf, int len);
int fgfw_transport_fill_token(fgfw_transport_t *transport, int n_token);

#endif