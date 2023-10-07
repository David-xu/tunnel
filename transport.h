#ifndef _TRANSPORT_H_
#define _TRANSPORT_H_

#define FGFW_TRANSPORT_PKT_ALIGN            16                  /* aes 128 */
#define FGFW_MAX_TRANSPORT                  256
#define FGFW_TRANSPORT_DESCLEN              256
// #define FGFW_PENDING_BUFSIZE                (1 * 1024 * 1024)
#define FGFW_PENDING_BUFSIZE                (16 * 1024)
// #define FGFW_TRANSPORT_RECVBUF_SIZE         (1 * 1024 * 1024)
#define FGFW_TRANSPORT_RECVBUF_SIZE         (16 * 1024)
#define FGFW_TRANSPORT_MAX_SEND_LEN         (1024)
#define FGFW_TRANSPORT_DEFAULT_SEND_BPS     (10000)

typedef struct _fgfw_transport {
    fgfw_transport_id           transport_id;
    int                         transport_belongs_to_bundle_id; /* which bundle this transport belongs to, FGFW_BUNDLE_ID_INVALID if not belongs to any bundle */

    pthread_mutex_t             transport_op_big_lock;

    fgfw_epoll_inst_t           epoll_inst;     /*  */

    fgfw_listhead_t             node;
    vacc_host_t                 conn;
    char conn_desc[FGFW_TRANSPORT_DESCLEN];
    
    single_token_bucket_t   send_stb;
    uint32_t                send_bps;           /* byte per second (>=1000) */

    uint32_t    pending_buf_tail, pending_buf_head;
    uint8_t     pending_buf[FGFW_PENDING_BUFSIZE];      /* after encode */

    uint32_t    recv_buf_tail, recv_buf_head;
    uint8_t     recv_buf[FGFW_TRANSPORT_RECVBUF_SIZE];  /* after decode */

    uint32_t    align_tmp_buf_len;
    uint8_t     align_tmp_buf[FGFW_TRANSPORT_PKT_ALIGN];

    int         aes_128_enable;
    AES_KEY     aes_128_enc_key, aes_128_dec_key;
} fgfw_transport_t;

static inline void fgfw_transport_enable_aes_128(fgfw_transport_t *transport, uint8_t key[])
{
    AES_set_encrypt_key(key, 128, &(transport->aes_128_enc_key));
    AES_set_decrypt_key(key, 128, &(transport->aes_128_dec_key));
    
    transport->aes_128_enable = 1;
}

static inline void fgfw_transport_disable_aes_128(fgfw_transport_t *transport)
{
    memset(&(transport->aes_128_enc_key), 0, sizeof(transport->aes_128_enc_key));
    memset(&(transport->aes_128_dec_key), 0, sizeof(transport->aes_128_dec_key));

    transport->aes_128_enable = 0;
}

static inline int fgfw_transport_get_pending_num(fgfw_transport_t *transport)
{
    return (transport->pending_buf_tail - transport->pending_buf_head);
}

typedef struct _fgfw_transport_pool {
    fgfw_transport_t        _transport_res[FGFW_MAX_TRANSPORT];
    fgfw_transport_t        *free_list[FGFW_MAX_TRANSPORT];
    uint32_t                free_tail, free_head;
} fgfw_transport_pool_t;

static inline void fgfw_transport_pool_init(fgfw_transport_pool_t *transport_pool) {
    int i;
    memset(transport_pool, 0, sizeof(fgfw_transport_pool_t));
    for (i = 0; i < FGFW_MAX_TRANSPORT; i++) {
        transport_pool->_transport_res[i].transport_id = i;
        transport_pool->free_list[i] = &(transport_pool->_transport_res[i]);
    }
    transport_pool->free_tail = FGFW_MAX_TRANSPORT;
    transport_pool->free_head = 0;
}

/* return:  */
fgfw_transport_id fgfw_transport_pool_get(fgfw_transport_pool_t *transport_pool);
int fgfw_transport_pool_put(fgfw_transport_pool_t *transport_pool, fgfw_transport_id transport_id);

int fgfw_transport_fill_token(fgfw_transport_t *transport, int n_token);
int fgfw_transport_pool_fill_token_all(fgfw_transport_pool_t *transport_pool, int cycle_ms);

/*
 * do aes if need, send by vacc_host_t
 * len: align to FGFW_TRANSPORT_PKT_ALIGN
 * return: 0
 *         FGFW_RETVALUE_NOENOUGHRES
 */
int fgfw_transport_send(fgfw_transport_t *transport, void *buf, int len);
int fgfw_transport_recv(fgfw_transport_t *transport, void *buf, int len);

#endif