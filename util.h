#ifndef _UTIL_H_
#define _UTIL_H_

#define RN_BUILD_BUG_ON(condition)          ((void)sizeof(char[1 - 2*!!(condition)]))

#define RN_RETVALUE_OK                      0
#define RN_RETVALUE_ERR                     -1
#define RN_RETVALUE_SYSCALL_FAILD           -2
#define RN_RETVALUE_INVALID_PARAM           -3
#define RN_RETVALUE_NO_SUCH_BUNDLE          -4
#define RN_RETVALUE_NO_SUCH_SESSION         -5
#define RN_RETVALUE_NO_SUCH_TRANSPORT       -6
#define RN_RETVALUE_NOENOUGHRES             -7
#define RN_RETVALUE_INVALID_STATE           -8
#define RN_RETVALUE_EMPTY                   -9
#define RN_RETVALUE_NOTALIGN                -10
#define RN_RETVALUE_SOCKET_CONNECT_ERR      -11
#define RN_RETVALUE_SESSION_NOT_READY       -12
#define RN_RETVALUE_TIMER_NOT_READY         -13
#define RN_RETVALUE_NOENOUGHSPACE           -14
#define RN_RETVALUE_PKT_INCOMPLETE          -15
#define RN_RETVALUE_PROTO_ERR               -16
#define RN_RETVALUE_SESSION_CREATE_FAILD    -17
#define RN_RETVALUE_CHALLENGE_NOT_MATCH     -18
#define RN_RETVALUE_BUNDLE_NOT_BUILD        -19
#define RN_RETVALUE_NOPKT_NEED_PROC         -20

#define rn_assert(cond)    do{ \
    if (!(cond)) { \
        rn_printf("%-24s %4d Assert! `" #cond "'\n", __FUNCTION__, __LINE__); \
        while (1) {sleep(1000);} \
    } \
} while (0)

#define rn_log(fmt, args...) do { \
        rn_printf("[LOG] %-24s %4d: "fmt, __FUNCTION__, __LINE__, ##args); \
    } while(0)
#define rn_warn(fmt, args...) do { \
        rn_printf("[WARN] %-24s %4d: "fmt, __FUNCTION__, __LINE__, ##args); \
    } while(0)
#define rn_err(fmt, args...) do { \
        rn_printf("[ERR] %-24s %4d: "fmt, __FUNCTION__, __LINE__, ##args); \
    } while(0)

#ifndef rte_mb
#define rte_mb()    _mm_mfence()
#endif

#ifndef rte_wmb
#define rte_wmb()   _mm_sfence()
#endif

#ifndef rte_rmb
#define rte_rmb()   _mm_lfence()
#endif

#define RN_P2V(p)                           ((char *)(p) - (char *)0)
#define RN_V2P(v)                           ((void *)((char *)0 + (v)))
#define RN_OFFSETOF(strtype, field)         RN_P2V(&(((strtype *)0)->field))
#define RN_ARRAY_SIZE(ar)                   (sizeof(ar) / sizeof((ar)[0]))

#define	RN_GETCONTAINER(p, type, field)              \
    ((type *)RN_V2P(RN_P2V(p) - RN_OFFSETOF(type, field)))

#define	RN_LISTISEMPLY(head)             ((head) == ((head)->next))

typedef struct _rn_listhead {
    struct _rn_listhead          *prev;
    struct _rn_listhead          *next;
} rn_listhead_t;

#define RN_LISTWALK(p, head) for (p = (head)->next; p != (head); p = p->next)

#define RN_LISTWALK_SAVE(p, n, head) \
    for (p = (head)->next, n = p->next; p != (head); p = n, n = p->next)

#define RN_LISTENTRYWALK(p, head, field) \
    for (p = RN_GETCONTAINER((head)->next, typeof(*p), field); \
        &(p->field) != (head); \
        p = RN_GETCONTAINER((p)->field.next, typeof(*p), field))

#define RN_LISTENTRYWALK_SAVE(p, n, head, field) \
    for (p = RN_GETCONTAINER((head)->next, typeof(*p), field), \
        n = RN_GETCONTAINER((head)->next->next, typeof(*p), field); \
        &(p->field) != (head); \
        p = n, n = RN_GETCONTAINER(p->field.next, typeof(*p), field))

static inline void rn_initlisthead(rn_listhead_t *head)
{
    head->next = head->prev = head;
}

static inline void rn_listadd_(rn_listhead_t *p, rn_listhead_t *prev, rn_listhead_t *next)
{
    prev->next = p;
    p->prev = prev;
    p->next = next;
    next->prev = p;
}

static inline void rn_listdel_(rn_listhead_t *prev, rn_listhead_t *next)
{
    prev->next = next;
    next->prev = prev;
}

/* add the element @p to head */
static inline void rn_listadd(rn_listhead_t *p, rn_listhead_t *head)
{
    rn_listadd_(p, head, head->next);
}
static inline void rn_listadd_tail(rn_listhead_t *p, rn_listhead_t *head)
{
    rn_listadd_(p, head->prev, head);
}

static inline void rn_listdel(rn_listhead_t *p)
{
    if (!RN_LISTISEMPLY(p)) {
        rn_listdel_(p->prev, p->next);
    }
}

/* utils */
int qemu_time_millis_now_raw(unsigned long *now);
int time_string_now_raw(char *buf);

uint32_t rn_crc32c_sw(const void *data, uint64_t length);
int rn_printf(const char *fmt, ...);
void rn_aes_encrypt(const unsigned char *key, const unsigned char *input, unsigned char *output);
void rn_aes_decrypt(const unsigned char *key, const unsigned char *input, unsigned char *output);

/*
 * ret: 1 --> overlap
 */
static inline int rn_isrange_overlap(__uint128_t begin1, __uint128_t size1, __uint128_t begin2, __uint128_t size2)
{
    __uint128_t begin = begin1 < begin2 ? begin1 : begin2;
    __uint128_t end1, end2, end;
    end1 = begin1 + size1;
    end2 = begin2 + size2;
    end = end1 > end2 ? end1 : end2;
    if ((end - begin) < (size1 + size2)) {
        return 1;
    }
    return 0;
}

static inline char rn_n2c(uint32_t v)
{
    return (v > 9) ? ('A' + v - 10) : ('0' + v);
}

static inline int rn_c2n(char c)
{
    if ((c >= '0') && (c <= '9')) {
        return c - '0';
    } else if ((c >= 'A') && (c <= 'F')) {
        return c - 'A' + 10;
    } else if ((c >= 'a') && (c <= 'f')) {
        return c - 'a' + 10;
    } else {
        return -1;
    }
}


int rn_stdiv
(
	char *buf,			/* input */
	int buflen,			/* input */
	int n_argv,			/* input: sizeof argv */
	char *argv[],		/* output */
	uint32_t len[],		/* output */
	int n_divflag,		/* input */
	char *divflag,		/* input */
	uint32_t ctrl		/* input */
);
void rn_hexdump(const void *buf, uint32_t len);

/*
 */

typedef struct {
    int     free, max;
} single_token_bucket_t;

static inline int single_token_bucket_init(single_token_bucket_t *stb, int free, int max)
{
    stb->free = free;
    stb->max = max;
    return 0;
}

static inline int single_token_bucket_insert(single_token_bucket_t *stb, int n_token)
{
    stb->free += n_token;
    if (stb->free > stb->max) {
        stb->free = stb->max;
    }

    return 0;
}
/* return: number of token consumed */
static inline int single_token_bucket_consume(single_token_bucket_t *stb, int n_token)
{
    int old_free = stb->free;
    if (n_token > old_free) {
        n_token = old_free;
    }

    stb->free -= n_token;
    return n_token;
}

/*
 * bitmap
 */
#define RN_BITMAP_MAGIC                 0x4d544942
#define RN_BITMAP_NAME_MAXLEN           32
typedef struct {
    uint32_t        magic, id_base;
    uint32_t        n_total, n_free;
    uint32_t        pad[4];
    char            name[RN_BITMAP_NAME_MAXLEN];
    uint64_t        bm[0];              /* 1: free, 0: occupied */
} rn_bitmap_t;

#define RN_BITMAP_BMARRAY_SIZE(bm)            (((bm)->n_total + 63) / 64)

int rn_bitmap_init_ex(rn_bitmap_t *bm, const char *name, uint32_t n_total, uint32_t id_base, int clear);
#define iohub_bitmap_init(bm, name, n_total, id_base)   rn_bitmap_init_ex(bm, name, n_total, id_base, 0)
int rn_bitmap_alloc(rn_bitmap_t *bm, uint32_t n, uint32_t *res);
int rn_bitmap_alloc_specified(rn_bitmap_t *bm, uint32_t specified_id);
int rn_bitmap_free(rn_bitmap_t *bm, uint32_t n, uint32_t *ids);
int rn_bitmap_query_specified(rn_bitmap_t *bm, uint32_t specified_id);

#define RN_RAW_BITMAP_SET(bm, idx)              do {((uint32_t *)bm)[(idx) / 32] |= 0x1ULL << ((idx) % 32);} while (0)
#define RN_RAW_BITMAP_CLEAR(bm, idx)            do {((uint32_t *)bm)[(idx) / 32] &= ~(0x1ULL << ((idx) % 32));} while (0)
#define RN_RAW_BITMAP_TEST(bm, idx)             (((uint32_t *)bm)[(idx) / 32] & (0x1ULL << ((idx) % 32)))

/*
 * fifo
 */
typedef struct {
    volatile uint32_t   tail, head;
    uint32_t            depth;
    uint32_t            element_size;
    uint32_t            rsv[4];
} rn_gpfifo_t;
#define RN_GPFIFO_CUR_LEN(gpfifo)       ((gpfifo)->tail - (gpfifo)->head)
#define RN_GPFIFO_ISEMPTY(gpfifo)       (RN_GPFIFO_CUR_LEN(gpfifo) == 0)
#define RN_GPFIFO_ISFULL(gpfifo)        (RN_GPFIFO_CUR_LEN(gpfifo) == (gpfifo)->depth)

static inline int rn_gpfifo_enqueue(rn_gpfifo_t *gpfifo, void *data, uint32_t len)
{
    void *buf;
    int cp_len = len < gpfifo->element_size ? len : gpfifo->element_size;

    rn_assert(len <= gpfifo->element_size);

    if (RN_GPFIFO_ISFULL(gpfifo)) {
        return RN_RETVALUE_NOENOUGHRES;
    }

    buf = (void *)(gpfifo + 1) + (gpfifo->tail % gpfifo->depth) * gpfifo->element_size;
    memcpy(buf, data, cp_len);

    gpfifo->tail++;

    return RN_RETVALUE_OK;
}

static inline int rn_gpfifo_dequeue(rn_gpfifo_t *gpfifo, void *data, uint32_t len)
{
    void *buf;
    int cp_len = len < gpfifo->element_size ? len : gpfifo->element_size;

    rn_assert(len <= gpfifo->element_size);

    if (RN_GPFIFO_ISEMPTY(gpfifo)) {
        return RN_RETVALUE_EMPTY;
    }

    buf = (void *)(gpfifo + 1) + (gpfifo->head % gpfifo->depth) * gpfifo->element_size;
    memcpy(data, buf, cp_len);

    gpfifo->head++;

    return RN_RETVALUE_OK;
}

static inline int rn_gpfifo_peek(rn_gpfifo_t *gpfifo, void *data, uint32_t len)
{
    void *buf;
    int cp_len = len < gpfifo->element_size ? len : gpfifo->element_size;

    rn_assert(len <= gpfifo->element_size);

    if (RN_GPFIFO_ISEMPTY(gpfifo)) {
        return RN_RETVALUE_EMPTY;
    }

    buf = (void *)(gpfifo + 1) + (gpfifo->head % gpfifo->depth) * gpfifo->element_size;
    memcpy(data, buf, cp_len);

    return RN_RETVALUE_OK;
}

static inline int rn_gpfifo_enqueue_p(rn_gpfifo_t *gpfifo, void *p)
{
    return rn_gpfifo_enqueue(gpfifo, &p, sizeof(p));
}

static inline void * rn_gpfifo_dequeue_p(rn_gpfifo_t *gpfifo)
{
    void *p;

    if (rn_gpfifo_dequeue(gpfifo, &p, sizeof(p)) != RN_RETVALUE_OK) {
        return NULL;
    }

    return p;
}

static inline void * rn_gpfifo_peek_p(rn_gpfifo_t *gpfifo)
{
    void *p;

    if (rn_gpfifo_peek(gpfifo, &p, sizeof(p)) != RN_RETVALUE_OK) {
        return NULL;
    }

    return p;
}

static inline int rn_gpfifo_enqueue_b(rn_gpfifo_t *gpfifo, uint8_t b)
{
    return rn_gpfifo_enqueue(gpfifo, &b, sizeof(b));
}

static inline int rn_gpfifo_enqueue_w(rn_gpfifo_t *gpfifo, uint16_t w)
{
    return rn_gpfifo_enqueue(gpfifo, &w, sizeof(w));
}

static inline int rn_gpfifo_enqueue_d(rn_gpfifo_t *gpfifo, uint32_t d)
{
    return rn_gpfifo_enqueue(gpfifo, &d, sizeof(d));
}

static inline int rn_gpfifo_enqueue_l(rn_gpfifo_t *gpfifo, uint64_t l)
{
    return rn_gpfifo_enqueue(gpfifo, &l, sizeof(l));
}

rn_gpfifo_t * rn_gpfifo_create(uint32_t depth, uint32_t element_size);
int rn_gpfifo_destroy(rn_gpfifo_t *gpfifo);

/*
 * packet buffer & packet buffer pool
 */
#define RN_PKB_OVERHEAD                     (64)
#define PN_PKB_FLAG_ALREADY_FREE            1

struct _rn_pkb_pool;
typedef struct {
    uint64_t    pkb_flag;
    void        *bufhead;

#ifdef RN_CONFIG_PKBPOOL_CHECK
    struct _rn_pkb_pool     *pkb_pool;
    uint32_t    idx;
#endif
    uint32_t    bufsize;

    uint32_t    cur_off;
    uint32_t    cur_len;
} rn_pkb_t;
#define RN_PKB_HEAD(pkb)            ((pkb)->bufhead + (pkb)->cur_off)
#define RN_PKB_TAIL(pkb)            ((pkb)->bufhead + (pkb)->cur_off + (pkb)->cur_len)
#define RN_PKB_LEFTSPACE(pkb)       ((pkb)->bufsize - (pkb)->cur_off - (pkb)->cur_len)

typedef struct _rn_pkb_pool {
    uint32_t        total_pkb_num;
    uint32_t        bufsize;                /* each packet buffer size */
    rn_gpfifo_t     *free_pkt_fifo;

    uint32_t        rsv[4];
} rn_pkb_pool_t;

rn_pkb_pool_t * rn_pkb_pool_create(uint32_t total_pkb_num, uint32_t bufsize);
int rn_pkb_pool_destroy(rn_pkb_pool_t *pkb_pool);
rn_pkb_t *rn_pkb_pool_get_pkb(rn_pkb_pool_t *pkb_pool);
int rn_pkb_pool_put_pkb(rn_pkb_pool_t *pkb_pool, rn_pkb_t *pkb);
struct _vacc_host;
int rn_pkb_recv(rn_pkb_t *pkb, int recv_len, struct _vacc_host *vacc_host);
int rn_pkb_send(rn_pkb_t *pkb, int send_len, struct _vacc_host *vacc_host);

/*
 * public socket mngr
 */
typedef struct {
    vacc_host_t     vacc_host;
    rn_listhead_t   list_entry;
    int             conn_id;
    uint32_t        listen_port;
    uint32_t        connect_port;
} rn_socket_public_t;

struct _rn_socket_mngr;

typedef int (*rn_socket_init_cb)(struct _rn_socket_mngr *mngr, rn_socket_public_t *socket, void *cb_param);
typedef int (*rn_socket_uninit_cb)(struct _rn_socket_mngr *mngr, rn_socket_public_t *socket, void *cb_param);

typedef struct _rn_socket_mngr {
    uint32_t        unit_num;
    uint32_t        unit_size;          /* size of struct which contain rn_socket_public_t */
    rn_gpfifo_t     *free_fifo;
    rn_socket_public_t      *socket_list;

    rn_socket_init_cb       socket_init;
    rn_socket_uninit_cb     socket_uninit;
    void                    *cb_param;

    int             n_listen;
    rn_listhead_t   listen_list;
    int             n_srv_inst;
    rn_listhead_t   srv_inst_list;
    int             n_client_inst;
    rn_listhead_t   client_inst_list;
    /* socket instance list */
} rn_socket_mngr_t;

#define RN_SOCKET_ENTRY(mngr, idx)      ((void *)((mngr)->socket_list) + (idx) * (mngr)->unit_size)

int rn_socket_mngr_create(rn_socket_mngr_t *mngr, rn_socket_public_t *socket_list, uint32_t unit_num, uint32_t unit_size, rn_socket_init_cb socket_init, rn_socket_uninit_cb socket_uninit, void *cb_param);
int rn_socket_mngr_destroy(rn_socket_mngr_t *mngr);
int rn_socket_mngr_listen_add(rn_socket_mngr_t *mngr, char *ip, uint16_t port, uint32_t sock_bufsize);
int rn_socket_mngr_connect(rn_socket_mngr_t *mngr, char *ip, uint16_t port, uint32_t sock_bufsize, rn_socket_public_t **connected_socket);
void rn_socket_mngr_dump(rn_socket_mngr_t *mngr);

#endif

