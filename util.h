#ifndef _UTIL_H_
#define _UTIL_H_

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

#endif