#ifndef _UTIL_H_
#define _UTIL_H_

#define FGFW_P2V(p)                        ((char *)(p) - (char *)0)
#define FGFW_V2P(v)                        ((void *)((char *)0 + (v)))
#define FGFW_OFFSETOF(strtype, field)      FGFW_P2V(&(((strtype *)0)->field))

#define	FGFW_GETCONTAINER(p, type, field)              \
    ((type *)FGFW_V2P(FGFW_P2V(p) - FGFW_OFFSETOF(type, field)))

#define	FGFW_LISTISEMPLY(head)             ((head) == ((head)->next))

typedef struct _fgfw_listhead {
    struct _fgfw_listhead          *prev;
    struct _fgfw_listhead          *next;
} fgfw_listhead_t;

#define FGFW_LISTWALK(p, head) for (p = (head)->next; p != (head); p = p->next)

#define FGFW_LISTWALK_SAVE(p, n, head) \
    for (p = (head)->next, n = p->next; p != (head); p = n, n = p->next)

#define FGFW_LISTENTRYWALK(p, head, field) \
    for (p = FGFW_GETCONTAINER((head)->next, typeof(*p), field); \
        &(p->field) != (head); \
        p = FGFW_GETCONTAINER((p)->field.next, typeof(*p), field))

#define FGFW_LISTENTRYWALK_SAVE(p, n, head, field) \
    for (p = FGFW_GETCONTAINER((head)->next, typeof(*p), field), \
        n = FGFW_GETCONTAINER((head)->next->next, typeof(*p), field); \
        &(p->field) != (head); \
        p = n, n = FGFW_GETCONTAINER(p->field.next, typeof(*p), field))

static inline void fgfw_initlisthead(fgfw_listhead_t *head)
{
    head->next = head->prev = head;
}

static inline void fgfw_listadd_(fgfw_listhead_t *p, fgfw_listhead_t *prev, fgfw_listhead_t *next)
{
    prev->next = p;
    p->prev = prev;
    p->next = next;
    next->prev = p;
}

static inline void fgfw_listdel_(fgfw_listhead_t *prev, fgfw_listhead_t *next)
{
    prev->next = next;
    next->prev = prev;
}

/* add the element @p to head */
static inline void fgfw_listadd(fgfw_listhead_t *p, fgfw_listhead_t *head)
{
    fgfw_listadd_(p, head, head->next);
}
static inline void fgfw_listadd_tail(fgfw_listhead_t *p, fgfw_listhead_t *head)
{
    fgfw_listadd_(p, head->prev, head);
}

static inline void fgfw_listdel(fgfw_listhead_t *p)
{
    if (!FGFW_LISTISEMPLY(p)) {
        fgfw_listdel_(p->prev, p->next);
    }
}

/* utils */
int qemu_time_millis_now_raw(unsigned long *now);
int time_string_now_raw(char *buf);

int fgfw_printf(const char *fmt, ...);

void fgfw_aes_encrypt(const unsigned char *key, const unsigned char *input, unsigned char *output);
void fgfw_aes_decrypt(const unsigned char *key, const unsigned char *input, unsigned char *output);

/*
 * ret: 1 --> overlap
 */
static inline int fgfw_isrange_overlap(__uint128_t begin1, __uint128_t size1, __uint128_t begin2, __uint128_t size2)
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

static inline char fgfw_n2c(uint32_t v)
{
    return (v > 9) ? ('A' + v - 10) : ('0' + v);
}

static inline int fgfw_c2n(char c)
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

void fgfw_hexdump(const void *buf, uint32_t len);

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
    if (n_token > stb->free) {
        n_token = stb->free;
    }

    stb->free -= n_token;
    return n_token;
}

typedef struct {
    fgfw_listhead_t         node;
    uint64_t                base;
    uint64_t                size;
} fgfw_range_res_node_t;

typedef struct {
    fgfw_listhead_t        freelist;            /* free node list */
    uint64_t                base;
    uint64_t                size;
    uint64_t                free;
    uint32_t                n_node;

    uint32_t                putget_cnt;
} fgfw_range_res_t;

#define FGFW_RANGE_RES_INVALID          (-1ULL)
int fgfw_range_res_init(fgfw_range_res_t *mngr, uint64_t base, uint64_t size);
int fgfw_range_res_uninit(fgfw_range_res_t *mngr);
uint64_t fgfw_range_res_alloc(fgfw_range_res_t *mngr, uint64_t size);
int fgfw_range_res_alloc_specified(fgfw_range_res_t *mngr, uint64_t base, uint64_t *size);
void fgfw_range_res_free(fgfw_range_res_t *mngr, uint64_t base, uint64_t size);
void fgfw_range_res_dump(fgfw_range_res_t *mngr);
int fgfw_range_res_merge(fgfw_range_res_t *mngr, uint64_t base[2], uint64_t num[2], uint32_t dir);

#endif