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

typedef struct {
    int     free, max;
} single_token_bucket_t;

static int __attribute__((unused)) single_token_bucket_init(single_token_bucket_t *stb, int free, int max)
{
    stb->free = free;
    stb->max = max;
    return 0;
}

static int __attribute__((unused)) single_token_bucket_insert(single_token_bucket_t *stb, int n_token)
{
    stb->free += n_token;
    if (stb->free > stb->max) {
        stb->free = stb->max;
    }

    return 0;
}
/* return: number of token consumed */
static int __attribute__((unused)) single_token_bucket_consume(single_token_bucket_t *stb, int n_token)
{
    if (n_token > stb->free) {
        n_token = stb->free;
    }

    stb->free -= n_token;
    return n_token;
}

#endif