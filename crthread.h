#ifndef CRTHREAD_T
#define CRTHREAD_T

#include <stdint.h>
#include <ucontext.h>

/*********************************
 *multi-thread based on ucontext
 *
 */
// #define CRTHREAD_DEBUG
#define CRTHREAD_SWAPTIME_STAT

struct _crthread_tcb;
struct _crthread_scheduler;
typedef int (*thread_func)(struct _crthread_tcb *tcb, void *p);
typedef void (*tdump_func)(struct _crthread_tcb *tcb, void *p);

typedef struct _crthread_semaphore {
    int                             v;
    uint32_t                        n_wait;
    fgfw_listhead_t                waitlist;
} crthread_semaphore_t;

typedef struct _crthread_tcb{
    ucontext_t      ctx;
    void            *stack;

    void            *param;
    thread_func     tf;
    tdump_func      tdf;

    uint64_t        entrance_tm;        /* ns */

    struct {
        uint64_t    timestamp;          /* ns */
        uint64_t    delay;              /* ns */
    } tp;

    uint64_t        flag;
    int             idx;

    /* debug info */
    const char      *funcname;
    size_t          line;

    /* dual link list node */
    fgfw_listhead_t    node;
    struct _crthread_scheduler  *s;

    /*  */
    crthread_semaphore_t    *sem;
    fgfw_listhead_t    waitlist_node;  /* attach in sem's waitlist */
    int                 sem_ret;
} crthread_tcb_t;

#define CRTHREAD_MAX_THREAD_NUM     16
#define CRTHREAD_IDLE_TID           0
#define CRTHREAD_STACKSIZE          (2 * 1024 * 1024)
#define CRTHREAD_STACKMARGIN        0x80

typedef struct _crthread_scheduler {
    fgfw_listhead_t        running;
    fgfw_listhead_t        sleeping;
    fgfw_listhead_t        blocked;
    fgfw_listhead_t        zombie;
    fgfw_listhead_t        free;

    crthread_tcb_t  *idle;
    crthread_tcb_t  *cur;

    crthread_tcb_t  tcb_array[CRTHREAD_MAX_THREAD_NUM];
    uint8_t         stack[CRTHREAD_STACKSIZE * CRTHREAD_MAX_THREAD_NUM];

#ifdef CRTHREAD_SWAPTIME_STAT
    struct {
#define CRTHREAD_SWAPDELTA_TOTAL        64
        uint64_t    swap_delta[CRTHREAD_SWAPDELTA_TOTAL];
        uint32_t    idx;
    } swap_stat;
#endif
} crthread_scheduler_t;
int crthread_init_scheduler(crthread_scheduler_t *s);
crthread_tcb_t* crthread_create_dbg(crthread_scheduler_t *s, thread_func func, tdump_func tdf, void *param, const char *funcname, size_t line);
#define crthread_create(s, func, param)         crthread_create_dbg(s, func, NULL, param, __FUNCTION__, __LINE__)
#define crthread_create_ex(s, func, dumpfunc, param)         crthread_create_dbg(s, func, dumpfunc, param, __FUNCTION__, __LINE__)
void crthread_launch(crthread_tcb_t *tcb);
static inline int crthread_tid(crthread_scheduler_t *s, crthread_tcb_t *tcb)
{
    return (int)(tcb - s->tcb_array);
}
void crthread_run(crthread_scheduler_t *s, volatile int *shutdown);
void crthread_yield(crthread_tcb_t *curr);
void crthread_usleep(crthread_tcb_t *curr, uint64_t us);
void crthread_init_sem(crthread_semaphore_t *sem);
void crthread_sem_up(crthread_tcb_t *curr, crthread_semaphore_t *sem, uint32_t v);
int crthread_sem_down(crthread_tcb_t *curr, crthread_semaphore_t *sem, uint32_t timeout_us);

#ifdef CRTHREAD_SWAPTIME_STAT
void curthread_dump_swap_stat(crthread_scheduler_t *s);
#else
static inline void curthread_dump_swap_stat(crthread_scheduler_t *s) {}
#endif

#ifdef CRTHREAD_DEBUG
void crthread_testmain(void);
#else
static inline void crthread_testmain(void) {}
#endif

#endif

