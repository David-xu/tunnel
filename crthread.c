#include "pub.h"

/*********************************
 *multi-thread based on ucontext
 *
 */
static inline void crthread_dump_threadinfo(crthread_tcb_t *tcb, char *prefix)
{
    crthread_scheduler_t *s = tcb->s;

    fgfw_log("%stid: %ld, %-24s %4d, param %p\n", prefix ? prefix : "",
        crthread_tid(s, tcb), tcb->funcname, tcb->line, tcb->param);
    if (tcb->tdf) {
        tcb->tdf(tcb, tcb->param);
    }
}

void crthread_dump_linklist(crthread_scheduler_t *s, uint32_t type)
{
    crthread_tcb_t *p;
    int i;

    if (type & 0x1) {
        fgfw_log("running list:\n");
        i = 0;
        FGFW_LISTENTRYWALK(p, &(s->running), node) {
            if (type & 0x10000) {
                crthread_dump_threadinfo(p, "\t");
            }
            i++;
        }
        fgfw_log("running total: %d\n", i);
    }

    if (type & 0x2) {
        fgfw_log("sleeping list:\n");
        i = 0;
        FGFW_LISTENTRYWALK(p, &(s->sleeping), node) {
            if (type & 0x20000) {
                crthread_dump_threadinfo(p, "\t");
            }
            i++;
        }
        fgfw_log("sleeping total: %d\n", i);
    }

    if (type & 0x4) {
        fgfw_log("blocked list:\n");
        i = 0;
        FGFW_LISTENTRYWALK(p, &(s->blocked), node) {
            if (type & 0x40000) {
                crthread_dump_threadinfo(p, "\t");
            }
            i++;
        }
        fgfw_log("blocked total: %d\n", i);
    }

    if (type & 0x8) {
        fgfw_log("free:\n");
        i = 0;
        FGFW_LISTENTRYWALK(p, &(s->free), node) {
            if (type & 0x80000) {
                crthread_dump_threadinfo(p, "\t");
            }
            i++;
        }
        fgfw_log("free total: %d\n", i);
    }

    if (type & 0x10) {
        fgfw_log("zombie:\n");
        i = 0;
        FGFW_LISTENTRYWALK(p, &(s->zombie), node) {
            if (type & 0x100000) {
                crthread_dump_threadinfo(p, "\t");
            }
            i++;
        }
        fgfw_log("zombie total: %d\n", i);
    }
}

void crthread_dump_sem(crthread_scheduler_t *s, crthread_semaphore_t *sem)
{
    int i;
    crthread_tcb_t *p;
    fgfw_log("sem v %d, n_wait %d\n", sem->v, sem->n_wait);
    fgfw_log("waitlist:\n");
    i = 0;
    FGFW_LISTENTRYWALK(p, &(sem->waitlist), waitlist_node) {
        crthread_dump_threadinfo(p, "\t");
        i++;
    }
    fgfw_log("waitlist total: %d\n", i);
}

#ifdef CRTHREAD_SWAPTIME_STAT
void curthread_dump_swap_stat(crthread_scheduler_t *s)
{
    uint64_t total = 0;
    int i;
    for (i = 0; i < CRTHREAD_SWAPDELTA_TOTAL; i++) {
        total += s->swap_stat.swap_delta[i];
    }
    fgfw_log("avrg swap time %d ns.\n", total / CRTHREAD_SWAPDELTA_TOTAL);
}
#endif

static crthread_tcb_t *get_next_crthread(crthread_scheduler_t *s, crthread_tcb_t *curr)
{
    crthread_tcb_t *next;

    if (FGFW_LISTISEMPLY(&(s->running))) {
        return NULL;
    }

    next = FGFW_GETCONTAINER(s->running.next, crthread_tcb_t, node);

    return next;
}

static inline uint64_t get_timestamp(void)
{
    struct timespec tm;
    clock_gettime(CLOCK_REALTIME, &tm);

    return tm.tv_sec * 1000000000ULL + tm.tv_nsec;
}

static void sem_wakeup(crthread_tcb_t *curr, int sem_ret)
{
    crthread_scheduler_t *s = curr->s;
    crthread_semaphore_t *sem = curr->sem;

    fgfw_assert(sem != NULL);

    /* move this task from blocked list to running list */
    fgfw_listdel(&(curr->node));
    fgfw_listadd_tail(&(curr->node), &(s->running));

    /* dettach from sem's waitlist */
    sem->n_wait--;
    fgfw_listdel(&(curr->waitlist_node));
    curr->sem_ret = sem_ret;
    curr->sem = NULL;
}

static void pre_sched(crthread_tcb_t *curr)
{
    crthread_scheduler_t *s = curr->s;
    crthread_tcb_t *p, *n;
    uint64_t tm = get_timestamp();

    curr->entrance_tm = tm;

    /* timeout wakeup */
    FGFW_LISTENTRYWALK_SAVE(p, n, &(s->sleeping), node)
    {
        if ((tm - p->tp.timestamp) >= p->tp.delay) {
            /* move this task from sleepling list to running list */
            fgfw_listdel(&(p->node));
            fgfw_listadd_tail(&(p->node), &(s->running));
        }
    }

    FGFW_LISTENTRYWALK_SAVE(p, n, &(s->blocked), node)
    {
        if (p->tp.delay == 0) {
            continue;
        }

        if ((tm - p->tp.timestamp) >= p->tp.delay) {
            p->sem->v++;
            sem_wakeup(p, -1);      /* sem timeout, return -1 */
        }
    }
}

static void schedule(crthread_tcb_t *curr, fgfw_listhead_t *dstlist)
{
    crthread_scheduler_t *s = curr->s;
    crthread_tcb_t *next;

    next = get_next_crthread(s, curr);
    if (next == NULL) {
        /* do nothing, just cotinue current task */
        return;
    }

    /* remove next from running list */
    fgfw_listdel(&(next->node));
    /* add curr to dst list */
    fgfw_listadd_tail(&(curr->node), dstlist);

#ifdef CRTHREAD_SWAPTIME_STAT
    /* swap time stat */
    s->swap_stat.swap_delta[s->swap_stat.idx] = get_timestamp() - curr->entrance_tm;
    s->swap_stat.idx = (s->swap_stat.idx + 1) % CRTHREAD_SWAPDELTA_TOTAL;
#endif
    fgfw_assert(curr == s->cur);

    swapcontext(&(curr->ctx), &(next->ctx));

    // fgfw_log("############  (old)%d -----> (new)%d\n", s->cur->idx, curr->idx);

    s->cur = curr;
}

static void pub_entry(crthread_tcb_t *curr)
{
    crthread_scheduler_t *s = curr->s;
    crthread_tcb_t *next;

    // fgfw_log("#####  %d start......\n", curr->idx);
    s->cur = curr;

    curr->tf(curr, curr->param);

    /* thread exit, switch to next and free this tcb */

    /* insert into zombie list */
    fgfw_listadd_tail(&(curr->node), &(s->zombie));

    /* switch context */
    next = get_next_crthread(s, curr);
    fgfw_listdel(&(next->node));
    swapcontext(&(curr->ctx), &(next->ctx));

    //
    fgfw_err("out of control...\n");
    fgfw_assert(0);
}

int crthread_init_scheduler(crthread_scheduler_t *s)
{
    int i;
    crthread_tcb_t *tcb;

    memset(s, 0, sizeof(crthread_scheduler_t));

    fgfw_initlisthead(&(s->running));
    fgfw_initlisthead(&(s->sleeping));
    fgfw_initlisthead(&(s->blocked));
    fgfw_initlisthead(&(s->zombie));
    fgfw_initlisthead(&(s->free));

    for (i = 0 ; i < CRTHREAD_MAX_THREAD_NUM; i++) {
        tcb = &(s->tcb_array[i]);
        tcb->stack = s->stack + i * CRTHREAD_STACKSIZE;
        tcb->s = s;
        tcb->idx = i;
        fgfw_listadd_tail(&(tcb->node), &(s->free));
    }

    s->idle = crthread_create(s, NULL, NULL);
    crthread_launch(s->idle);
    s->cur = s->idle;
    fgfw_listdel(&(s->idle->node));

    return 0;
}

crthread_tcb_t* crthread_create_dbg(crthread_scheduler_t *s, thread_func func, tdump_func tdf, void *param, const char *funcname, size_t line)
{
    crthread_tcb_t *newtcb;
    if (FGFW_LISTISEMPLY(&(s->free))) {
        return NULL;
    }

    newtcb = FGFW_GETCONTAINER(s->free.next, crthread_tcb_t, node);
    fgfw_listdel(&(newtcb->node));

    newtcb->param = param;
    newtcb->tf = func;
    newtcb->tdf = tdf;

    newtcb->funcname = funcname;
    newtcb->line = line;

    return newtcb;
}

void crthread_launch(crthread_tcb_t *tcb)
{
    crthread_scheduler_t *s = tcb->s;
    memset(&(tcb->ctx), 0, sizeof(ucontext_t));
    getcontext(&(tcb->ctx));
    tcb->ctx.uc_stack.ss_sp = tcb->stack;
    tcb->ctx.uc_stack.ss_size = CRTHREAD_STACKSIZE - CRTHREAD_STACKMARGIN;
    makecontext(&(tcb->ctx), (void (*)(void))pub_entry, 1, tcb);
    fgfw_listadd_tail(&(tcb->node), &(s->running));
}

void crthread_run(crthread_scheduler_t *s, volatile int *shutdown)
{
    crthread_tcb_t *p, *n;

    /* main idle task */
    while (*shutdown == 0) {
        crthread_yield(s->idle);
        /*  */
        if (!FGFW_LISTISEMPLY(&(s->zombie))) {
            FGFW_LISTENTRYWALK_SAVE(p, n, &(s->zombie), node) {
                crthread_dump_threadinfo(p, "reclaim... ");

                p->param = NULL;
                p->tf = NULL;
                fgfw_listdel(&(p->node));
                fgfw_listadd_tail(&(p->node), &(s->free));
            }
        }
    }
}

void crthread_yield(crthread_tcb_t *curr)
{
    crthread_scheduler_t *s = curr->s;

    pre_sched(curr);
    /* curr task move to running list */
    schedule(curr, &(s->running));
}

void crthread_usleep(crthread_tcb_t *curr, uint64_t us)
{
    crthread_scheduler_t *s = curr->s;

    pre_sched(curr);

    curr->tp.timestamp = curr->entrance_tm;
    curr->tp.delay = us * 1000;

    /* curr task move to sleeping list */
    schedule(curr, &(s->sleeping));
}

void crthread_init_sem(crthread_semaphore_t *sem)
{
    memset(sem, 0, sizeof(crthread_semaphore_t));
    fgfw_initlisthead(&(sem->waitlist));
}

void crthread_sem_up(crthread_tcb_t *curr, crthread_semaphore_t *sem, uint32_t v)
{
    crthread_tcb_t *p, *n;

    if (v == 0) {
        //
        fgfw_log("v == 0\n");
        return;
    }

    sem->v += v;

    /*  */
    FGFW_LISTENTRYWALK_SAVE(p, n, &(sem->waitlist), waitlist_node)
    {
        /* wakeup */
        sem_wakeup(p, 0);

        v--;

        if (v == 0) {
            break;
        }
    }
}

int crthread_sem_down(crthread_tcb_t *curr, crthread_semaphore_t *sem, uint32_t timeout_us)
{
    crthread_scheduler_t *s = curr->s;

    pre_sched(curr);

    sem->v--;
    curr->sem_ret = 0;

    if (sem->v < 0) {
        sem->n_wait++;
        curr->sem = sem;
        fgfw_listadd_tail(&(curr->waitlist_node), &(sem->waitlist));

        /* if timeout_us == 0, never timeout, wait forever */
        curr->tp.timestamp = curr->entrance_tm;
        curr->tp.delay = timeout_us * 1000ULL;

        /*  */
        schedule(curr, &(s->blocked));
    }

    return curr->sem_ret;
}

#ifdef CRTHREAD_DEBUG
int test_thread(crthread_tcb_t *tcb, void *param)
{
    // crthread_scheduler_t *s = tcb->s;
    int loops = 4;
    // uint64_t v = IOHUB_P2V(param);
    while (loops--) {
        // iohub_log("thread %ld, loops %d\n", v, loops);
#if 0
        clock_gettime(CLOCK_REALTIME, &g_tvlist[n_tv]);
        n_tv++;
#endif
        // yield(tcb);
        crthread_usleep(tcb, 500000);
    }

    // launch_crthread(create_crthread(s, test_thread, IOHUB_V2P(v + 10)));
    return 0;
}

int test_thread2(crthread_tcb_t *tcb, void *param)
{
    // crthread_scheduler_t *s = tcb->s;
    int loops = 100;
    uint64_t v = IOHUB_P2V(param);
    while (loops--) {
        fgfw_log("thread %ld, loops %d\n", v, loops);
        // yield(tcb);
        crthread_usleep(tcb, 5000);
    }

    return 0;
}

void test_00(crthread_scheduler_t *s)
{
    crthread_launch(crthread_create(s, test_thread, IOHUB_V2P(0)));
    crthread_launch(crthread_create(s, test_thread, IOHUB_V2P(1)));
    crthread_launch(crthread_create(s, test_thread, IOHUB_V2P(2)));
    crthread_launch(crthread_create(s, test_thread, IOHUB_V2P(3)));
    crthread_launch(crthread_create(s, test_thread, IOHUB_V2P(4)));
    crthread_launch(crthread_create(s, test_thread, IOHUB_V2P(5)));
    crthread_launch(crthread_create(s, test_thread, IOHUB_V2P(6)));
    crthread_launch(crthread_create(s, test_thread, IOHUB_V2P(7)));
    crthread_launch(crthread_create(s, test_thread2, IOHUB_V2P(8)));
}

int test_thread_01(crthread_tcb_t *tcb, void *param)
{
    int ret;
    crthread_semaphore_t *sem = (crthread_semaphore_t *)param;
    while (1) {
        ret = crthread_sem_down(tcb, sem, 0);
        fgfw_log("0 down ret %d\n", ret);
    }

    return 0;
}

int test_thread_03(crthread_tcb_t *tcb, void *param)
{
    int ret;
    crthread_semaphore_t *sem = (crthread_semaphore_t *)param;
    while (1) {
        ret = crthread_sem_down(tcb, sem, 0);
        fgfw_log("1 down ret %d\n", ret);
    }

    return 0;
}

int test_thread_02(crthread_tcb_t *tcb, void *param)
{
    crthread_semaphore_t *sem = (crthread_semaphore_t *)param;
    while (1) {
        crthread_usleep(tcb, 500000);
        crthread_sem_up(tcb, sem, 1);
    }

    return 0;
}

static crthread_semaphore_t test_sem;
void test_01(crthread_scheduler_t *s)
{
    crthread_init_sem(&test_sem);

    crthread_launch(crthread_create(s, test_thread_01, &test_sem));
    crthread_launch(crthread_create(s, test_thread_02, &test_sem));
    crthread_launch(crthread_create(s, test_thread_03, &test_sem));
}

static crthread_scheduler_t g_s;
void crthread_testmain(void)
{
    int shutdown = 0;
    crthread_init_scheduler(&g_s);

    test_00(&g_s);
    test_01(&g_s);

    crthread_run(&g_s, &shutdown);
}
#endif

