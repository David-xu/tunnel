#ifndef _EPOLL_WORKER_H_
#define _EPOLL_WORKER_H_

#define RN_EPOLL_THREAD_MAX_INST_IN_SUBPROC_CRTHREAD                (2 * 1024)
typedef struct _rn_epoll_inst {
    /* set by epoll thread framework */
    struct _rn_epoll_thread *epoll_thread;
    rn_listhead_t node;
    uint32_t reg_events;

    /* set by user */
    void (*epoll_inst_cb)(struct _rn_epoll_inst *epoll_inst);
    int fd;
} rn_epoll_inst_t;

#define RN_TIMERFW_MAXTIMER                 64

typedef int (*rn_timerfw_cb_func)(void *param);

typedef struct {
    rn_epoll_inst_t         epoll_inst;
    int                     valid;
    int                     timer_fd;
    struct itimerspec       timer;
    rn_timerfw_cb_func      cb;
    void                    *cb_param;
} rn_timerfw_timer_t;

typedef struct _rn_epoll_thread {
    int epoll_fd;
    pthread_t t;

    volatile int shutdown;

    int n_inst;
    rn_listhead_t inst_list_head;

    int                     n_timer;
    rn_timerfw_timer_t      timer_list[RN_TIMERFW_MAXTIMER];
} rn_epoll_thread_t;

int rn_epoll_thread_create(rn_epoll_thread_t *epoll_thread);
int rn_epoll_thread_destroy(rn_epoll_thread_t *epoll_thread);
/*
 *  epoll_inst need init first, epoll_inst->fd, epoll
 */
int rn_epoll_thread_reg_inst(rn_epoll_thread_t *epoll_thread, rn_epoll_inst_t *epoll_inst);
int rn_epoll_thread_reg_uninst(rn_epoll_thread_t *epoll_thread, rn_epoll_inst_t *epoll_inst);

/*
 *
 */
int rn_timerfw_add_timer(rn_epoll_thread_t *epoll_thread, uint64_t first_us, uint64_t interval_us, rn_timerfw_cb_func cb, void *cb_param);
int rn_timerfw_del_timer(rn_epoll_thread_t *epoll_thread, int idx);

#endif