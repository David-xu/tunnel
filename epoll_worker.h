#ifndef _EPOLL_WORKER_H_
#define _EPOLL_WORKER_H_

struct _fgfw_epoll_thread;

typedef struct _fgfw_epoll_inst {
    /* set by epoll thread framework */
    struct _fgfw_epoll_thread *epoll_thread;
    fgfw_listhead_t node;
    uint32_t reg_events;

    /* set by user */
    void (*epoll_inst_cb)(struct _fgfw_epoll_inst *epoll_inst);
    int fd;
} fgfw_epoll_inst_t;

#define FGFW_TIMERFW_MAXTIMER               64

typedef int (*fgfw_timerfw_cb_func)(void *param);

typedef struct {
    fgfw_epoll_inst_t       epoll_inst;
    int                     valid;
    int                     timer_fd;
    struct itimerspec       timer;
    fgfw_timerfw_cb_func    cb;
    void                    *cb_param;
} fgfw_timerfw_timer_t;

typedef struct _fgfw_epoll_thread {
    int epoll_fd;
    pthread_t t;

    volatile int running;

    int n_inst;
    fgfw_listhead_t inst_list_head;

    int                     n_timer;
    fgfw_timerfw_timer_t    timer_list[FGFW_TIMERFW_MAXTIMER];
} fgfw_epoll_thread_t;

int fgfw_epoll_thread_create(fgfw_epoll_thread_t *epoll_thread);
int fgfw_epoll_thread_destroy(fgfw_epoll_thread_t *epoll_thread);
/*
 *  epoll_inst need init first, epoll_inst->fd, epoll
 */
int fgfw_epoll_thread_reg_inst(fgfw_epoll_thread_t *epoll_thread, fgfw_epoll_inst_t *epoll_inst);
int fgfw_epoll_thread_reg_uninst(fgfw_epoll_thread_t *epoll_thread, fgfw_epoll_inst_t *epoll_inst);

/*
 *
 */
int fgfw_timerfw_add_timer(fgfw_epoll_thread_t *epoll_thread, uint64_t first_us, uint64_t interval_us, fgfw_timerfw_cb_func cb, void *cb_param);
int fgfw_timerfw_del_timer(fgfw_epoll_thread_t *epoll_thread, int idx);

#endif