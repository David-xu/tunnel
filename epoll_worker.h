#ifndef _EPOLL_WORKER_H_
#define _EPOLL_WORKER_H_

typedef struct _fgfw_epoll_thread {
    int epoll_fd;
    pthread_t t;

    volatile int running;

    int n_inst;
    fgfw_listhead_t inst_list_head;
} fgfw_epoll_thread_t;

typedef struct _fgfw_epoll_inst {
    /* set by epoll thread framework */
    fgfw_epoll_thread_t *epoll_thread;
    fgfw_listhead_t node;
    uint32_t reg_events;

    /* set by user */
    void (*epoll_inst_cb)(struct _fgfw_epoll_inst *epoll_inst);
    int fd;
} fgfw_epoll_inst_t;

int fgfw_epoll_thread_create(fgfw_epoll_thread_t *epoll_thread);
int fgfw_epoll_thread_destroy(fgfw_epoll_thread_t *epoll_thread);
/*
 *  epoll_inst need init first, epoll_inst->fd, epoll
 */
int fgfw_epoll_thread_reg_inst(fgfw_epoll_thread_t *epoll_thread, fgfw_epoll_inst_t *epoll_inst);
int fgfw_epoll_thread_reg_uninst(fgfw_epoll_thread_t *epoll_thread, fgfw_epoll_inst_t *epoll_inst);

#endif