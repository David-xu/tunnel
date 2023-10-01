#include "pub.h"

#define FGFW_MAX_EVENTS         1024

static void *epoll_thread_proc(void *arg)
{
    fgfw_epoll_thread_t *epoll_thread = (fgfw_epoll_thread_t *)arg;
    struct epoll_event events[FGFW_MAX_EVENTS];
    int idx, fds;

    while (epoll_thread->running) {
        fds = epoll_wait(epoll_thread->epoll_fd, events, FGFW_MAX_EVENTS, 1);
        for (idx = 0; idx < fds; idx++) {
            fgfw_epoll_inst_t *epoll_inst = (fgfw_epoll_inst_t *)events[idx].data.ptr;
            epoll_inst->epoll_inst_cb(epoll_inst);
        }
    }

    return NULL;
}

int fgfw_epoll_thread_create(fgfw_epoll_thread_t *epoll_thread)
{
    int flag;

    memset(epoll_thread, 0, sizeof(fgfw_epoll_thread_t));

    epoll_thread->n_inst = 0;
    fgfw_initlisthead(&(epoll_thread->inst_list_head));

    /* create epoll */
    epoll_thread->epoll_fd = epoll_create(1);
    if (epoll_thread->epoll_fd==-1)
    {
        fgfw_err("epoll_create failed.\n");
        return FGFW_RETVALUE_ERR;
    }
    flag = fcntl(epoll_thread->epoll_fd, F_GETFD);
    fcntl(epoll_thread->epoll_fd, F_SETFD, flag | FD_CLOEXEC);

    epoll_thread->running = 1;
    pthread_create(&(epoll_thread->t), NULL, epoll_thread_proc, (void *)epoll_thread);

    return FGFW_RETVALUE_OK;
}

int fgfw_epoll_thread_destroy(fgfw_epoll_thread_t *epoll_thread)
{
    fgfw_epoll_inst_t *p, *n;
    FGFW_LISTENTRYWALK_SAVE(p, n, &(epoll_thread->inst_list_head), node) {
        fgfw_epoll_thread_reg_uninst(epoll_thread, p);
    }

    /* stop thread */
    epoll_thread->running = 0;

    /* wait for epoll thread exit */
    pthread_join(epoll_thread->t, NULL);

    /* destroy epoll */
    close(epoll_thread->epoll_fd);

    return FGFW_RETVALUE_OK;
}

int fgfw_epoll_thread_reg_inst(fgfw_epoll_thread_t *epoll_thread, fgfw_epoll_inst_t *epoll_inst)
{
    struct epoll_event event;
    int ret;

    event.data.ptr = epoll_inst;
    event.events = EPOLLIN | EPOLLET;
    ret = epoll_ctl(epoll_thread->epoll_fd, EPOLL_CTL_ADD, epoll_inst->fd, &event);
    if (ret) {
        fgfw_err("epoll_ctl add faild %d\n", ret);
        return FGFW_RETVALUE_ERR;
    }

    epoll_inst->epoll_thread = epoll_thread;
    epoll_inst->reg_events = event.events;

    fgfw_listadd_tail(&(epoll_inst->node), &(epoll_thread->inst_list_head));
    epoll_thread->n_inst++;
    return FGFW_RETVALUE_OK;
}

int fgfw_epoll_thread_reg_uninst(fgfw_epoll_thread_t *epoll_thread, fgfw_epoll_inst_t *epoll_inst)
{
    fgfw_epoll_inst_t *p;
    struct epoll_event event;
    int ret, finded = 0;

    if (epoll_inst->epoll_thread != epoll_thread) {
        return FGFW_RETVALUE_INVALID_PARAM;
    }

    FGFW_LISTENTRYWALK(p, &(epoll_thread->inst_list_head), node) {
        if (p == epoll_inst) {
            break;
        }
    }
    if (finded == 0) {
        return FGFW_RETVALUE_ERR;
    }

    event.data.ptr = epoll_inst;
    event.events = epoll_inst->reg_events;
    ret = epoll_ctl(epoll_thread->epoll_fd, EPOLL_CTL_DEL, epoll_inst->fd, &event);
    if (ret) {
        fgfw_err("epoll_ctl del faild %d\n", ret);
    }

    fgfw_listdel(&(epoll_inst->node));
    epoll_thread->n_inst--;

    return FGFW_RETVALUE_OK;
}