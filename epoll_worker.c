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
    int i;
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

    for (i = 0; i < FGFW_TIMERFW_MAXTIMER; i++) {
        if (epoll_thread->timer_list[i].valid) {
            close(epoll_thread->timer_list[i].timer_fd);
        }
    }
    epoll_thread->n_timer = 0;

    return FGFW_RETVALUE_OK;
}

static int fgfw_epoll_thread_reg_inst_ex(fgfw_epoll_thread_t *epoll_thread, fgfw_epoll_inst_t *epoll_inst, int is_edge_trigger)
{
    struct epoll_event event;
    int ret;

    event.data.ptr = epoll_inst;
    event.events = EPOLLIN | (is_edge_trigger ? EPOLLET : 0);
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

int fgfw_epoll_thread_reg_inst(fgfw_epoll_thread_t *epoll_thread, fgfw_epoll_inst_t *epoll_inst)
{
    return fgfw_epoll_thread_reg_inst_ex(epoll_thread, epoll_inst, 0);
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

static void fgfw_timerfw_public_cb(fgfw_epoll_inst_t *epoll_inst)
{
    fgfw_timerfw_timer_t *timer_inst = FGFW_GETCONTAINER(epoll_inst, fgfw_timerfw_timer_t, epoll_inst);
    int ret;
    uint64_t exp;

    fgfw_assert(timer_inst->timer_fd == epoll_inst->fd);

    if (!timer_inst->valid) {
        return;
    }

    ret = read(timer_inst->timer_fd, &exp, sizeof(uint64_t));
    if (ret != sizeof(uint64_t)) {
        fgfw_err("read return invalid len %d, %d(%s)\n", ret, errno, strerror(errno));
    } else {
        timer_inst->cb(timer_inst->cb_param);
    }
}

int fgfw_timerfw_add_timer(fgfw_epoll_thread_t *ctx, uint64_t first_us, uint64_t interval_us, fgfw_timerfw_cb_func cb, void *cb_param)
{
    int i;
    fgfw_timerfw_timer_t *timer_inst = NULL;

    for (i = 0; i < FGFW_TIMERFW_MAXTIMER; i++) {
        if (!ctx->timer_list[i].valid) {
            timer_inst = &(ctx->timer_list[i]);
            break;
        }
    }
    if (timer_inst == NULL) {
        fgfw_err("no enough timer resource.\n");
        return FGFW_RETVALUE_NOENOUGHRES;
    }

    timer_inst->timer_fd = timerfd_create(CLOCK_MONOTONIC, TFD_CLOEXEC);
    if (timer_inst->timer_fd < 0) {
        fgfw_err("failed timerfd_create, errno %d(%s)\n", errno, strerror(errno));
        return -3;
    }

    timer_inst->timer.it_value.tv_sec = first_us / 1000000;
    timer_inst->timer.it_value.tv_nsec = (first_us % 1000000) * 1000 + 1;
    timer_inst->timer.it_interval.tv_sec = interval_us / 1000000;
    timer_inst->timer.it_interval.tv_nsec = (interval_us % 1000000) * 1000;

    if (timerfd_settime(timer_inst->timer_fd, 0, &(timer_inst->timer), NULL)) {
        close(timer_inst->timer_fd);
        memset(timer_inst, 0, sizeof(fgfw_timerfw_timer_t));
        fgfw_err("failed timerfd_settime, errno %d(%s)\n", errno, strerror(errno));
        return -4;
    }

    timer_inst->cb = cb;
    timer_inst->cb_param = cb_param;

    timer_inst->epoll_inst.fd = timer_inst->timer_fd;
    timer_inst->epoll_inst.epoll_inst_cb = fgfw_timerfw_public_cb;

    fgfw_epoll_thread_reg_inst_ex(ctx, &(timer_inst->epoll_inst), 1);

    timer_inst->valid = 1;

    ctx->n_timer++;

    return i;
}

int fgfw_timerfw_del_timer(fgfw_epoll_thread_t *ctx, int idx)
{
    fgfw_timerfw_timer_t *timer_inst = &(ctx->timer_list[idx]);

    if (idx >= FGFW_TIMERFW_MAXTIMER) {
        return FGFW_RETVALUE_INVALID_PARAM;
    }

    if (!timer_inst->valid) {
        return FGFW_RETVALUE_TIMER_NOT_READY;
    }

    fgfw_epoll_thread_reg_uninst(ctx, &(timer_inst->epoll_inst));

    close(timer_inst->timer_fd);
    timer_inst->valid = 0;
    memset(timer_inst, 0, sizeof(fgfw_timerfw_timer_t));

    return FGFW_RETVALUE_OK;
}