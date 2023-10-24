#include "pub.h"

#define RN_MAX_EVENTS                   1024

static void *epoll_thread_proc(void *arg)
{
    rn_epoll_thread_t *epoll_thread = (rn_epoll_thread_t *)arg;
    struct epoll_event events[RN_MAX_EVENTS];
    int idx, fds;
    rn_epoll_inst_t *epoll_inst;

    while (epoll_thread->shutdown == 0) {
        fds = epoll_wait(epoll_thread->epoll_fd, events, RN_MAX_EVENTS, 1);
        if (fds < 0) {
            if (errno != EINTR) {
                rn_err("epoll_wait faild.\n");
            }
        } else {
            for (idx = 0; idx < fds; idx++) {
                epoll_inst = (rn_epoll_inst_t *)events[idx].data.ptr;

                epoll_inst->epoll_inst_cb(epoll_inst);
            }
        }
    }

    rn_log("epoll main loop exit.\n");

    return NULL;
}

int rn_epoll_thread_create(rn_epoll_thread_t *epoll_thread)
{
    int flag;

    memset(epoll_thread, 0, sizeof(rn_epoll_thread_t));

    epoll_thread->n_inst = 0;
    rn_initlisthead(&(epoll_thread->inst_list_head));

    /* create epoll */
    epoll_thread->epoll_fd = epoll_create(1);
    if (epoll_thread->epoll_fd==-1)
    {
        rn_err("epoll_create failed.\n");
        return RN_RETVALUE_ERR;
    }
    flag = fcntl(epoll_thread->epoll_fd, F_GETFD);
    fcntl(epoll_thread->epoll_fd, F_SETFD, flag | FD_CLOEXEC);

    epoll_thread->shutdown = 0;
    pthread_create(&(epoll_thread->t), NULL, epoll_thread_proc, (void *)epoll_thread);

    return RN_RETVALUE_OK;
}

int rn_epoll_thread_destroy(rn_epoll_thread_t *epoll_thread)
{
    int i;
    rn_epoll_inst_t *p, *n;

    RN_LISTENTRYWALK_SAVE(p, n, &(epoll_thread->inst_list_head), node) {
        rn_epoll_thread_reg_uninst(epoll_thread, p);
    }

    /* stop thread */
    epoll_thread->shutdown = 1;

    /* wait for epoll thread exit */
    pthread_join(epoll_thread->t, NULL);

    /* destroy epoll */
    close(epoll_thread->epoll_fd);

    for (i = 0; i < RN_TIMERFW_MAXTIMER; i++) {
        if (epoll_thread->timer_list[i].valid) {
            close(epoll_thread->timer_list[i].timer_fd);
        }
    }
    epoll_thread->n_timer = 0;

    return RN_RETVALUE_OK;
}

static int rn_epoll_thread_reg_inst_ex(rn_epoll_thread_t *epoll_thread, rn_epoll_inst_t *epoll_inst, int is_edge_trigger)
{
    rn_epoll_inst_t *p;
    struct epoll_event event;
    int ret, finded = 0;

    RN_LISTENTRYWALK(p, &(epoll_thread->inst_list_head), node) {
        if (p == epoll_inst) {
            finded = 1;
            break;
        }
    }
    if (finded == 1) {
        rn_assert(epoll_inst->already_in_epoll == 1);
        /* already in epoll */
        return RN_RETVALUE_OK;
    }

    rn_assert(epoll_inst->already_in_epoll == 0);

    epoll_inst->epoll_thread = epoll_thread;
    epoll_inst->reg_events = event.events;
    epoll_inst->already_in_epoll = 1;

    event.data.ptr = epoll_inst;
    event.events = EPOLLIN | (is_edge_trigger ? EPOLLET : 0);
    ret = epoll_ctl(epoll_thread->epoll_fd, EPOLL_CTL_ADD, epoll_inst->fd, &event);
    if (ret) {
        rn_err("epoll_ctl add faild %d\n", ret);
        return RN_RETVALUE_ERR;
    }

    rn_listadd_tail(&(epoll_inst->node), &(epoll_thread->inst_list_head));
    epoll_thread->n_inst++;

    return RN_RETVALUE_OK;
}

/*
 * sub_crthread_id: -1 process in main crthread
 */
int rn_epoll_thread_reg_inst(rn_epoll_thread_t *epoll_thread, rn_epoll_inst_t *epoll_inst)
{
    return rn_epoll_thread_reg_inst_ex(epoll_thread, epoll_inst, 0);
}

int rn_epoll_thread_reg_uninst(rn_epoll_thread_t *epoll_thread, rn_epoll_inst_t *epoll_inst)
{
    rn_epoll_inst_t *p;
    struct epoll_event event;
    int ret, finded = 0;

    if (epoll_inst->epoll_thread != epoll_thread) {
        return RN_RETVALUE_INVALID_PARAM;
    }

    RN_LISTENTRYWALK(p, &(epoll_thread->inst_list_head), node) {
        if (p == epoll_inst) {
            finded = 1;
            break;
        }
    }
    if (finded == 0) {
        rn_assert(epoll_inst->already_in_epoll == 0);
        /* already removed */
        return RN_RETVALUE_OK;
    }

    rn_assert(epoll_inst->already_in_epoll == 1);

    event.data.ptr = epoll_inst;
    event.events = epoll_inst->reg_events;
    ret = epoll_ctl(epoll_thread->epoll_fd, EPOLL_CTL_DEL, epoll_inst->fd, &event);
    if (ret) {
        rn_err("epoll_ctl del faild %d\n", ret);
    }

    rn_listdel(&(epoll_inst->node));
    epoll_inst->already_in_epoll = 0;
    epoll_thread->n_inst--;

    return RN_RETVALUE_OK;
}

static void rn_timerfw_public_cb(rn_epoll_inst_t *epoll_inst)
{
    rn_timerfw_timer_t *timer_inst = RN_GETCONTAINER(epoll_inst, rn_timerfw_timer_t, epoll_inst);
    int ret;
    uint64_t exp;

    rn_assert(timer_inst->timer_fd == epoll_inst->fd);

    if (!timer_inst->valid) {
        return;
    }

    ret = read(timer_inst->timer_fd, &exp, sizeof(uint64_t));
    if (ret != sizeof(uint64_t)) {
        rn_err("read return invalid len %d, %d(%s)\n", ret, errno, strerror(errno));
    } else {
        timer_inst->cb(timer_inst->cb_param);
    }
}

/* return: < 0 --> error
 *         >=0 --> timer idx
 */
int rn_timerfw_add_timer(rn_epoll_thread_t *ctx, uint64_t first_us, uint64_t interval_us, rn_timerfw_cb_func cb, void *cb_param)
{
    int i;
    rn_timerfw_timer_t *timer_inst = NULL;

    for (i = 0; i < RN_TIMERFW_MAXTIMER; i++) {
        if (!ctx->timer_list[i].valid) {
            timer_inst = &(ctx->timer_list[i]);
            break;
        }
    }
    if (timer_inst == NULL) {
        rn_err("no enough timer resource.\n");
        return RN_RETVALUE_NOENOUGHRES;
    }

    timer_inst->timer_fd = timerfd_create(CLOCK_MONOTONIC, TFD_CLOEXEC);
    if (timer_inst->timer_fd < 0) {
        rn_err("failed timerfd_create, errno %d(%s)\n", errno, strerror(errno));
        return RN_RETVALUE_SYSCALL_FAILD;
    }

    timer_inst->timer.it_value.tv_sec = first_us / 1000000;
    timer_inst->timer.it_value.tv_nsec = (first_us % 1000000) * 1000 + 1;
    timer_inst->timer.it_interval.tv_sec = interval_us / 1000000;
    timer_inst->timer.it_interval.tv_nsec = (interval_us % 1000000) * 1000;

    if (timerfd_settime(timer_inst->timer_fd, 0, &(timer_inst->timer), NULL)) {
        close(timer_inst->timer_fd);
        memset(timer_inst, 0, sizeof(rn_timerfw_timer_t));
        rn_err("failed timerfd_settime, errno %d(%s)\n", errno, strerror(errno));
        return RN_RETVALUE_SYSCALL_FAILD;
    }

    timer_inst->cb = cb;
    timer_inst->cb_param = cb_param;

    timer_inst->epoll_inst.fd = timer_inst->timer_fd;
    timer_inst->epoll_inst.epoll_inst_cb = rn_timerfw_public_cb;

    /* timer should process in main crthread */
    rn_epoll_thread_reg_inst_ex(ctx, &(timer_inst->epoll_inst), 1);

    timer_inst->valid = 1;

    ctx->n_timer++;

    return i;
}

int rn_timerfw_del_timer(rn_epoll_thread_t *ctx, int idx)
{
    rn_timerfw_timer_t *timer_inst = &(ctx->timer_list[idx]);

    if (idx >= RN_TIMERFW_MAXTIMER) {
        return RN_RETVALUE_INVALID_PARAM;
    }

    if (!timer_inst->valid) {
        return RN_RETVALUE_TIMER_NOT_READY;
    }

    rn_epoll_thread_reg_uninst(ctx, &(timer_inst->epoll_inst));

    close(timer_inst->timer_fd);
    timer_inst->valid = 0;
    memset(timer_inst, 0, sizeof(rn_timerfw_timer_t));

    ctx->n_timer--;

    return RN_RETVALUE_OK;
}
