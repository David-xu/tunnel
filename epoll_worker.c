#include "pub.h"

#define FGFW_MAX_EVENTS         1024

static void *epoll_thread_proc(void *arg)
{
    fgfw_epoll_thread_t *epoll_thread = (fgfw_epoll_thread_t *)arg;
    
    crthread_run(&(epoll_thread->crthread_ctx), &(epoll_thread->shutdown));

    fgfw_log("epoll main loop exit.\n");

    return NULL;
}

static int epoll_main_crthread_func(crthread_tcb_t *tcb, void *p)
{
    fgfw_epoll_thread_t *epoll_thread = (fgfw_epoll_thread_t *)p;
    struct epoll_event events[FGFW_MAX_EVENTS];
    int idx, fds;

    while (1) {
        fds = epoll_wait(epoll_thread->epoll_fd, events, FGFW_MAX_EVENTS, 1);
        for (idx = 0; idx < fds; idx++) {
            fgfw_epoll_inst_t *epoll_inst = (fgfw_epoll_inst_t *)events[idx].data.ptr;
            if (epoll_inst->sub_crthread_id == -1) {
                /* process in main crthread */
                epoll_inst->epoll_inst_cb(epoll_inst);
            } else {
                fgfw_epoll_thread_sub_crthread_t *sub_crthread = &(epoll_thread->sub_crthread[epoll_inst->sub_crthread_id]);
                fgfw_assert(epoll_inst->sub_crthread_id < FGFW_EPOLL_THREAD_MAXSUBCRTHREAD);

                /* set pending bitmap */
                if (FGFW_RAW_BITMAP_TEST(sub_crthread->pending_bm, epoll_inst->idx_in_sub_crthread) == 0) {
                    FGFW_RAW_BITMAP_SET(sub_crthread->pending_bm, epoll_inst->idx_in_sub_crthread);
                    sub_crthread->pending_inst[epoll_inst->idx_in_sub_crthread] = epoll_inst;

                    if (sub_crthread->n_pending == 0) {
                        /* trigger sub crthread */
                        crthread_sem_up(tcb, &(sub_crthread->sem), 1);
                    }
                    sub_crthread->n_pending++;
                } else {
                    fgfw_assert(sub_crthread->pending_inst[epoll_inst->idx_in_sub_crthread] == epoll_inst);
                }
            }
        }

        crthread_yield(tcb);
    }

    return 0;
}

static int epoll_sub_crthread_func(crthread_tcb_t *tcb, void *p)
{
    fgfw_epoll_thread_sub_crthread_t *sub_crthread = (fgfw_epoll_thread_sub_crthread_t *)p;
    fgfw_epoll_inst_t *epoll_inst;
    int i;
    uint32_t cnt, cur_cnt;

    while (1) {
        crthread_sem_down(tcb, &(sub_crthread->sem), 0);
        while (sub_crthread->n_pending) {
            cur_cnt = sub_crthread->n_pending;
            cnt = 0;
            for (i = 0; i < FGFW_EPOLL_THREAD_MAX_INST_IN_SUBPROC_CRTHREAD; i++) {
                if (cnt == cur_cnt) {
                    break;
                }
                if (FGFW_RAW_BITMAP_TEST(sub_crthread->pending_bm, i)) {
                    epoll_inst = sub_crthread->pending_inst[i];
                    epoll_inst->epoll_inst_cb(epoll_inst);

                    sub_crthread->pending_inst[i] = NULL;
                    FGFW_RAW_BITMAP_CLEAR(sub_crthread->pending_bm, i);
                    sub_crthread->n_pending--;

                    cnt++;
                }
            }
            if (sub_crthread->n_pending) {
                fgfw_log("[%d] sub_crthread->n_pending %d...\n", sub_crthread->idx, sub_crthread->n_pending);
            }
        }
    }

    return 0;
}

int fgfw_epoll_thread_create(fgfw_epoll_thread_t *epoll_thread)
{
    int flag, i;

    memset(epoll_thread, 0, sizeof(fgfw_epoll_thread_t));

    epoll_thread->n_inst = 0;
    fgfw_initlisthead(&(epoll_thread->inst_list_head));

    /* init crthread controller */
    crthread_init_scheduler(&(epoll_thread->crthread_ctx));
    for (i = 0; i < FGFW_EPOLL_THREAD_MAXSUBCRTHREAD; i++) {
        epoll_thread->sub_crthread[i].idx = i;
        epoll_thread->sub_crthread[i].epoll_thread = epoll_thread;
        crthread_init_sem(&(epoll_thread->sub_crthread[i].sem));
        fgfw_bitmap_init_ex(&(epoll_thread->sub_crthread[i].bm), "", FGFW_EPOLL_THREAD_MAX_INST_IN_SUBPROC_CRTHREAD, 0, 0);
        /* register and launch main crthread */
        epoll_thread->sub_crthread[i].crthread_tcb = crthread_create(&(epoll_thread->crthread_ctx), epoll_sub_crthread_func, &(epoll_thread->sub_crthread[i]));
        crthread_launch(epoll_thread->sub_crthread[i].crthread_tcb);
    }
    epoll_thread->main_crthread = crthread_create(&(epoll_thread->crthread_ctx), epoll_main_crthread_func, epoll_thread);
    crthread_launch(epoll_thread->main_crthread);

    /* create epoll */
    epoll_thread->epoll_fd = epoll_create(1);
    if (epoll_thread->epoll_fd==-1)
    {
        fgfw_err("epoll_create failed.\n");
        return FGFW_RETVALUE_ERR;
    }
    flag = fcntl(epoll_thread->epoll_fd, F_GETFD);
    fcntl(epoll_thread->epoll_fd, F_SETFD, flag | FD_CLOEXEC);

    epoll_thread->shutdown = 0;
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
    epoll_thread->shutdown = 1;

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

static int fgfw_epoll_thread_reg_inst_ex(fgfw_epoll_thread_t *epoll_thread, fgfw_epoll_inst_t *epoll_inst, int sub_crthread_id, int is_edge_trigger)
{
    struct epoll_event event;
    int ret;
    fgfw_epoll_thread_sub_crthread_t *sub_crthread = NULL;

    epoll_inst->epoll_thread = epoll_thread;
    epoll_inst->reg_events = event.events;
    epoll_inst->sub_crthread_id = sub_crthread_id;

    if (sub_crthread_id != -1) {
        sub_crthread = &(epoll_thread->sub_crthread[sub_crthread_id]);
        fgfw_assert(sub_crthread_id < FGFW_EPOLL_THREAD_MAXSUBCRTHREAD);
        ret = fgfw_bitmap_alloc(&(sub_crthread->bm), 1, &(epoll_inst->idx_in_sub_crthread));
        if (ret < 0) {
            /* todo */
            fgfw_assert(0);
            return FGFW_RETVALUE_NOENOUGHRES;
        }
    }

    event.data.ptr = epoll_inst;
    event.events = EPOLLIN | (is_edge_trigger ? EPOLLET : 0);
    ret = epoll_ctl(epoll_thread->epoll_fd, EPOLL_CTL_ADD, epoll_inst->fd, &event);
    if (ret) {
        if (sub_crthread_id != -1) {
            fgfw_assert(sub_crthread != NULL);
            fgfw_bitmap_free(&(sub_crthread->bm), 1, &(epoll_inst->idx_in_sub_crthread));
        }
        
        fgfw_err("epoll_ctl add faild %d\n", ret);
        return FGFW_RETVALUE_ERR;
    }

    fgfw_listadd_tail(&(epoll_inst->node), &(epoll_thread->inst_list_head));
    epoll_thread->n_inst++;
    return FGFW_RETVALUE_OK;
}

/*
 * sub_crthread_id: -1 process in main crthread
 */
int fgfw_epoll_thread_reg_inst(fgfw_epoll_thread_t *epoll_thread, fgfw_epoll_inst_t *epoll_inst, int sub_crthread_id)
{
    return fgfw_epoll_thread_reg_inst_ex(epoll_thread, epoll_inst, sub_crthread_id, 0);
}

int fgfw_epoll_thread_reg_uninst(fgfw_epoll_thread_t *epoll_thread, fgfw_epoll_inst_t *epoll_inst)
{
    fgfw_epoll_inst_t *p;
    struct epoll_event event;
    int ret, finded = 0;
    fgfw_epoll_thread_sub_crthread_t *sub_crthread = NULL;

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

    if (epoll_inst->sub_crthread_id != -1) {
        sub_crthread = &(epoll_thread->sub_crthread[epoll_inst->sub_crthread_id]);
        fgfw_bitmap_free(&(sub_crthread->bm), 1, &(epoll_inst->idx_in_sub_crthread));

        sub_crthread->pending_inst[epoll_inst->idx_in_sub_crthread] = NULL;
        FGFW_RAW_BITMAP_CLEAR(sub_crthread->pending_bm, epoll_inst->idx_in_sub_crthread);
        sub_crthread->n_pending--;
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

    /* timer should process in main crthread */
    fgfw_epoll_thread_reg_inst_ex(ctx, &(timer_inst->epoll_inst), -1, 1);

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