#include "vacc_host.h"

/* epoll helper */
int helper_epoll_create(void)
{
    int flag;
    int epoll_fd=-1;

    epoll_fd = epoll_create(1);
    if (epoll_fd == -1) {
        return -1;
    }
    flag = fcntl(epoll_fd, F_GETFD);
    fcntl(epoll_fd, F_SETFD, flag | FD_CLOEXEC);

    return epoll_fd;
}

int helper_epoll_add(int epoll_fd, int fd, void *data)
{
    struct epoll_event event;
    event.data.ptr = data;
    event.events = EPOLLIN;
    return epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fd, &event);
}
int helper_epoll_del(int epoll_fd, int fd, void *data)
{
    struct epoll_event event;
    event.data.ptr = data;
    event.events = EPOLLIN;
    return epoll_ctl(epoll_fd, EPOLL_CTL_DEL, fd, &event);
}

static void vacc_host_setsockbuf_size(vacc_host_t *vacc_host, int recvbuf_size, int sendbuf_size)
{
    vacc_host->recvbuf_size = recvbuf_size;
    vacc_host->sendbuf_size = sendbuf_size;

    if (recvbuf_size) {
        setsockopt(vacc_host->sock_fd, SOL_SOCKET, SO_RCVBUF, &recvbuf_size, sizeof(recvbuf_size));
    }
    if (sendbuf_size) {
        setsockopt(vacc_host->sock_fd, SOL_SOCKET, SO_SNDBUF, &sendbuf_size, sizeof(sendbuf_size));
    }
}

static int vacc_host_create_tcp(vacc_host_t *vacc_host, const vacc_host_create_param_t *param)
{
    int ret, len, on;
    struct sockaddr_in srv_addr, cli_addr;

    memset(vacc_host, 0, sizeof(vacc_host_t));

    switch(param->insttype) {
    case VACC_HOST_INSTTYPE_SERVER_LISTENER:
        /* create server listen socket */
        vacc_host->sock_fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, IPPROTO_TCP);
        if (vacc_host->sock_fd < 0) {
            return VACC_HOST_RET_SOCKET_FAILD;
        }

        on = 1;
        setsockopt(vacc_host->sock_fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));

        memset(&srv_addr, 0, sizeof(srv_addr));
        srv_addr.sin_family = AF_INET;
        if (strlen(param->u.udp.srv_ip) == 0) {
            srv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
        } else {
            srv_addr.sin_addr.s_addr = inet_addr(param->u.udp.srv_ip);
        }
        srv_addr.sin_port = htons(param->u.tcp.srv_port);
        ret = bind(vacc_host->sock_fd, (struct sockaddr *)&srv_addr, sizeof(srv_addr));
        if (ret < 0) {
            close(vacc_host->sock_fd);
            return VACC_HOST_RET_BIND_FAILD;
        }
        ret = listen(vacc_host->sock_fd, param->n_listen != 0 ? param->n_listen : VACC_HOST_DEFAULT_LISTENNUM);
        if (ret < 0) {
            close(vacc_host->sock_fd);
            return VACC_HOST_RET_LISTEN_FAILD;
        }

        break;
    case VACC_HOST_INSTTYPE_SERVER_INST:
        /* new client need accept */
        len = sizeof(cli_addr);
        vacc_host->sock_fd = accept(param->u.uds.server_listener->sock_fd, (struct sockaddr *)&cli_addr, (socklen_t *)&len);
        if (vacc_host->sock_fd > 0) {
            /* new connection */
            // printf("new connection...\n");
        } else {
            return VACC_HOST_RET_ACCEPT_FAILD;
        }

        vacc_host_setsockbuf_size(vacc_host, param->recvbuf_size, param->sendbuf_size);

        /* build relation to listen socket */
        vacc_host->server_listener = param->u.uds.server_listener;
        vacc_host->server_listener->n_client_inst++;

        /* save client addr */
        memcpy(&(vacc_host->u.tcp.cli_addr), &cli_addr, sizeof(vacc_host->u.tcp.cli_addr));

        break;
    case VACC_HOST_INSTTYPE_CLIENT_INST:
        /* connect to server */
        vacc_host->sock_fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, IPPROTO_TCP);
        if (vacc_host->sock_fd < 0) {
            return VACC_HOST_RET_SOCKET_FAILD;
        }

        vacc_host_setsockbuf_size(vacc_host, param->recvbuf_size, param->sendbuf_size);

        memset(&srv_addr, 0, sizeof(srv_addr));
        srv_addr.sin_family = AF_INET;
        srv_addr.sin_addr.s_addr = inet_addr(param->u.tcp.srv_ip);
        srv_addr.sin_port = htons(param->u.tcp.srv_port);
        if (connect(vacc_host->sock_fd, (struct sockaddr *)&srv_addr, sizeof(srv_addr)) < 0) {
            close(vacc_host->sock_fd);
            return VACC_HOST_RET_CONNECT_FAILD;
        }

        break;
    default:
        return VACC_HOST_RET_INVALID_PARAM;
    }

    return VACC_HOST_RET_OK;
}

static int vacc_host_create_udp(vacc_host_t *vacc_host, const vacc_host_create_param_t *param)
{
    int ret, on;
    struct sockaddr_in srv_addr;

    memset(vacc_host, 0, sizeof(vacc_host_t));

    switch(param->insttype) {
    case VACC_HOST_INSTTYPE_SERVER_INST:
        /* create server socket */
        vacc_host->sock_fd = socket(AF_INET, SOCK_DGRAM, 0);
        if (vacc_host->sock_fd < 0) {
            return VACC_HOST_RET_SOCKET_FAILD;
        }

        on = 1;
        setsockopt(vacc_host->sock_fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));

        vacc_host_setsockbuf_size(vacc_host, param->recvbuf_size, param->sendbuf_size);

        memset(&srv_addr, 0, sizeof(srv_addr));
        srv_addr.sin_family = AF_INET;
        if (strlen(param->u.udp.srv_ip) == 0) {
            srv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
        } else {
            srv_addr.sin_addr.s_addr = inet_addr(param->u.udp.srv_ip);
        }
        srv_addr.sin_port = htons(param->u.udp.srv_port);
        ret = bind(vacc_host->sock_fd, (struct sockaddr *)&srv_addr, sizeof(srv_addr));
        if (ret < 0) {
            close(vacc_host->sock_fd);
            return VACC_HOST_RET_BIND_FAILD;
        }

        break;
    case VACC_HOST_INSTTYPE_CLIENT_INST:
        /* connect to server */
        vacc_host->sock_fd = socket(AF_INET, SOCK_DGRAM, 0);
        if (vacc_host->sock_fd < 0) {
            return VACC_HOST_RET_SOCKET_FAILD;
        }

        vacc_host_setsockbuf_size(vacc_host, param->recvbuf_size, param->sendbuf_size);

        memset(&srv_addr, 0, sizeof(srv_addr));
        srv_addr.sin_family = AF_INET;
        srv_addr.sin_addr.s_addr = inet_addr(param->u.udp.srv_ip);
        srv_addr.sin_port = htons(param->u.udp.srv_port);
        if (connect(vacc_host->sock_fd, (struct sockaddr *)&srv_addr, sizeof(srv_addr)) < 0) {
            close(vacc_host->sock_fd);
            return VACC_HOST_RET_CONNECT_FAILD;
        }

        break;
    default:
        return VACC_HOST_RET_INVALID_PARAM;
    }

    return VACC_HOST_RET_OK;

}

static int vacc_host_create_uds(vacc_host_t *vacc_host, const vacc_host_create_param_t *param)
{
    int ret, len;
    struct sockaddr_un srv_un, cli_un;

    memset(vacc_host, 0, sizeof(vacc_host_t));

    switch(param->insttype) {
    case VACC_HOST_INSTTYPE_SERVER_LISTENER:
        /* create server listen socket */
        vacc_host->sock_fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
        if (vacc_host->sock_fd < 0) {
            return VACC_HOST_RET_SOCKET_FAILD;
        }

        unlink(param->u.uds.path);

        memset(&srv_un, 0, sizeof(srv_un));
        srv_un.sun_family = AF_UNIX;
        snprintf(srv_un.sun_path, sizeof(srv_un.sun_path), "%s", param->u.uds.path);
        ret = bind(vacc_host->sock_fd, (struct sockaddr *)&srv_un, sizeof(srv_un));
        if (ret < 0) {
            close(vacc_host->sock_fd);
            return VACC_HOST_RET_BIND_FAILD;
        }
        ret = listen(vacc_host->sock_fd, param->n_listen != 0 ? param->n_listen : VACC_HOST_DEFAULT_LISTENNUM);
        if (ret < 0) {
            close(vacc_host->sock_fd);
            return VACC_HOST_RET_LISTEN_FAILD;
        }

        break;
    case VACC_HOST_INSTTYPE_SERVER_INST:
        /* new client need accept */
        len = sizeof(cli_un);
        vacc_host->sock_fd = accept(param->u.uds.server_listener->sock_fd, (__SOCKADDR_ARG)&cli_un, (socklen_t *)&len);
        if (vacc_host->sock_fd > 0) {
            /* new connection */
            // printf("new connection...\n");
        } else {
            return VACC_HOST_RET_ACCEPT_FAILD;
        }

        vacc_host_setsockbuf_size(vacc_host, param->recvbuf_size, param->sendbuf_size);

        /* build relation to listen socket */
        vacc_host->server_listener = param->u.uds.server_listener;
        vacc_host->server_listener->n_client_inst++;

        /* save client addr */
        memcpy(&(vacc_host->u.uds.cli_addr), &cli_un, sizeof(vacc_host->u.uds.cli_addr));

        break;
    case VACC_HOST_INSTTYPE_CLIENT_INST:
        /* connect to server */
        vacc_host->sock_fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
        if (vacc_host->sock_fd < 0) {
            return VACC_HOST_RET_SOCKET_FAILD;
        }

        vacc_host_setsockbuf_size(vacc_host, param->recvbuf_size, param->sendbuf_size);

        memset(&srv_un, 0, sizeof(srv_un));
        srv_un.sun_family = AF_UNIX;
        snprintf(srv_un.sun_path, sizeof(srv_un.sun_path), "%s", param->u.uds.path);
        if (connect(vacc_host->sock_fd, (struct sockaddr *)&srv_un, sizeof(srv_un)) < 0) {
            close(vacc_host->sock_fd);
            return VACC_HOST_RET_CONNECT_FAILD;
        }

        break;
    default:
        return VACC_HOST_RET_INVALID_PARAM;
    }

    return VACC_HOST_RET_OK;
}

static int vacc_host_destroy_tcp(vacc_host_t *vacc_host)
{
    return VACC_HOST_RET_OK;
}

static int vacc_host_destroy_uds(vacc_host_t *vacc_host)
{
    return VACC_HOST_RET_OK;
}

static int vacc_host_destroy_udp(vacc_host_t *vacc_host)
{
    return VACC_HOST_RET_OK;
}

static int vacc_host_send_data_normal(vacc_host_t *vacc_host, void *buf, uint32_t len)
{
    struct iovec iov;
    struct msghdr msgh;
    int ret;
    uint32_t already_send = 0;

    if (vacc_host->sock_fd < 0) {
        return VACC_HOST_RET_INVALID_INST;
    }

#ifdef VACC_HOST_SEND_TO_COMPLETE
__send_more:
#endif
    memset(&msgh, 0, sizeof(msgh));
    iov.iov_base = buf + already_send;
    iov.iov_len = len - already_send;

    msgh.msg_iov = &iov;
    msgh.msg_iovlen = 1;

retry:
    ret = sendmsg(vacc_host->sock_fd, &msgh, MSG_DONTWAIT);
    if ((ret < 0) && ((errno == EINTR) || (errno == EAGAIN))) {
        usleep(100);
        goto retry;
    }

    if (ret < 0) {
        if ((errno == ECONNRESET) || (errno == EPIPE)) {
            return VACC_HOST_RET_PEERCLOSE;
        }
        printf("##############  sendmsg() return faild, ret %d, errno %d\n", ret, errno);
        return VACC_HOST_RET_SENDMSG_FAILD;
    }
    already_send += ret;

#ifdef VACC_HOST_SEND_TO_COMPLETE
    if (already_send < len) {
        printf("##############  sendmsg() return %d already_send %d len %d\n", ret, already_send, len);
        goto __send_more;
    }

    if (already_send != len) {
        printf("##############  err already_send %d != len %d\n", already_send, len);
    }
#endif

    return already_send;
}

static int vacc_host_send_data_udp(vacc_host_t *vacc_host, void *buf, uint32_t len, vacc_host_addr_u *addr)
{
    socklen_t addr_len;
    int ret;

    if (addr) {
        addr_len = sizeof(struct sockaddr_in);
        ret = sendto(vacc_host->sock_fd, buf, len, 0, (struct sockaddr *)&(addr->udp.addr), addr_len);
    } else {
        ret = send(vacc_host->sock_fd, buf, len, 0);
    }

    if (ret < 0) {
        return VACC_HOST_RET_SENDMSG_FAILD;
    }

    return VACC_HOST_RET_OK;
}

static int vacc_host_recv_data_normal_proto(vacc_host_t *vacc_host)
{
    uint8_t buf[vacc_host->proto_abs.pkg_max_len];
    struct iovec iov;
    struct msghdr msgh;
    int ret, payload_len, left_size = vacc_host->proto_abs.pkg_max_len - vacc_host->proto_abs.head_len;
    int need_recv_len, already_recv_len = 0;
    int retry_cnt;

    already_recv_len = 0;
    // printf("!!!!!!!!!!!!! 00 ############## already_recv_len %d\n", already_recv_len);
    need_recv_len = vacc_host->proto_abs.head_len;
    retry_cnt = 10000;

__retry_recv_head:
    memset(&msgh, 0, sizeof(msgh));
    iov.iov_base = (void *)buf + already_recv_len;
    iov.iov_len = need_recv_len - already_recv_len;

    msgh.msg_iov = &iov;
    msgh.msg_iovlen = 1;

    ret = recvmsg(vacc_host->sock_fd, &msgh, MSG_DONTWAIT);
    if (ret == 0) {
        // printf("**********   exit   01\n");
        return VACC_HOST_RET_PEERCLOSE;
    } else if (ret < 0) {
        if ((errno == EINTR) || (errno == EAGAIN)) {
            usleep(100);
            goto __retry_recv_head;
        } else if ((errno == ECONNRESET) || (errno == EPIPE)) {
            // printf("**********   exit   02\n");
            /* peer close, just return 0 */
            return VACC_HOST_RET_PEERCLOSE;
        } else {
            // printf("**********   exit   03, errno %d\n", errno);
            return VACC_HOST_RET_READMSG_FAILD;
        }
    }
    // printf("!!!!!!!!!!!!! 01 ############## already_recv_len %d, ret %d\n", already_recv_len, ret);
    already_recv_len += ret;
    // printf("!!!!!!!!!!!!! 02 ############## already_recv_len %d, ret %d\n", already_recv_len, ret);
    if (already_recv_len != need_recv_len) {
        retry_cnt--;
        if (retry_cnt) {
            printf("!!!!!!!!!!!!!! 12341234 123412341234 !!!!!!!!!!!!!!!! already_recv_len %d need_recv_len %d, ret %d, fd %d\n",
                already_recv_len, need_recv_len, ret, vacc_host->sock_fd);
            goto __retry_recv_head;
        } else {
            printf("!!!!!!!!!!!!!! try too many times, recved_len %d need_recv_len %d\n", already_recv_len, need_recv_len);
            while (1) usleep(100000);
        }
    }
#if 0
    printf("!!!!!!!!!!!!!! 03 ################# ret %d ####### already_recv_len %d, fd %d\n",
        ret, already_recv_len, vacc_host->sock_fd);
#endif
    if (msgh.msg_flags & (MSG_TRUNC | MSG_CTRUNC)) {
        printf("!!!!!!!!!!!!!! msgh.msg_flags 0x%x\n", msgh.msg_flags);
        while (1) usleep(100000);
        return VACC_HOST_RET_TRUNCATED;
    }

    /* get payload len */
    payload_len = vacc_host->proto_abs.get_payload_len(buf);
    already_recv_len = 0;
    need_recv_len = payload_len;

    if (payload_len) {
        if (payload_len > left_size) {
            printf("!!!!!!!!!!!!!! payload_len %d left_size %d\n", payload_len, left_size);
            while (1) usleep(100000);
            return VACC_HOST_RET_INVALID_MSGLEN;
        }
        retry_cnt = 10000;
retry:
        ret = read(vacc_host->sock_fd, buf + vacc_host->proto_abs.head_len + already_recv_len, need_recv_len);
        if (ret < 0) {
            if ((errno == EINTR) || (errno == EAGAIN)) {
                usleep(100);
                goto retry;
            } else if (errno == ECONNRESET) {
                /* peer close, just return 0 */
                return VACC_HOST_RET_PEERCLOSE;
            }
        }
        if (ret <= 0) {
            printf("!!!!!!!!!!!!!! ret %d \n", ret);
            while (1) usleep(100000);
            return VACC_HOST_RET_READMSG_FAILD;
        }
        already_recv_len += ret;
        need_recv_len -= ret;
        if (already_recv_len != (int)payload_len) {
            retry_cnt--;
            if (retry_cnt) {
                goto retry;
            } else {
                printf("!!!!!!!!!!!!!! try too many times, recved_len %d payload_len %d\n", already_recv_len, payload_len);
                while (1) usleep(100000);
            }
        }
    }

    /**/
    if (vacc_host->cb_recv) {
        vacc_host->cb_recv(vacc_host, vacc_host->opaque, buf, vacc_host->proto_abs.head_len + payload_len);
    } else {
        printf("vacc_host_recv_data_normal_proto() vacc_host->cb_recv == NULL.\n");
    }

    return VACC_HOST_RET_OK;
}

static int vacc_host_recv_data_normal_without_proto(vacc_host_t *vacc_host, uint8_t *buf, int buf_len)
{
    int ret;
    uint8_t local_buf[64 * 1024];
    if (buf == NULL) {
        buf = local_buf;
        buf_len = sizeof(local_buf);
    }

retry:
    ret = read(vacc_host->sock_fd, buf, buf_len);
    if (ret == 0) {
        return VACC_HOST_RET_PEERCLOSE;
    } else if (ret < 0) {
        if ((errno == EINTR) || (errno == EAGAIN)) {
            usleep(100);
            goto retry;
        } else if (errno == ECONNRESET) {
            /* peer close, just return 0 */
            return VACC_HOST_RET_PEERCLOSE;
        } else {
            printf("read return %d, dead.\n", ret);
            while (1) usleep(100000);
            return VACC_HOST_RET_READMSG_FAILD;
        }
    }

    /**/
    if (vacc_host->cb_recv) {
        vacc_host->cb_recv(vacc_host, vacc_host->opaque, buf, ret);
    }

    return ret;
}

static int vacc_host_recv_data_normal(vacc_host_t *vacc_host, uint8_t *buf, int buf_len)
{
    if (vacc_host->sock_fd < 0) {
        return VACC_HOST_RET_INVALID_INST;
    }

    if (vacc_host->proto_abs.enable) {
        return vacc_host_recv_data_normal_proto(vacc_host);
    } else {
        return vacc_host_recv_data_normal_without_proto(vacc_host, buf, buf_len);
    }
}

static int vacc_host_recv_data_udp(vacc_host_t *vacc_host)
{

    vacc_host_addr_u addr;
    socklen_t len;
    int ret;
    memset(&addr, 0, sizeof(vacc_host_addr_u));

    if (vacc_host->proto_abs.enable) {
        uint8_t buf[vacc_host->proto_abs.pkg_max_len];

        len = sizeof(struct sockaddr_in);
        ret = recvfrom(vacc_host->sock_fd, buf, vacc_host->proto_abs.pkg_max_len, 0, (struct sockaddr *)&(addr.udp.addr), &len);
        if (ret == -1) {
            return VACC_HOST_RET_READMSG_FAILD;
        }

        if (vacc_host->cb_recv_ex) {
            vacc_host->cb_recv_ex(vacc_host, vacc_host->opaque, buf, ret, &addr);
        } else {
            vacc_host->cb_recv(vacc_host, vacc_host->opaque, buf, ret);
        }

        return VACC_HOST_RET_OK;
    } else {
        uint8_t buf[64 * 1024];

        len = sizeof(struct sockaddr_in);
        ret = recvfrom(vacc_host->sock_fd, buf, sizeof(buf), 0, (struct sockaddr *)&(addr.udp.addr), &len);
        if (ret == -1) {
            return VACC_HOST_RET_READMSG_FAILD;
        }

        if (vacc_host->cb_recv_ex) {
            vacc_host->cb_recv_ex(vacc_host, vacc_host->opaque, buf, ret, &addr);
        } else {
            vacc_host->cb_recv(vacc_host, vacc_host->opaque, buf, ret);
        }

        return VACC_HOST_RET_OK;
    }
}

int vacc_host_create(vacc_host_t *vacc_host, const vacc_host_create_param_t *param)
{
    int ret;
    if (!vacc_host) {
        return VACC_HOST_RET_INVALID_PARAM;
    }

    switch (param->transtype) {
    case VACC_HOST_TRANSTYPE_TCP:
        ret = vacc_host_create_tcp(vacc_host, param);
        break;
    case VACC_HOST_TRANSTYPE_UDP:
        ret = vacc_host_create_udp(vacc_host, param);
        break;
    case VACC_HOST_TRANSTYPE_UDS:
        ret = vacc_host_create_uds(vacc_host, param);
        break;
    default:
        return VACC_HOST_RET_INVALID_PARAM;
    }

    if (ret == VACC_HOST_RET_OK) {
        /* init vacc_host */
        vacc_host->transtype = param->transtype;
        vacc_host->insttype = param->insttype;
        vacc_host->cb_get = param->cb_get;
        vacc_host->cb_put = param->cb_put;
        vacc_host->cb_init = param->cb_init;
        vacc_host->cb_uninit = param->cb_uninit;
        vacc_host->cb_recv = param->cb_recv;
        vacc_host->cb_recv_ex = param->cb_recv_ex;
        vacc_host->proto_abs = param->proto_abs;
        vacc_host->opaque = param->opaque;
        vacc_host->recvbuf_size = param->recvbuf_size;
        vacc_host->sendbuf_size = param->sendbuf_size;

        /* call cb_init */
        vacc_host->cb_init(vacc_host, vacc_host->opaque);
    }

    return ret;
}

int vacc_host_destroy(vacc_host_t *vacc_host)
{
    int ret;
    if (!vacc_host) {
        return VACC_HOST_RET_INVALID_PARAM;
    }

    switch (vacc_host->transtype) {
    case VACC_HOST_TRANSTYPE_TCP:
        ret = vacc_host_destroy_tcp(vacc_host);
        break;
    case VACC_HOST_TRANSTYPE_UDS:
        ret = vacc_host_destroy_uds(vacc_host);
        break;
    case VACC_HOST_TRANSTYPE_UDP:
        ret = vacc_host_destroy_udp(vacc_host);
        break;
    default:
        return VACC_HOST_RET_INVALID_PARAM;
    }

    if (ret == VACC_HOST_RET_OK) {
        /* call cb_init */
        vacc_host->cb_uninit(vacc_host, vacc_host->opaque);

        switch(vacc_host->insttype) {
        case VACC_HOST_INSTTYPE_SERVER_LISTENER:
            close(vacc_host->sock_fd);
            break;
        case VACC_HOST_INSTTYPE_SERVER_INST:
            /* decrease the number of instance in the server which this client belongs to */
            vacc_host->server_listener->n_client_inst--;
            close(vacc_host->sock_fd);
            break;
        case VACC_HOST_INSTTYPE_CLIENT_INST:
            close(vacc_host->sock_fd);
            break;
        default:
            return VACC_HOST_RET_INVALID_PARAM;
        }
    }

    return ret;
}

static int vacc_host_new_connect(vacc_host_t *vacc_host)
{
    vacc_host_create_param_t param;
    vacc_host_t *new_inst;
    int ret;

    new_inst = vacc_host->cb_get(vacc_host, vacc_host->opaque);
    if (new_inst == NULL) {
        printf("cb_get return NULL\n");
        return VACC_HOST_RET_GET_INST_FAILD;
    }
    memset(&param, 0, sizeof(param));
    param.transtype = vacc_host->transtype;
    param.insttype = VACC_HOST_INSTTYPE_SERVER_INST;
    param.cb_get = vacc_host->cb_get;
    param.cb_put = vacc_host->cb_put;
    param.cb_init = vacc_host->cb_init;
    param.cb_uninit = vacc_host->cb_uninit;
    param.cb_recv = vacc_host->cb_recv;
    param.proto_abs = vacc_host->proto_abs;
    param.opaque = vacc_host->opaque;
    param.recvbuf_size = vacc_host->recvbuf_size;
    param.sendbuf_size = vacc_host->sendbuf_size;
    param.u.uds.server_listener = vacc_host;        /* attach to server listener instance */
    ret = vacc_host_create(new_inst, &param);
    if (ret != VACC_HOST_RET_OK) {
        printf("vacc_host_create() return %d\n", ret);
        vacc_host->cb_put(new_inst, vacc_host->opaque);
    }

    return ret;
}

/*
 * after this function, vacc_host struct has already clean, should not use anymore
 */
static void vacc_host_disconnect(vacc_host_t *vacc_host)
{
    void *opaque;
    vacc_host_cb_put cb_put;

    opaque = vacc_host->opaque;
    cb_put = vacc_host->cb_put;
    vacc_host_destroy(vacc_host);
    if (vacc_host->insttype == VACC_HOST_INSTTYPE_SERVER_INST) {
        cb_put(vacc_host, opaque);
    }
}

static int vacc_host_send_data(vacc_host_t *vacc_host, void *buf, uint32_t len, vacc_host_addr_u *addr)
{
    int ret;

    if (!vacc_host) {
        return VACC_HOST_RET_INVALID_PARAM;
    }

    switch (vacc_host->transtype) {
    case VACC_HOST_TRANSTYPE_TCP:
        /* fall through */
    case VACC_HOST_TRANSTYPE_UDS:
        ret = vacc_host_send_data_normal(vacc_host, buf, len);
        break;
    case VACC_HOST_TRANSTYPE_UDP:
        ret = vacc_host_send_data_udp(vacc_host, buf, len, addr);
        break;
    default:
        return VACC_HOST_RET_INVALID_PARAM;
    }

    if (ret == VACC_HOST_RET_PEERCLOSE) {
        /* peer close */
        vacc_host_disconnect(vacc_host);
    } else {
        /* todo */
    }

    return ret;
}

static int vacc_host_recv_data(vacc_host_t *vacc_host, uint8_t *buf, int buf_len)
{
    int ret;

    if (!vacc_host) {
        return VACC_HOST_RET_INVALID_PARAM;
    }

    switch (vacc_host->transtype) {
    case VACC_HOST_TRANSTYPE_TCP:
        /* fall through */
    case VACC_HOST_TRANSTYPE_UDS:
        ret = vacc_host_recv_data_normal(vacc_host, buf, buf_len);
        break;
    case VACC_HOST_TRANSTYPE_UDP:
        ret = vacc_host_recv_data_udp(vacc_host);
        break;
    default:
        return VACC_HOST_RET_INVALID_PARAM;
    }

    if (ret == VACC_HOST_RET_PEERCLOSE) {
        /* peer close */
        vacc_host_disconnect(vacc_host);
    }

    return ret;
}

int vacc_host_write(vacc_host_t *vacc_host, void *buf, uint32_t len)
{
    switch (vacc_host->insttype) {
    case VACC_HOST_INSTTYPE_SERVER_LISTENER:
        return VACC_HOST_RET_INVALID_PARAM;
    case VACC_HOST_INSTTYPE_SERVER_INST:
        /* fall through */
    case VACC_HOST_INSTTYPE_CLIENT_INST:
        return vacc_host_send_data(vacc_host, buf, len, NULL);
    default:
        printf("invalid insttype %d\n", vacc_host->insttype);
        return VACC_HOST_RET_INVALID_INSTTYPE;
    }
}

int vacc_host_write_ex(vacc_host_t *vacc_host, void *buf, uint32_t len, vacc_host_addr_u *addr)
{
    switch (vacc_host->insttype) {
    case VACC_HOST_INSTTYPE_SERVER_INST:
        return vacc_host_send_data(vacc_host, buf, len, addr);
    default:
        printf("invalid insttype %d\n", vacc_host->insttype);
        return VACC_HOST_RET_INVALID_INSTTYPE;
    }
}

int vacc_host_read(vacc_host_t *vacc_host, uint8_t *buf, int buf_len)
{
    switch (vacc_host->insttype) {
    case VACC_HOST_INSTTYPE_SERVER_LISTENER:
        return vacc_host_new_connect(vacc_host);
        break;
    case VACC_HOST_INSTTYPE_SERVER_INST:
        /* fall through */
    case VACC_HOST_INSTTYPE_CLIENT_INST:
        return vacc_host_recv_data(vacc_host, buf, buf_len);
        break;
    default:
        printf("invalid insttype %d\n", vacc_host->insttype);
        return VACC_HOST_RET_INVALID_INSTTYPE;
    }
}

