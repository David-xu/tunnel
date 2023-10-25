#ifndef _VACC_HOST_H_
#define _VACC_HOST_H_

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <sys/un.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define VACC_HOST_SEND_TO_COMPLETE

/* epoll helper */
int helper_epoll_create(void);
int helper_epoll_add(int epoll_fd, int fd, void *data);
int helper_epoll_del(int epoll_fd, int fd, void *data);

#define VACC_HOST_MAXPATHLEN            256
#define VACC_HOST_DEFAULT_LISTENNUM     64

#define VACC_HOST_RET_OK                0
#define VACC_HOST_RET_ERR               -1
#define VACC_HOST_RET_INVALID_PARAM     -2
#define VACC_HOST_RET_INVALID_INSTTYPE  -3
#define VACC_HOST_RET_INVALID_INST      -4
#define VACC_HOST_RET_GET_INST_FAILD    -5

#define VACC_HOST_RET_SOCKET_FAILD      -16
#define VACC_HOST_RET_BIND_FAILD        -17
#define VACC_HOST_RET_LISTEN_FAILD      -18
#define VACC_HOST_RET_ACCEPT_FAILD      -19
#define VACC_HOST_RET_CONNECT_FAILD     -20

#define VACC_HOST_RET_INVALID_MSGLEN    -32
#define VACC_HOST_RET_RECV_LEN_NOTEQ    -33
#define VACC_HOST_RET_PEERCLOSE         -34
#define VACC_HOST_RET_TRUNCATED         -35
#define VACC_HOST_RET_SENDMSG_FAILD     -36
#define VACC_HOST_RET_READMSG_FAILD     -37

typedef enum {
    VACC_HOST_INSTTYPE_INVALID = 0,
    VACC_HOST_INSTTYPE_SERVER_LISTENER,
    VACC_HOST_INSTTYPE_SERVER_INST,
    VACC_HOST_INSTTYPE_CLIENT_INST,
    VACC_HOST_INSTTYPE_COUNT,
} vacc_host_insttype_e;

typedef enum {
    VACC_HOST_TRANSTYPE_INVALID = 0,
    VACC_HOST_TRANSTYPE_TCP,
    VACC_HOST_TRANSTYPE_UDS,
    VACC_HOST_TRANSTYPE_UDP,
    VACC_HOST_TRANSTYPE_COUNT
} vacc_host_transtype_e;

typedef union {
    struct {
        struct sockaddr_in  addr;
    } udp;
} vacc_host_addr_u;

struct _vacc_host;
typedef struct _vacc_host* (*vacc_host_cb_get)(struct _vacc_host *vacc_host, void *opaque);
typedef void (*vacc_host_cb_put)(struct _vacc_host *vacc_host, void *opaque);
typedef int (*vacc_host_cb_init)(struct _vacc_host *vacc_host, void *opaque);
typedef int (*vacc_host_cb_uninit)(struct _vacc_host *vacc_host, void *opaque);
typedef int (*vacc_host_cb_recv)(struct _vacc_host *vacc_host, void *opaque, void *buf, uint32_t len);
typedef int (*vacc_host_cb_recv_ex)(struct _vacc_host *vacc_host, void *opaque, void *buf, uint32_t len, vacc_host_addr_u *peer_addr);

typedef struct {
    int             enable;
    int             head_len;
    int             pkg_max_len;
    int             (*get_payload_len)(void *header);
} protocol_abstract_t;

typedef struct _vacc_host {
    vacc_host_transtype_e       transtype;
    vacc_host_insttype_e        insttype;

    union {
        struct {
            struct sockaddr_in  cli_addr;
        } tcp;

        struct {
            struct sockaddr_un  cli_addr;
        } uds;
    } u;    /* for VACC_HOST_INSTTYPE_SERVER_INST, save client addr  */

    struct _vacc_host   *server_listener;   /* which server listerner this inst belongs to, inst must be 'server_inst' */

    vacc_host_cb_get            cb_get;
    vacc_host_cb_put            cb_put;
    vacc_host_cb_init           cb_init;
    vacc_host_cb_uninit         cb_uninit;
    vacc_host_cb_recv           cb_recv;
    vacc_host_cb_recv_ex        cb_recv_ex;

    protocol_abstract_t         proto_abs;

    int                         recvbuf_size;
    int                         sendbuf_size;
    /*
     * insttype == VACC_HOST_INSTTYPE_SERVER_LISTENER : sock_fd = server listen socket fd
     * insttype == VACC_HOST_INSTTYPE_SERVER_INST     : sock_fd = instance socket fd
     * insttype == VACC_HOST_INSTTYPE_CLIENT_INST     : sock_fd = instance socket fd
     */
    int                         sock_fd;            /*  */
    int                         n_client_inst;      /* number of VACC_HOST_INSTTYPE_SERVER_INST */
    void                        *opaque;
} vacc_host_t;

typedef struct {
    vacc_host_transtype_e       transtype;
    vacc_host_insttype_e        insttype;

    union {
        struct {
            char                srv_ip[VACC_HOST_MAXPATHLEN];
            unsigned short      srv_port;
        } tcp;
        struct {
            char                srv_ip[VACC_HOST_MAXPATHLEN];
            unsigned short      srv_port;
        } udp;
        struct {
            char path[VACC_HOST_MAXPATHLEN];
            struct _vacc_host   *server_listener;
        } uds;
    } u;

    vacc_host_cb_get            cb_get;
    vacc_host_cb_put            cb_put;
    vacc_host_cb_init           cb_init;
    vacc_host_cb_uninit         cb_uninit;
    vacc_host_cb_recv           cb_recv;
    vacc_host_cb_recv_ex        cb_recv_ex;

    protocol_abstract_t         proto_abs;

    int recvbuf_size;
    int sendbuf_size;

    int  n_listen;
    void *opaque;
} vacc_host_create_param_t;

int vacc_host_create(vacc_host_t *vacc_host, const vacc_host_create_param_t *param);
int vacc_host_destroy(vacc_host_t *vacc_host);
int vacc_host_write(vacc_host_t *vacc_host, void *buf, uint32_t len);
int vacc_host_write_ex(vacc_host_t *vacc_host, void *buf, uint32_t len, vacc_host_addr_u *addr);
int vacc_host_read(vacc_host_t *vacc_host, uint8_t *buf, int buf_len);

/* vacc msg define */
#define VACC_MSG_MAX_LEN                (64 * 1024)
typedef struct {
    uint16_t    ver;
    uint16_t    type;
    uint32_t    len;
} vacc_msg_head_t;

typedef enum {
    VACC_MSGTYPE_INVALID = 0,
    VACC_MSGTYPE_DEV_INFO,
    VACC_MSGTYPE_DEV_START,
    VACC_MSGTYPE_DEV_STOP,
    VACC_MSGTYPE_CUSTOM_BEGIN = 0x200,
} vacc_msgtype_e;

#endif

