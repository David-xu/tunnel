#include "pub.h"

static int fgfw_transport_pending_enq(fgfw_transport_t *transport, void *buf, int len) {
    int first, second, left = FGFW_PENDING_BUFSIZE - (transport->pending_buf_tail - transport->pending_buf_head);

    if (len > left) {
        /* no enough pending buf left */
        return FGFW_RETVALUE_NOENOUGHRES;
    }

    /* insert into pending buf */
    left = FGFW_PENDING_BUFSIZE - (transport->pending_buf_tail % FGFW_PENDING_BUFSIZE);
    if (left < len) {
        first = left;
    } else {
        first = len;
    }
    second = len - first;
    memcpy(&(transport->pending_buf[FGFW_PENDING_BUFSIZE - left]), buf, first);
    if (second) {
        memcpy(transport->pending_buf, buf + first, second);
    }

    /* enq */
    transport->pending_buf_tail += len;

    return FGFW_RETVALUE_OK;
}

static int fgfw_transport_pending_deq(fgfw_transport_t *transport, void *buf, int len) {
    int first, second, left;

    fgfw_assert(len <= fgfw_transport_get_pending_num(transport));

    left = FGFW_PENDING_BUFSIZE - (transport->pending_buf_head % FGFW_PENDING_BUFSIZE);
    if (left < len) {
        first = left;
    } else {
        first = len;
    }
    second = len - first;
    memcpy(buf, &(transport->pending_buf[FGFW_PENDING_BUFSIZE - left]), first);
    if (second) {
        memcpy(buf + first, transport->pending_buf, second);
    }

    /* deq */
    transport->pending_buf_head += len;

    return FGFW_RETVALUE_OK;
}

static void fgfw_transport_send_pending_try(fgfw_transport_t *transport)
{
    int ret, n_allow_send, n_pending;
    n_pending = fgfw_transport_get_pending_num(transport);

    if (n_pending == 0) {
        return;
    }
    
    /* get the number allow to send */
    n_allow_send = single_token_bucket_consume(&(transport->send_stb), n_pending);
    if (n_allow_send) {
        uint8_t buf[n_pending];
        fgfw_transport_pending_deq(transport, buf, n_allow_send);
        ret = vacc_host_write(&(transport->conn), buf, n_allow_send);
        if (ret) {
            fgfw_err("%s: vacc_host_write() return %d\n", transport->conn_desc, ret);
        }
    }
}

int fgfw_transport_send(fgfw_transport_t *transport, void *buf, int len)
{
    /* to make it simple, always insert all into pending buf fist */
    int ret = fgfw_transport_pending_enq(transport, buf, len);

    fgfw_transport_send_pending_try(transport);

    return ret;
}

int fgfw_transport_fill_token(fgfw_transport_t *transport, int n_token)
{
    single_token_bucket_insert(&(transport->send_stb), n_token);
    fgfw_transport_send_pending_try(transport);

    return 0;
}