#include "pub.h"

void fgfw_transport_pool_dump(fgfw_transport_pool_t *transport_pool)
{
    fgfw_transport_id transport_id;
    fgfw_transport_t *transport;

    fgfw_log("transport list:\n");
    for (transport_id = 0; transport_id < FGFW_MAX_TRANSPORT; transport_id++) {
        transport = &(transport_pool->_transport_res[transport_id]);
        if (transport->valid == 0) {
            continue;
        }
        fgfw_log("\tid %d, bundle id %d, send Bps %d\n"
            "\tsendbuf tail 0x%x head 0x%x, recvbuf tail 0x%x head 0x%x, align_tmp_buf_len %d, aes_128_enable %d\n",
            transport->transport_id, transport->transport_belongs_to_bundle_id, transport->send_bps,
            transport->pending_buf_tail, transport->pending_buf_head, transport->recv_buf_tail, transport->recv_buf_head, transport->align_tmp_buf_len, transport->aes_128_enable);
    }
}

fgfw_transport_id fgfw_transport_pool_get(fgfw_transport_pool_t *transport_pool)
{
    fgfw_transport_t *transport;

    if (transport_pool->free_tail == transport_pool->free_head) {
        return FGFW_RETVALUE_NOENOUGHRES;
    }

    transport = transport_pool->free_list[transport_pool->free_head % FGFW_MAX_TRANSPORT];
    transport_pool->free_head++;

    fgfw_assert(transport->valid == 0);

    transport->valid = 1;

    return transport->transport_id;
}

int fgfw_transport_pool_put(fgfw_transport_pool_t *transport_pool, fgfw_transport_id transport_id)
{
    fgfw_transport_t *transport = &(transport_pool->_transport_res[transport_id]);

    if (transport_pool->free_tail == (transport_pool->free_head + FGFW_MAX_TRANSPORT)) {
        return FGFW_RETVALUE_ERR;
    }

    fgfw_assert(transport->transport_id < FGFW_MAX_TRANSPORT);
    fgfw_assert(transport->valid == 1);

    transport->valid = 0;

    transport_pool->free_list[transport_pool->free_tail % FGFW_MAX_TRANSPORT] = transport;
    transport_pool->free_tail++;
    return FGFW_RETVALUE_OK;
}

static int fgfw_transport_pending_enq(fgfw_transport_t *transport, void *buf, int len) {
    int i, first, second, left;
    
    // pthread_mutex_lock(&(transport->transport_op_big_lock));

    left = FGFW_PENDING_BUFSIZE - (transport->pending_buf_tail - transport->pending_buf_head);

    fgfw_assert((len & (FGFW_TRANSPORT_PKT_ALIGN - 1)) == 0);

    if (len > left) {
        // pthread_mutex_unlock(&(transport->transport_op_big_lock));

        fgfw_warn("transport %d, buff afull, len %d\n", transport->transport_id, len);
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

    fgfw_assert((first & (FGFW_TRANSPORT_PKT_ALIGN - 1)) == 0);
    fgfw_assert((second & (FGFW_TRANSPORT_PKT_ALIGN - 1)) == 0);

    /* first */
    if (transport->aes_128_enable) {
        for (i = 0; i < first; i += FGFW_TRANSPORT_PKT_ALIGN) {
            AES_ecb_encrypt(
                buf + i,
                &(transport->pending_buf[FGFW_PENDING_BUFSIZE - left]) + i,
                &(transport->aes_128_enc_key), AES_ENCRYPT);
        }
    } else {
        memcpy(&(transport->pending_buf[FGFW_PENDING_BUFSIZE - left]), buf, first);
    }
    /* second */
    if (second) {
        if (transport->aes_128_enable) {
            for (i = 0; i < second; i += FGFW_TRANSPORT_PKT_ALIGN) {
                AES_ecb_encrypt(
                    buf + first + i,
                    transport->pending_buf + i,
                    &(transport->aes_128_enc_key), AES_ENCRYPT);
            }
        } else {
            memcpy(transport->pending_buf, buf + first, second);
        }
    }

    rte_wmb();

    /* enq */
    transport->pending_buf_tail += len;

    // pthread_mutex_unlock(&(transport->transport_op_big_lock));

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
            fgfw_assert(0);
            fgfw_err("%s: vacc_host_write() return %d\n", transport->conn_desc, ret);
        }
    }
}

int fgfw_transport_fill_token(fgfw_transport_t *transport, int n_token)
{
    single_token_bucket_insert(&(transport->send_stb), n_token);
    fgfw_transport_send_pending_try(transport);

    return 0;
}

int fgfw_transport_pool_fill_token_all(fgfw_transport_pool_t *transport_pool, int cycle_ms)
{
    int i, n_token;
    fgfw_transport_t *transport;

    for (i = 0; i < FGFW_MAX_TRANSPORT; i++) {
        transport = &(transport_pool->_transport_res[i]);
        n_token = transport->send_bps / (1000 / cycle_ms);
        fgfw_transport_fill_token(transport, n_token);
    }

    return FGFW_RETVALUE_OK;
}

int fgfw_transport_send(fgfw_transport_t *transport, void *buf, int len)
{
    if (len & (FGFW_TRANSPORT_PKT_ALIGN - 1)) {
        fgfw_assert(0);
        return FGFW_RETVALUE_NOTALIGN;
    }

    /* to make it simple, always insert all into pending buf fist */
    int ret = fgfw_transport_pending_enq(transport, buf, len);
    if (ret) {
        /* need return this err */
    }
#if 0
    /* don't do real send, only do send after fill token */
    fgfw_transport_send_pending_try(transport);
#endif
    return ret;
}

/*
 * do aes decode, result will saved in transport->recv_buf
 * return
 *    FGFW_RETVALUE_NOENOUGHSPACE :  need to do retry
 */
int fgfw_transport_recv(fgfw_transport_t *transport, void *buf, int len)
{
    int i, left = len, offset = 0, curlen, first, second;

    fgfw_assert((transport->recv_buf_tail - transport->recv_buf_head) <= FGFW_TRANSPORT_RECVBUF_SIZE);

    /* no enough buf space to store */
    if ((int)(FGFW_TRANSPORT_RECVBUF_SIZE - (transport->recv_buf_tail - transport->recv_buf_head)) < len) {
        return FGFW_RETVALUE_NOENOUGHSPACE;
    }

    while (left) {
        if (transport->align_tmp_buf_len) {
            curlen = FGFW_TRANSPORT_PKT_ALIGN - transport->align_tmp_buf_len;
            if (curlen > left) {
                curlen = left;
            }
            fgfw_assert(offset == 0);
            memcpy(transport->align_tmp_buf + transport->align_tmp_buf_len, buf + offset, curlen);

            transport->align_tmp_buf_len += curlen;

            if (transport->align_tmp_buf_len == FGFW_TRANSPORT_PKT_ALIGN) {
                if (transport->aes_128_enable) {
                    /* do aes decode */
                    AES_ecb_encrypt(
                        transport->align_tmp_buf,
                        &(transport->recv_buf[transport->recv_buf_tail % FGFW_TRANSPORT_RECVBUF_SIZE]),
                        &(transport->aes_128_dec_key), AES_DECRYPT);
                } else {
                    memcpy(&(transport->recv_buf[transport->recv_buf_tail % FGFW_TRANSPORT_RECVBUF_SIZE]),
                        transport->align_tmp_buf, FGFW_TRANSPORT_PKT_ALIGN);
                }

                transport->recv_buf_tail += FGFW_TRANSPORT_PKT_ALIGN;
                transport->align_tmp_buf_len = 0;

                fgfw_assert((transport->recv_buf_tail & (FGFW_TRANSPORT_PKT_ALIGN - 1)) == 0);
            }
        } else {
            curlen = left;
            if (curlen >= FGFW_TRANSPORT_PKT_ALIGN) {
                /* align to FGFW_TRANSPORT_PKT_ALIGN */
                curlen &= ~(FGFW_TRANSPORT_PKT_ALIGN - 1);

                first = FGFW_TRANSPORT_RECVBUF_SIZE - (transport->recv_buf_tail % FGFW_TRANSPORT_RECVBUF_SIZE);
                if (first > curlen) {
                    first = curlen;
                }
                second = curlen - first;

                fgfw_assert((first & (FGFW_TRANSPORT_PKT_ALIGN - 1)) == 0);
                fgfw_assert((second & (FGFW_TRANSPORT_PKT_ALIGN - 1)) == 0);

                /* first */
                if (transport->aes_128_enable) {
                    for (i = 0; i < first; i += FGFW_TRANSPORT_PKT_ALIGN) {
                        /* do aes decode */
                        AES_ecb_encrypt(
                            buf + offset + i,
                            &(transport->recv_buf[transport->recv_buf_tail % FGFW_TRANSPORT_RECVBUF_SIZE]) + i,
                            &(transport->aes_128_dec_key), AES_DECRYPT);
                    }
                } else {
                    memcpy(&(transport->recv_buf[transport->recv_buf_tail % FGFW_TRANSPORT_RECVBUF_SIZE]),
                        buf + offset, first);
                }
                /* second */
                if (second) {
                    if (transport->aes_128_enable) {
                        for (i = 0; i < second; i += FGFW_TRANSPORT_PKT_ALIGN) {
                            /* do aes decode */
                            AES_ecb_encrypt(
                                buf + offset + first + i,
                                transport->recv_buf + i,
                                &(transport->aes_128_dec_key), AES_DECRYPT);
                        }
                    } else {
                        memcpy(transport->recv_buf, buf + offset + first, second);
                    }
                }

                transport->recv_buf_tail += curlen;

                fgfw_assert((transport->recv_buf_tail & (FGFW_TRANSPORT_PKT_ALIGN - 1)) == 0);
            } else {
                /* no enouth FGFW_TRANSPORT_PKT_ALIGN, just copy info transport->align_tmp_buf */
                fgfw_assert(transport->align_tmp_buf_len == 0);

                memcpy(transport->align_tmp_buf, buf + offset, curlen);
                transport->align_tmp_buf_len = curlen;
            }
        }

        left -= curlen;
        offset += curlen;
    }

    return FGFW_RETVALUE_OK;
}
