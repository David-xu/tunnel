#ifndef _PROTOCOL_H_
#define _PROTOCOL_H_

#include <stdint.h>

/****************************************************************************************************
 * tunnel protocol
 */

#define FGFW_TUNNEL_PROTOCOL_MAGIC                          0x57464746
#define FGFW_TUNNEL_PROTOCOL_PKTLEN_ALIGN                   FGFW_TRANSPORT_PKT_ALIGN

static inline uint32_t fgfw_tunnel_protocol_align(int len) {
    uint32_t tmp = FGFW_TUNNEL_PROTOCOL_PKTLEN_ALIGN - 1;
    return ((len + tmp) & (~tmp));
}

typedef enum {
    FGFW_TP_TYPE_REQ = 0,
    FGFW_TP_TYPE_REQ_BUNDLE_JOIN,
    FGFW_TP_TYPE_REQ_SESSION_NEW,
    FGFW_TP_TYPE_REQ_SESSION_DEL,

    FGFW_TP_TYPE_RESP = 0x100,
    FGFW_TP_TYPE_RESP_BUNDLE_JOIN_ACK,
    FGFW_TP_TYPE_RESP_SESSION_NEW_ACK,
    FGFW_TP_TYPE_RESP_SESSION_DEL_ACK,

    FGFW_TP_TYPE_SESSION_DATA = 0x200,
} fgfw_tunnel_protocol_type_e;

typedef struct {
    fgfw_tunnel_protocol_type_e tp_type;
    uint32_t                    real_len;                   /* include this struct */
    uint32_t                    align_len;                  /* include this struct, align to FGFW_TUNNEL_PROTOCOL_PKTLEN_ALIGN */
    uint32_t                    challenge;                  /* make all pkt not same */
} fgfw_tunnel_protocol_pkt_head_t;

typedef struct {
    uint32_t        magic;
    char            src_ipstr[INET_ADDRSTRLEN];
    uint32_t        pid_at_cli;                             /* client's pid */
    uint32_t        key_len;
    uint8_t         key[64];
} fgfw_tunnel_protocol_pkt_bundle_join_req_t;

typedef struct {
    uint32_t        magic;
    int             ret;
    uint32_t        bundle_id;                              /* srv return */
} fgfw_tunnel_protocol_pkt_bundle_join_resp_t;

typedef struct {
    uint32_t        magic;
    uint32_t        port;
    uint32_t        src_session_id;
} fgfw_tunnel_protocol_pkt_session_new_req_t;

typedef struct {
    uint32_t        magic;
    int             ret;
    uint32_t        src_session_id;                         /* produced by server */
    uint32_t        dst_session_id;                         /* origin session id in client */
} fgfw_tunnel_protocol_pkt_session_new_resp_t;

typedef struct {
    uint32_t        magic;
    uint32_t        src_session_id;                         /*  */
    uint32_t        dst_session_id;                         /*  */
} fgfw_tunnel_protocol_pkt_session_del_req_t;

typedef struct {
    uint32_t        magic;
    int             ret;
    uint32_t        src_session_id;                         /*  */
    uint32_t        dst_session_id;                         /*  */
} fgfw_tunnel_protocol_pkt_session_del_resp_t;

typedef struct {
    uint32_t        src_session_id;
    uint32_t        dst_session_id;                         /* indicate session, after 'session create' proc, produced by tunnel server */
    uint64_t        session_offset;
} fgfw_tunnel_protocol_pkt_session_data_t;

#endif