#ifndef _PROTOCOL_H_
#define _PROTOCOL_H_

#include <stdint.h>

typedef enum {
    FGFW_PKT_TYPE_REQ = 0x0,
    FGFW_PKT_TYPE_REQ_HELLO,
    FGFW_PKT_TYPE_RESP = 0x100,
    FGFW_PKT_TYPE_RESP_HELLO,
} fgfw_pkt_type_e;

typedef struct {
    fgfw_pkt_type_e     prot_type;
    uint32_t            prot_ver;
} fgfw_pkt_head_t;

#endif