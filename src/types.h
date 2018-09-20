#ifndef RS_HTTP_RS_TYPES_H
#define RS_HTTP_RS_TYPES_H

#include <stdint.h>
#include <stddef.h>
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/ecc.h>

typedef struct bytes {
    uint8_t * buf;
    size_t len;
} bytes;

struct edhoc_session_state {
    ecc_key key;
    ecc_key peer_key;
    ecc_key eph_key;
    bytes session_id;
    bytes shared_secret;
    bytes message1;
    bytes message2;
    bytes message3;
};
typedef struct edhoc_session_state edhoc_server_session_state;
typedef struct edhoc_session_state edhoc_client_session_state;

typedef struct oscore_context {
    uint8_t master_secret[16];
    uint8_t master_salt[7];
} oscore_context;

#endif //RS_HTTP_RS_TYPES_H