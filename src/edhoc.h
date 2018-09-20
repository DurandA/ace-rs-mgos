#ifndef RS_HTTP_EDHOC_H
#define RS_HTTP_EDHOC_H

#include "types.h"
#include "cose.h"

typedef struct edhoc_msg_1 {
    uint8_t tag;
    bytes session_id;
    bytes nonce;
    bytes eph_key;
} edhoc_msg_1;

typedef struct edhoc_msg_2 {
    uint8_t tag;
    bytes session_id;
    bytes peer_session_id;
    bytes peer_nonce;
    bytes peer_key;
    bytes cose_enc_2;
} edhoc_msg_2;

typedef struct msg_2_context {
    bytes shared_secret;
    bytes enc_key;
    bytes enc_iv;
    bytes message1;
} msg_2_context;

typedef struct edhoc_msg_3 {
    uint8_t tag;
    bytes peer_session_id;
    bytes cose_enc_3;
} edhoc_msg_3;

typedef struct msg_3_context {
    bytes shared_secret;
    bytes message1;
    bytes message2;
} msg_3_context;

void edhoc_msg_1_free(edhoc_msg_1 *msg1);
void edhoc_msg_2_free(edhoc_msg_2 *msg2);
void edhoc_msg_3_free(edhoc_msg_3 *msg3);

size_t edhoc_serialize_msg_1(edhoc_msg_1 *msg1, unsigned char* buffer, size_t buf_size);
size_t edhoc_serialize_msg_2(edhoc_msg_2 *msg2, msg_2_context* context, ecc_key sigkey, unsigned char* buffer, size_t buf_size);
size_t edhoc_serialize_msg_3(edhoc_msg_3 *msg3, msg_3_context* context, ecc_key sigkey, unsigned char* buffer, size_t buf_size);

void edhoc_deserialize_msg1(edhoc_msg_1 *msg1, uint8_t* buffer, size_t len);
void edhoc_deserialize_msg2(edhoc_msg_2 *msg2, uint8_t* buffer, size_t len);
void edhoc_deserialize_msg3(edhoc_msg_3 *msg3, uint8_t* buffer, size_t len);

void edhoc_aad2(edhoc_msg_2 *msg2, bytes message1, uint8_t* out_hash);
void edhoc_msg_sig(uint8_t* aad, ecc_key sigkey,
                   uint8_t* out, size_t out_size, size_t* out_len);

void edhoc_msg_enc_0(uint8_t *aad, bytes *signature, bytes *key, bytes *iv,
                      uint8_t* out, size_t out_size, size_t* out_len);

void edhoc_aad3(edhoc_msg_3* msg3, bytes message1, bytes message2,
                uint8_t* out_hash);

void oscore_exchange_hash(bytes *msg1, bytes *msg2, bytes *msg3, uint8_t *out_hash);

#endif //RS_HTTP_EDHOC_H
