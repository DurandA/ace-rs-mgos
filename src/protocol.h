#ifndef PROTOCOL_EDHOC_H
#define PROTOCOL_EDHOC_H

#include "types.h"

//#define SHA256_DIGEST_SIZE 32

size_t initiate_edhoc(edhoc_client_session_state* ctx, uint8_t* out, size_t out_size);
size_t edhoc_handler_message_1(edhoc_server_session_state* ctx, const uint8_t* buffer_in, size_t in_len, uint8_t* out, size_t out_size);
size_t edhoc_handler_message_2(edhoc_client_session_state* ctx, const uint8_t* buffer_in, size_t in_len, uint8_t* out, size_t out_size);
void edhoc_handler_message_3(edhoc_server_session_state* ctx, const uint8_t* buffer_in, size_t in_len);

#endif //PROTOCOL_EDHOC_H