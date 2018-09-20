#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>

#include "utils.h"
#include "cwt.h"
#include "edhoc.h"
#include "protocol.h"
#include "tinycbor/cbor.h"

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/ecc.h>

#define AUDIENCE "tempSensor0"
//#define SHA256_DIGEST_SIZE 32

static edhoc_server_session_state edhoc_state;
static edhoc_client_session_state edhoc_c_state;
uint8_t state_mem[512 * 3];
uint8_t c_state_mem[512 * 3];

uint8_t id_u[64];
uint8_t id_v[64];
uint8_t AS_ID[64] = {0x5a, 0xee, 0xc3, 0x1f, 0x9e, 0x64, 0xaa, 0xd4, 0x5a, 0xba, 0x2d, 0x36, 0x5e, 0x71, 0xe8, 0x4d, 0xee, 0x0d, 0xa3, 0x31, 0xba, 0xda, 0xb9, 0x11, 0x8a, 0x25, 0x31, 0x50, 0x1f, 0xd9, 0x86, 0x1d,
                     0x02, 0x7c, 0x99, 0x77, 0xca, 0x32, 0xd5, 0x44, 0xe6, 0x34, 0x26, 0x76, 0xef, 0x00, 0xfa, 0x43, 0x4b, 0x3a, 0xae, 0xd9, 0x9f, 0x48, 0x23, 0x75, 0x05, 0x17, 0xca, 0x33, 0x90, 0x37, 0x47, 0x53};


static size_t error_buffer(uint8_t* buf, size_t buf_len, char* text) {
    CborEncoder enc;
    cbor_encoder_init(&enc, buf, buf_len, 0);

    CborEncoder map;
    cbor_encoder_create_map(&enc, &map, 1);

    cbor_encode_text_stringz(&map, "error");
    cbor_encode_text_stringz(&map, text);
    cbor_encoder_close_container(&enc, &map);

    return cbor_encoder_get_buffer_size(&enc, buf);
}

int main(int argc, char *argv[]) {

    // Allocate space for stored messages
    edhoc_state.message1.buf = state_mem;
    edhoc_state.message2.buf = state_mem + 512;
    edhoc_state.message3.buf = state_mem + 1024; 
    edhoc_state.shared_secret.buf = malloc(32);
    edhoc_state.shared_secret.len = 32;

    edhoc_c_state.message1.buf = c_state_mem;
    edhoc_c_state.message2.buf = c_state_mem + 512;
    edhoc_c_state.message3.buf = c_state_mem + 1024; 
    edhoc_c_state.shared_secret.buf = malloc(32);
    edhoc_c_state.shared_secret.len = 32;

    // Generate keys
    RNG rng;
    wc_InitRng(&rng);
    
    wc_ecc_init(&(edhoc_state.key));
    wc_ecc_make_key(&rng, 32, &(edhoc_state.key));

    byte pub_key[65];
    word32 pub_key_len = sizeof(pub_key);
    wc_ecc_export_x963(&edhoc_state.key, pub_key, &pub_key_len);
    wc_ecc_import_x963(pub_key, pub_key_len, &edhoc_c_state.peer_key);

    wc_ecc_init(&(edhoc_c_state.key));
    wc_ecc_make_key(&rng, 32, &(edhoc_c_state.key));

    wc_ecc_export_x963(&edhoc_c_state.key, pub_key, &pub_key_len);
    wc_ecc_import_x963(pub_key, pub_key_len, &edhoc_state.peer_key);


    uint8_t message1_buf[512];
    uint8_t message2_buf[512];
    uint8_t message3_buf[512];
    size_t message1_len = initiate_edhoc(&edhoc_c_state, message1_buf, 512);
    size_t message2_len = edhoc_handler_message_1(&edhoc_state, message1_buf, message1_len, message2_buf, 512);
    size_t message3_len = edhoc_handler_message_2(&edhoc_c_state, message2_buf, message2_len, message3_buf, 512);
    edhoc_handler_message_3(&edhoc_state, message3_buf, message3_len);

out:

    return 0;
}