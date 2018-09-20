#include <stdlib.h>

#include "edhoc.h"
#include "cose.h"
#include "tinycbor/cbor.h"
#include "utils.h"

#define DIGEST_SIZE 32

void edhoc_msg_1_free(edhoc_msg_1 *msg1) {
    free(msg1->session_id.buf);
    free(msg1->nonce.buf);
    free(msg1->eph_key.buf);
    //free(msg1);
}

void edhoc_msg_2_free(edhoc_msg_2 *msg2) {
    free(msg2->session_id.buf);
    free(msg2->peer_session_id.buf);
    free(msg2->peer_nonce.buf);
    free(msg2->peer_key.buf);
    free(msg2->cose_enc_2.buf);
    //free(msg2);
}

void edhoc_msg_3_free(edhoc_msg_3 *msg3) {
    free(msg3->peer_session_id.buf);
    free(msg3->cose_enc_3.buf);
    //free(msg3);
}

void edhoc_deserialize_msg1(edhoc_msg_1 *msg1, uint8_t* buffer, size_t len) {
    CborParser parser;
    CborValue value;

    uint8_t* copy = buffer;
    cbor_parser_init(copy, len, 0, &parser, &value);

    CborValue elem;
    cbor_value_enter_container(&value, &elem);

    cbor_value_get_uint64(&elem, (uint64_t *) &msg1->tag);
    cbor_value_advance(&elem);

    cbor_value_dup_byte_string(&elem, &msg1->session_id.buf, &msg1->session_id.len, &elem);
    cbor_value_dup_byte_string(&elem, &msg1->nonce.buf, &msg1->nonce.len, &elem);
    cbor_value_dup_byte_string(&elem, &msg1->eph_key.buf, &msg1->eph_key.len, &elem);

    // must free msg.session_id
    // must free msg.nonce
    // must free msg.eph_key
}

void edhoc_deserialize_msg2(edhoc_msg_2 *msg2, uint8_t* buffer, size_t len) {
    CborParser parser;
    CborValue value;

    uint8_t* copy = buffer;
    cbor_parser_init(copy, len, 0, &parser, &value);

    CborValue element;
    cbor_value_enter_container(&value, &element);

    cbor_value_get_uint64(&element, (uint64_t *) &msg2->tag);
    cbor_value_advance(&element); // TODO: double-check

    uint8_t* session_id;
    size_t session_id_len;
    cbor_value_dup_byte_string(&element, &session_id, &session_id_len, &element);

    uint8_t* peer_session_id;
    size_t peer_session_id_len;
    cbor_value_dup_byte_string(&element, &peer_session_id, &peer_session_id_len, &element);

    uint8_t* peer_nonce;
    size_t peer_nonce_len;
    cbor_value_dup_byte_string(&element, &peer_nonce, &peer_nonce_len, &element);

    uint8_t* peer_key;
    size_t peer_key_len;
    cbor_value_dup_byte_string(&element, &peer_key, &peer_key_len, &element);

    uint8_t* cose_enc_2;
    size_t cose_enc_2_length;
    cbor_value_dup_byte_string(&element, &cose_enc_2, &cose_enc_2_length, &element);

    msg2->session_id      = (struct bytes) { session_id, session_id_len };
    msg2->peer_session_id = (struct bytes) { peer_session_id, peer_session_id_len };
    msg2->peer_nonce      = (struct bytes) { peer_nonce, peer_nonce_len };
    msg2->peer_key      = (struct bytes)   { peer_key, peer_key_len };
    msg2->cose_enc_2      = (struct bytes) { cose_enc_2, cose_enc_2_length };

    // must free msg.peer_session_id
    // must free msg.cose_enc_2
}

void edhoc_deserialize_msg3(edhoc_msg_3 *msg3, uint8_t* buffer, size_t len) {
    CborParser parser;
    CborValue value;

    uint8_t* copy = buffer;
    cbor_parser_init(copy, len, 0, &parser, &value);

    CborValue element;
    cbor_value_enter_container(&value, &element);

    cbor_value_get_uint64(&element, (uint64_t *) &msg3->tag);
    cbor_value_advance(&element);

    uint8_t* peer_sess_id;
    size_t peer_sess_id_length;
    cbor_value_dup_byte_string(&element, &peer_sess_id, &peer_sess_id_length, &element);

    uint8_t* cose_enc_3;
    size_t cose_enc_3_length;
    cbor_value_dup_byte_string(&element, &cose_enc_3, &cose_enc_3_length, &element);

    msg3->peer_session_id = (struct bytes) { peer_sess_id, peer_sess_id_length };
    msg3->cose_enc_3      = (struct bytes) { cose_enc_3,   cose_enc_3_length };
    
    // must free msg.peer_session_id
    // must free msg.cose_enc_3
}

size_t edhoc_serialize_msg_1(edhoc_msg_1 *msg1, unsigned char* buffer, size_t buf_size) {
    // Serialize
    CborEncoder enc;
    cbor_encoder_init(&enc, buffer, buf_size, 0);

    CborEncoder ary;
    cbor_encoder_create_array(&enc, &ary, 4);

    cbor_encode_uint(&ary, msg1->tag);
    cbor_encode_byte_string(&ary, msg1->session_id.buf, msg1->session_id.len);
    cbor_encode_byte_string(&ary, msg1->nonce.buf, msg1->nonce.len);
    cbor_encode_byte_string(&ary, msg1->eph_key.buf, msg1->eph_key.len);

    cbor_encoder_close_container(&enc, &ary);

    return cbor_encoder_get_buffer_size(&enc, buffer);
}

size_t edhoc_serialize_msg_2(edhoc_msg_2 *msg2, msg_2_context* context, ecc_key sigkey, unsigned char* buffer, size_t buf_size) {
    // Compute AAD
    uint8_t aad2[DIGEST_SIZE];
    edhoc_aad2(msg2, context->message1, aad2);

    // Compute Signature
    uint8_t sig_v[256];
    size_t sig_v_len = sizeof(sig_v);
    edhoc_msg_sig(aad2, sigkey, sig_v, sizeof(sig_v), &sig_v_len);

    bytes b_sig_v = {sig_v, sig_v_len};
    //printf("sig_v: ");
    //phex(sig_v, sig_v_len);

    // Derive keys
    bytes other = {aad2, DIGEST_SIZE};

    uint8_t context_info_k2[128];
    size_t ci_k2_len;
    cose_kdf_context("AES-CCM-64-64-128", 16, &other, context_info_k2, sizeof(context_info_k2), &ci_k2_len);

    uint8_t context_info_iv2[128];
    size_t ci_iv2_len;
    cose_kdf_context("IV-Generation", 7, &other, context_info_iv2, sizeof(context_info_iv2), &ci_iv2_len);

    bytes b_ci_k2 = {context_info_k2, ci_k2_len};
    bytes b_ci_iv2 = {context_info_iv2, ci_iv2_len};

    uint8_t k2[16];
    derive_key(&context->shared_secret, &b_ci_k2, k2, sizeof(k2));

    uint8_t iv2[7];
    derive_key(&context->shared_secret, &b_ci_iv2, iv2, sizeof(iv2));

    //printf("AAD2: ");
    //phex(aad2, DIGEST_SIZE);
    printf("K2: ");
    phex(k2, 16);
    printf("IV2: ");
    phex(iv2, 7);

    // Encrypt
    uint8_t enc_2[256];
    size_t enc_2_len = sizeof(enc_2);
    bytes b_k2 = {k2, 16};
    bytes b_iv2 = {iv2, 7};
    edhoc_msg_enc_0(aad2, &b_sig_v, &b_k2, &b_iv2, enc_2, sizeof(enc_2), &enc_2_len);

    // Serialize
    CborEncoder enc;
    cbor_encoder_init(&enc, buffer, buf_size, 0);

    CborEncoder ary;
    cbor_encoder_create_array(&enc, &ary, 6);

    cbor_encode_int(&ary, msg2->tag);
    cbor_encode_byte_string(&ary, msg2->session_id.buf, msg2->session_id.len);
    cbor_encode_byte_string(&ary, msg2->peer_session_id.buf, msg2->peer_session_id.len);
    cbor_encode_byte_string(&ary, msg2->peer_nonce.buf, msg2->peer_nonce.len);
    cbor_encode_byte_string(&ary, msg2->peer_key.buf, msg2->peer_key.len);
    cbor_encode_byte_string(&ary, enc_2, enc_2_len);

    cbor_encoder_close_container(&enc, &ary);

    return cbor_encoder_get_buffer_size(&enc, buffer);
}

size_t edhoc_serialize_msg_3(edhoc_msg_3 *msg3, msg_3_context* context, ecc_key key, unsigned char* buffer, size_t buf_size) {
    // Compute AAD
    uint8_t aad3[DIGEST_SIZE];
    edhoc_aad3(msg3, context->message1, context->message2, aad3);

    // Compute Signature
    uint8_t sig_u[256];
    size_t sig_u_len = sizeof(sig_u);
    edhoc_msg_sig(aad3, key, sig_u, sizeof(sig_u), &sig_u_len);

    bytes b_sig_u = {sig_u, sig_u_len};
    //printf("sig_v: ");
    //phex(sig_v, sig_v_len);

    // Derive keys
    bytes other = {aad3, DIGEST_SIZE};

    uint8_t context_info_k3[128];
    size_t ci_k3_len;
    cose_kdf_context("AES-CCM-64-64-128", 16, &other, context_info_k3, sizeof(context_info_k3), &ci_k3_len);

    uint8_t context_info_iv3[128];
    size_t ci_iv3_len;
    cose_kdf_context("IV-Generation", 7, &other, context_info_iv3, sizeof(context_info_iv3), &ci_iv3_len);

    bytes b_ci_k3 = {context_info_k3, ci_k3_len};
    bytes b_ci_iv3 = {context_info_iv3, ci_iv3_len};

    uint8_t k3[16];
    derive_key(&context->shared_secret, &b_ci_k3, k3, sizeof(k3));

    uint8_t iv3[7];
    derive_key(&context->shared_secret, &b_ci_iv3, iv3, sizeof(iv3));

    //printf("AAD2: ");
    //phex(aad2, DIGEST_SIZE);
    printf("K3: ");
    phex(k3, 16);
    printf("IV3: ");
    phex(iv3, 7);

    // Encrypt
    uint8_t enc_3[256];
    size_t enc_3_len = sizeof(enc_3);
    bytes b_k3 = {k3, 16};
    bytes b_iv3 = {iv3, 7};
    edhoc_msg_enc_0(aad3, &b_sig_u, &b_k3, &b_iv3, enc_3, sizeof(enc_3), &enc_3_len);

    // Serialize
    CborEncoder enc;
    cbor_encoder_init(&enc, buffer, buf_size, 0);

    CborEncoder ary;
    cbor_encoder_create_array(&enc, &ary, 3);

    cbor_encode_int(&ary, msg3->tag);
    cbor_encode_byte_string(&ary, msg3->peer_session_id.buf, msg3->peer_session_id.len);
    cbor_encode_byte_string(&ary, enc_3, enc_3_len);

    cbor_encoder_close_container(&enc, &ary);

    return cbor_encoder_get_buffer_size(&enc, buffer);
}

void edhoc_aad2(edhoc_msg_2 *msg2, bytes message1, uint8_t *out_hash) {
    uint8_t data2[256];

    // Compute data2
    CborEncoder enc;
    cbor_encoder_init(&enc, data2, sizeof(data2), 0);

    CborEncoder ary;
    cbor_encoder_create_array(&enc, &ary, 5);

    cbor_encode_int(&ary, msg2->tag);
    cbor_encode_byte_string(&ary, msg2->session_id.buf, msg2->session_id.len);
    cbor_encode_byte_string(&ary, msg2->peer_session_id.buf, msg2->peer_session_id.len);
    cbor_encode_byte_string(&ary, msg2->peer_nonce.buf, msg2->peer_nonce.len);
    cbor_encode_byte_string(&ary, msg2->peer_key.buf, msg2->peer_key.len);

    cbor_encoder_close_container(&enc, &ary);
    size_t data2_len = cbor_encoder_get_buffer_size(&enc, data2);

    //printf("data2: ");
    //phex(data2, data2_len);

    //printf("message1: ");
    //phex(message1.buf, message1.len);

    // Compute aad2
    uint8_t aad2[message1.len + data2_len];

    memcpy(aad2, message1.buf, message1.len);
    memcpy((aad2+message1.len), data2, data2_len);

    Sha256 sha;
    wc_InitSha256(&sha);
    wc_Sha256Update(&sha, aad2, sizeof(aad2));
    wc_Sha256Final(&sha, out_hash);
    //atcab_sha((uint16_t) sizeof(aad2), (const uint8_t*) aad2, out_hash);
}

void edhoc_msg_sig(uint8_t* aad, ecc_key key,
                      uint8_t* out, size_t out_size, size_t* out_len) {

    uint8_t *prot_header, *unprot_header;
    size_t prot_len = hexstring_to_buffer(&prot_header, "a10126", strlen("a10126"));
    size_t unprot_len = hexstring_to_buffer(&unprot_header, "a104524173796d6d65747269634543445341323536", strlen("a104524173796d6d65747269634543445341323536"));

    cose_sign1 signature;
    signature.payload = (bytes) {NULL, 0};
    signature.protected_header = (bytes) {prot_header, prot_len};
    signature.unprotected_header = (bytes) {unprot_header, unprot_len};
    signature.external_aad = (bytes) {(uint8_t *) aad, DIGEST_SIZE};

    cose_encode_signed(&signature, key, out, out_size, out_len);

    free(prot_header);
    free(unprot_header);
}

void edhoc_msg_enc_0(uint8_t *aad, bytes *signature, bytes *key, bytes *iv,
                      uint8_t* out, size_t out_size, size_t* out_len) {
    bytes eaad = {aad, DIGEST_SIZE};
    cose_encrypt0 enc = {
            .external_aad = eaad,
            .plaintext = *signature
    };

    cose_encode_encrypted(&enc, key->buf, iv->buf, out, out_size, out_len);
}

void edhoc_aad3(edhoc_msg_3* msg3, bytes message1, bytes message2,
                uint8_t* out_hash) {

    // Combine msg1+msg2;
    uint8_t combined[message1.len + message2.len];
    memcpy(combined, message1.buf, message1.len);
    memcpy(combined+message1.len, message2.buf, message2.len);

    uint8_t digest[DIGEST_SIZE];
    //atcab_sha((uint16_t) sizeof(combined), (const uint8_t*) combined, digest);
    Sha256 sha;
    wc_InitSha256(&sha);
    wc_Sha256Update(&sha, combined, sizeof(combined));
    wc_Sha256Final(&sha, digest);

    // Compute data3
    uint8_t data3[64];

    CborEncoder enc;
    cbor_encoder_init(&enc, data3, sizeof(data3), 0);

    CborEncoder ary;
    cbor_encoder_create_array(&enc, &ary, 2);

    cbor_encode_int(&ary, msg3->tag);
    cbor_encode_byte_string(&ary, msg3->peer_session_id.buf, msg3->peer_session_id.len);

    cbor_encoder_close_container(&enc, &ary);
    size_t data3_len = cbor_encoder_get_buffer_size(&enc, data3);

    // Combine with data3
    uint8_t final[DIGEST_SIZE + data3_len];
    memcpy(final, digest, DIGEST_SIZE);
    memcpy(final+DIGEST_SIZE, data3, data3_len);
    
    //atcab_sha((uint16_t) sizeof(final), (const uint8_t*) final, out_hash);
    Sha256 sha2;
    wc_InitSha256(&sha2);
    wc_Sha256Update(&sha2, final, sizeof(final));
    wc_Sha256Final(&sha2, out_hash);
}

void oscore_exchange_hash(bytes *msg1, bytes *msg2, bytes *msg3, uint8_t *out_hash) {
    // Combine msg1+msg2;
    uint8_t combined[msg1->len + msg2->len];
    memcpy(combined, msg1->buf, msg1->len);
    memcpy(combined+msg1->len, msg2->buf, msg2->len);
    
    uint8_t digest[DIGEST_SIZE];
    
    //atcab_sha((uint16_t) sizeof(combined), (const uint8_t*) combined, digest);
    Sha256 sha;
    wc_InitSha256(&sha);
    wc_Sha256Update(&sha, combined, sizeof(combined));
    wc_Sha256Final(&sha, digest);

    // Comine with msg3
    uint8_t final[DIGEST_SIZE + msg3->len];
    memcpy(final, digest, DIGEST_SIZE);
    memcpy(final+DIGEST_SIZE, msg3->buf, msg3->len);
    
    //atcab_sha((uint16_t) sizeof(final), (const uint8_t*) final, out_hash);
    Sha256 sha2;
    wc_InitSha256(&sha2);
    wc_Sha256Update(&sha2, final, sizeof(final));
    wc_Sha256Final(&sha2, out_hash);
}

