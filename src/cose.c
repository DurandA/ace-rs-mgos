#include <stdlib.h>

#include "cose.h"
#include "utils.h"
#include "tinycbor/cbor.h"
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/sha.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/hmac.h>
#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/wolfcrypt/wolfmath.h>
#include <wolfssl/wolfcrypt/aes.h>
#include "hkdf.h"

#define DIGEST_SIZE 32
#define TAG_SIZE 8

void cose_encode_signed(cose_sign1* sign1, ecc_key key,
                        uint8_t* out, size_t out_size, size_t* out_len) {
    uint8_t sign_structure[256];
    size_t sign_struct_len = sizeof(sign_structure);

    cose_sign1_structure("Signature1", &sign1->protected_header, &sign1->external_aad, &sign1->payload,
                         sign_structure, sizeof(sign_structure), &sign_struct_len);

    //printf("to_verify: ");
    //phex(sign_structure, sign_struct_len);

    // Hash sign structure
    //atcab_sha((uint16_t) sign_struct_len, (const uint8_t*) sign_structure, digest);
    uint8_t digest[DIGEST_SIZE];
    Sha256 sha;
    wc_InitSha256(&sha);
    wc_Sha256Update(&sha, sign_structure, sign_struct_len);
    wc_Sha256Final(&sha, digest);


    // Compute signature
    uint8_t der[72];
    uint8_t signature[64];

    //atcab_sign(key_id, digest, signature);
    RNG rng;
    wc_InitRng(&rng);

    
    int derSz = sizeof(der);
    int ret = wc_ecc_sign_hash(digest, DIGEST_SIZE, der, &derSz, &rng, &key);
    

    // Convert DER to r and s
    uint8_t rLen = der[3];
    uint8_t sLen = der[5 + rLen];
    memcpy(signature, der + 4 + (rLen == 32 ? 0 : 1), 32);
    memcpy(signature + 32, der + 6 + rLen + (sLen == 32 ? 0 : 1), 32);

    char r[32];
    char s[32];
    memcpy(r, signature, 32);
    memcpy(s, signature + 32, 32);    

    // Encode sign1 structure
    CborEncoder enc;
    cbor_encoder_init(&enc, out, out_size, 0);
    cbor_encode_tag(&enc, 18);

    CborEncoder ary;
    cbor_encoder_create_array(&enc, &ary, 4);

    cbor_encode_byte_string(&ary, sign1->protected_header.buf, sign1->protected_header.len);
    cbor_encode_byte_string(&ary, sign1->unprotected_header.buf, sign1->unprotected_header.len);
    cbor_encode_byte_string(&ary, sign1->payload.buf, sign1->payload.len);
    cbor_encode_byte_string(&ary, signature, sizeof(signature));

    cbor_encoder_close_container(&enc, &ary);
    *out_len = cbor_encoder_get_buffer_size(&enc, out);
}

void cose_sign1_structure(const char* context,
                          bytes* body_protected,
                          bytes* external_aad,
                          bytes* payload,
                          uint8_t* out,
                          size_t out_size,
                          size_t* out_len) {

    CborEncoder enc;
    cbor_encoder_init(&enc, out, out_size, 0);

    CborEncoder ary;
    cbor_encoder_create_array(&enc, &ary, 4);

    cbor_encode_text_stringz(&ary, context);
    cbor_encode_byte_string(&ary, body_protected->buf, body_protected->len);
    cbor_encode_byte_string(&ary, external_aad->buf, external_aad->len);
    cbor_encode_byte_string(&ary, payload->buf, payload->len);

    cbor_encoder_close_container(&enc, &ary);
    *out_len = cbor_encoder_get_buffer_size(&enc, out);
}

void cose_encode_encrypted(cose_encrypt0 *enc0, uint8_t *key, uint8_t *iv, uint8_t *out, size_t out_size, size_t *out_len) {
    uint8_t* prot_header;
    size_t prot_len = hexstring_to_buffer(&prot_header, "a1010c", strlen("a1010c"));
    bytes b_prot_header = {prot_header, prot_len};

    // Compute aad
    uint8_t aad[128];
    size_t aad_len;
    cose_enc0_structure(&b_prot_header, &enc0->external_aad, aad, sizeof(aad), &aad_len);

    // Encrypt
    uint8_t ciphertext[enc0->plaintext.len + TAG_SIZE];

    Aes aes;
    wc_AesCcmSetKey(&aes, key, 16);
    wc_AesCcmEncrypt(&aes, ciphertext, enc0->plaintext.buf, enc0->plaintext.len, iv, 7, ciphertext + enc0->plaintext.len, TAG_SIZE , aad, aad_len);
    printf("PLAINTEXT: ");
    phex(enc0->plaintext.buf, enc0->plaintext.len);
    printf("CIPHERTEXT: ");
    phex(ciphertext, enc0->plaintext.len);
    printf("TAG: ");
    phex(ciphertext + enc0->plaintext.len, TAG_SIZE);


    // Encode
    CborEncoder enc;
    cbor_encoder_init(&enc, out, out_size, 0);
    cbor_encode_tag(&enc, 16);

    CborEncoder ary;
    cbor_encoder_create_array(&enc, &ary, 3);

    cbor_encode_byte_string(&ary, b_prot_header.buf, b_prot_header.len);
    cbor_encode_byte_string(&ary, NULL, 0);
    cbor_encode_byte_string(&ary, ciphertext, sizeof(ciphertext));

    cbor_encoder_close_container(&enc, &ary);

    *out_len = cbor_encoder_get_buffer_size(&enc, out);

    // Cleanup
    free(prot_header);
}

void cose_enc0_structure(bytes* body_protected, bytes* external_aad,
                         uint8_t* out, size_t out_size, size_t* out_len) {

    CborEncoder enc;
    cbor_encoder_init(&enc, out, out_size, 0);

    CborEncoder ary;
    cbor_encoder_create_array(&enc, &ary, 3);

    cbor_encode_text_stringz(&ary, "Encrypt0");
    cbor_encode_byte_string(&ary, body_protected->buf, body_protected->len);
    cbor_encode_byte_string(&ary, external_aad->buf, external_aad->len);

    cbor_encoder_close_container(&enc, &ary);
    *out_len = cbor_encoder_get_buffer_size(&enc, out);
}

void cose_kdf_context(const char* algorithm_id, int key_length, bytes *other, uint8_t* out, size_t out_size, size_t *out_len) {
    CborEncoder enc;
    cbor_encoder_init(&enc, out, out_size, 0);

    CborEncoder ary;
    cbor_encoder_create_array(&enc, &ary, 4);
    cbor_encode_text_stringz(&ary, algorithm_id);

    CborEncoder partyUInfo;
    cbor_encoder_create_array(&ary, &partyUInfo, 3);
    cbor_encode_null(&partyUInfo);
    cbor_encode_null(&partyUInfo);
    cbor_encode_null(&partyUInfo);
    cbor_encoder_close_container(&ary, &partyUInfo);

    CborEncoder partyVInfo;
    cbor_encoder_create_array(&ary, &partyVInfo, 3);
    cbor_encode_null(&partyVInfo);
    cbor_encode_null(&partyVInfo);
    cbor_encode_null(&partyVInfo);
    cbor_encoder_close_container(&ary, &partyVInfo);

    CborEncoder suppPubInfo;
    cbor_encoder_create_array(&ary, &suppPubInfo, 3);
    cbor_encode_int(&suppPubInfo, key_length);
    cbor_encode_byte_string(&suppPubInfo, NULL, 0);
    cbor_encode_byte_string(&suppPubInfo, other->buf, other->len);
    cbor_encoder_close_container(&ary, &suppPubInfo);

    cbor_encoder_close_container(&enc, &ary);

    *out_len = cbor_encoder_get_buffer_size(&enc, out);
}

void derive_key(bytes *input_key, bytes *info, uint8_t* out, size_t out_size) {
    
    //const mbedtls_md_info_t *sha256 = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    //mbedtls_hkdf(sha256, NULL, 0, input_key->buf, input_key->len, info->buf, info->len, out, out_size);
    wc_HKDF(WC_HASH_TYPE_SHA256, input_key->buf, input_key->len, NULL, 0, info->buf, info->len, out, out_size);
}

void cose_decrypt_enc0(bytes* enc0, uint8_t *key, uint8_t *iv, bytes* external_aad,
                       uint8_t* out, size_t out_size, size_t *out_len) {
    // Parse encoded enc0
    CborParser parser;
    CborValue val;
    cbor_parser_init(enc0->buf, enc0->len, 0, &parser, &val);

    CborTag tag;
    cbor_value_get_tag(&val, &tag);
    cbor_value_advance(&val);

    CborValue e;
    cbor_value_enter_container(&val, &e);

    bytes protected;
    cbor_value_dup_byte_string(&e, &protected.buf, &protected.len, &e);

    // Skip unprotected header
    cbor_value_advance(&e);

    bytes ciphertext;
    cbor_value_dup_byte_string(&e, &ciphertext.buf, &ciphertext.len, &e);
    cbor_value_leave_container(&val, &e);

    // Compute AAD
    uint8_t aad[64];
    size_t aad_len;
    cose_enc0_structure(&protected, external_aad, aad, sizeof(aad), &aad_len);

    // Allocate Resources
    uint8_t plaintext[ciphertext.len - TAG_SIZE];
    uint8_t auth_tag[TAG_SIZE];
    memcpy(auth_tag, ciphertext.buf + ciphertext.len - TAG_SIZE, TAG_SIZE);

    // Decrypt

    Aes aes;
    wc_AesCcmSetKey(&aes, key, 16);
    wc_AesCcmDecrypt(&aes, plaintext, ciphertext.buf, sizeof(plaintext), iv, 7, auth_tag, TAG_SIZE, aad, aad_len);
    printf("CIPHERTEXT: ");
    phex(ciphertext.buf, sizeof(plaintext));


    printf("PLAINTEXT: ");
    phex(plaintext, sizeof(plaintext));

    // Return plaintext to caller
    memcpy(out, plaintext, sizeof(plaintext));
    *out_len = sizeof(plaintext);

    // Clean up
    free(protected.buf);
    free(ciphertext.buf);
}

int cose_verify_sign1(bytes* sign1, ecc_key *peer_key, bytes* external_aad) {
    /// Parse
    CborParser parser;
    CborValue val;
    cbor_parser_init(sign1->buf, sign1->len, 0, &parser, &val);

    CborTag tag;
    cbor_value_get_tag(&val, &tag);
    cbor_value_advance(&val);

    CborValue e;
    cbor_value_enter_container(&val, &e);

    bytes protected;
    cbor_value_dup_byte_string(&e, &protected.buf, &protected.len, &e);

    // Skip unprotected header
    cbor_value_advance(&e);

    bytes payload;
    cbor_value_dup_byte_string(&e, &payload.buf, &payload.len, &e);

    bytes signature;
    cbor_value_dup_byte_string(&e, &signature.buf, &signature.len, &e);

    // Verify
    uint8_t to_verify[256];
    size_t to_verify_len;
    cose_sign1_structure("Signature1", &protected, external_aad, &payload, to_verify, sizeof(to_verify), &to_verify_len);

    // Compute digest
    uint8_t digest[DIGEST_SIZE];
    //atcab_sha((uint16_t) to_verify_len, (const uint8_t*) to_verify, digest);
    Sha256 sha;
    wc_InitSha256(&sha);
    wc_Sha256Update(&sha, to_verify, to_verify_len);
    wc_Sha256Final(&sha, digest);


    int verified = 0;
    //atcab_verify_extern(digest, signature.buf, NULL, &verified);
    char r[65];
    char s[65];
    char hexmap[] = {'0', '1', '2', '3', '4', '5', '6', '7',
                    '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
    for(int i=0; i<32; i++){
        r[2 * i] = hexmap[(signature.buf[i] & 0xF0) >> 4];
        r[2 * i + 1] = hexmap[signature.buf[i] & 0x0F];
        s[2 * i] = hexmap[(signature.buf[i + 32] & 0xF0) >> 4];
        s[2 * i + 1] = hexmap[signature.buf[i + 32] & 0x0F];
    }
    r[64] = '\0';
    s[64] = '\0';

    byte sig[wc_ecc_sig_size(peer_key)];
    word32 sigSz = sizeof(sig);
    wc_ecc_rs_to_sig(r, s, sig, &sigSz);
    int ret = wc_ecc_verify_hash(sig, sigSz, digest, DIGEST_SIZE, &verified, peer_key);

    // Cleanup
    free(protected.buf);
    free(payload.buf);
    free(signature.buf);

    return verified;
}
