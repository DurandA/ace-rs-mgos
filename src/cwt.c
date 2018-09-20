//
// Created by Urs Gerber on 08.03.18.
//
#include <stdlib.h>

#include "cwt.h"
#include "tinycbor/cbor.h"
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include "utils.h"

#define CBOR_LABEL_COSE_KEY 25
#define CBOR_LABEL_AUDIENCE 3

void cwt_parse(rs_cwt* cwt, uint8_t* encoded, size_t len) {
    CborParser parser;
    CborValue value;

    uint8_t* enc = encoded;
    cbor_parser_init(enc, len, 0, &parser, &value);

    CborTag tag;
    cbor_value_get_tag(&value, &tag);
    cbor_value_advance(&value);

    CborValue elem;
    cbor_value_enter_container(&value, &elem);

    cwt->h_protected = elem;
    cbor_value_advance(&elem);

    cwt->h_unprotected = elem;
    cbor_value_advance(&elem);

    cwt->payload = elem;
    cbor_value_advance(&elem);

    cwt->signature = elem;
}

int cwt_verify(rs_cwt* cwt, bytes *eaad, ecc_key *peer_key) {
    CborEncoder enc;
    uint8_t buffer[256];
    cbor_encoder_init(&enc, buffer, 256, 0);

    CborEncoder ary;
    cbor_encoder_create_array(&enc, &ary, 4);
    cbor_encode_text_stringz(&ary, "Signature1");

    uint8_t* protected;
    size_t len;
    cbor_value_dup_byte_string(&cwt->h_protected, &protected, &len, NULL);
    cbor_encode_byte_string(&ary, protected, len);
    free(protected);

    cbor_encode_byte_string(&ary, eaad->buf, eaad->len);

    uint8_t* payload;
    size_t p_len;
    cbor_value_dup_byte_string(&cwt->payload, &payload, &p_len, NULL);
    cbor_encode_byte_string(&ary, payload, p_len);
    free(payload);

    cbor_encoder_close_container(&enc, &ary);
    size_t buf_len = cbor_encoder_get_buffer_size(&enc, buffer);

    // Compute digest
    uint8_t digest[32];
    //atcab_sha((uint16_t) buf_len, (const uint8_t*) buffer, digest);
    Sha256 sha;
    wc_InitSha256(&sha);
    wc_Sha256Update(&sha, buffer, buf_len);
    wc_Sha256Final(&sha, digest);

    // Extract Signature
    uint8_t* signature;
    size_t sig_len;
    cbor_value_dup_byte_string(&cwt->signature, &signature, &sig_len, NULL);
    
    int verified = 0;
    //atcab_verify_extern(digest, signature, key, &verified);
    char r[65];
    char s[65];
    char hexmap[] = {'0', '1', '2', '3', '4', '5', '6', '7',
                    '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
    for(int i=0; i<32; i++){
        r[2 * i] = hexmap[(signature[i] & 0xF0) >> 4];
        r[2 * i + 1] = hexmap[signature[i] & 0x0F];
        s[2 * i] = hexmap[(signature[i + 32] & 0xF0) >> 4];
        s[2 * i + 1] = hexmap[signature[i + 32] & 0x0F];
    }
    r[64] = '\0';
    s[64] = '\0';

    byte sig[wc_ecc_sig_size(peer_key)];
    word32 sigSz = sizeof(sig);
    wc_ecc_rs_to_sig(r, s, sig, &sigSz);
    wc_ecc_verify_hash(sig, sigSz, digest, sizeof(digest), &verified, peer_key);
    
    free(signature);

    return verified;
}

void cwt_parse_payload(rs_cwt* cwt, rs_payload* out) {
    uint8_t* payload;
    size_t len;

    cbor_value_dup_byte_string(&cwt->payload, &payload, &len, NULL);

    CborParser parser;
    CborValue map;
    cbor_parser_init(payload, len, 0, &parser, &map);

    CborValue elem;
    cbor_value_enter_container(&map, &elem);

    while (!cbor_value_at_end(&elem)) {
        int label;
        cbor_value_get_int(&elem, &label);
        cbor_value_advance(&elem);

        if (label == CBOR_LABEL_AUDIENCE) {
            char* audience;
            size_t aud_len;
            cbor_value_dup_text_string(&elem, &audience, &aud_len, &elem);
            out->aud = audience;
        } else if (label == CBOR_LABEL_COSE_KEY) {
            CborValue cnf_elem;
            cbor_value_enter_container(&elem, &cnf_elem);

            int cnf_tag;
            cbor_value_get_int(&cnf_elem, &cnf_tag);
            cbor_value_advance(&cnf_elem);

            uint8_t* cnf;
            size_t cnf_len;
            cbor_value_dup_byte_string(&cnf_elem, &cnf, &cnf_len, &cnf_elem);
            out->cnf = (bytes) {cnf, cnf_len};

            cbor_value_leave_container(&elem, &cnf_elem);
        } else {
            cbor_value_advance(&elem);
        }
    }

    free(payload);
}

#define CBOR_LABEL_COSE_KEY_KTY 1
#define CBOR_LABEL_COSE_KEY_KID 2
#define CBOR_LABEL_COSE_KEY_CRV (-1)
#define CBOR_LABEL_COSE_KEY_X (-2)
#define CBOR_LABEL_COSE_KEY_Y (-3)

void cwt_parse_cose_key(bytes* encoded, cose_key* out) {
    out->kid = (bytes) {NULL, 0};

    CborParser parser;
    CborValue map;

    cbor_parser_init(encoded->buf, encoded->len, 0, &parser, &map);

    CborValue elem;
    cbor_value_enter_container(&map, &elem);

    while (!cbor_value_at_end(&elem)) {
        int label;
        cbor_value_get_int(&elem, &label);
        cbor_value_advance(&elem);

        if (label == CBOR_LABEL_COSE_KEY_KTY) {
            int kty;
            cbor_value_get_int(&elem, &kty);
            cbor_value_advance(&elem);
            out->kty = (uint8_t) kty;
        } else if (label == CBOR_LABEL_COSE_KEY_KID) {
            uint8_t* kid;
            size_t kid_len;
            cbor_value_dup_byte_string(&elem, &kid, &kid_len, &elem);
            out->kid = (bytes) {kid, kid_len};
        } else if (label == CBOR_LABEL_COSE_KEY_CRV) {
            int crv;
            cbor_value_get_int(&elem, &crv);
            cbor_value_advance(&elem);
            out->crv = (uint8_t) crv;
        } else if (label == CBOR_LABEL_COSE_KEY_X) {
            uint8_t* x;
            size_t x_len;
            cbor_value_dup_byte_string(&elem, &x, &x_len, &elem);

            out->x = (bytes) { x, x_len };
        } else if (label == CBOR_LABEL_COSE_KEY_Y) {
            uint8_t* y;
            size_t y_len;
            cbor_value_dup_byte_string(&elem, &y, &y_len, &elem);

            out->y = (bytes) { y, y_len };
        } else {
            cbor_value_advance(&elem);
        }
    }
}

void cwt_encode_cose_key(cose_key* key, uint8_t* buffer, size_t buf_size, size_t* len) {
    CborEncoder enc;
    cbor_encoder_init(&enc, buffer, buf_size, 0);
    
    CborEncoder map;
    cbor_encoder_create_map(&enc, &map, 5);
    
    cbor_encode_int(&map, CBOR_LABEL_COSE_KEY_KTY);
    cbor_encode_int(&map, key->kty);
    
    cbor_encode_int(&map, CBOR_LABEL_COSE_KEY_CRV);
    cbor_encode_int(&map, key->crv);

    cbor_encode_int(&map, CBOR_LABEL_COSE_KEY_X);
    cbor_encode_byte_string(&map, key->x.buf, key->x.len);

    cbor_encode_int(&map, CBOR_LABEL_COSE_KEY_Y);
    cbor_encode_byte_string(&map, key->y.buf, key->y.len);

    cbor_encode_int(&map, CBOR_LABEL_COSE_KEY_KID);
    cbor_encode_byte_string(&map, key->kid.buf, key->kid.len);

    cbor_encoder_close_container(&enc, &map);

    *len = cbor_encoder_get_buffer_size(&enc, buffer);
}

void cwt_encode_ecc_key(uint8_t* key, uint8_t* buffer, size_t buf_size, size_t* len) {
    cose_key cose = {
            .crv = 1, // P-256
            .kid = (bytes) {(uint8_t *) "abcd", 4},
            .kty = 2, // EC2
            .x = (bytes) { key, 32 },
            .y = (bytes) { key+32, 32 }
    };

    cwt_encode_cose_key(&cose, buffer, buf_size, len);
}

void cwt_import_key(uint8_t* key, cose_key* cose) {
    memcpy(key, cose->x.buf, cose->x.len);
    memcpy(key+(cose->x.len), cose->y.buf, cose->y.len);
}
