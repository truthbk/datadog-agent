#ifndef __DTLS_H
#define __DTLS_H

#include "ktypes.h"
#include "bpf_builtins.h"
#include "tls.h"

/* https://datatracker.ietf.org/doc/html/rfc9147#appendix-A.1 A.1. Record Layer */
typedef struct __attribute__((packed)) {
    __u8 app;
    __u16 version;
    __u16 epoch;
    __u32 sequence_number_low;
    __u16 sequence_number_high;
    __u16 length;
} dtls_record_t;

#define DTLS_HEADER_SIZE sizeof(dtls_record_t)

#define DTLS1_VERSION                   0xFEFF
#define DTLS1_2_VERSION                 0xFEFD

static __always_inline bool is_valid_dtls_version(__u16 version) {
    return (version == DTLS1_VERSION) || (version == DTLS1_2_VERSION);
}

static __always_inline bool is_dtls_payload_length_valid(__u8 app, __u16 dtls_len, __u32 buf_size) {
    /* check only for application data layer */
    if (app != TLS_APPLICATION_DATA) {
        return true;
    }

    if (buf_size < (sizeof(dtls_record_t)+dtls_len)) {
        return false;
    }

    return true;
}

static __always_inline bool is_dtls(const char* buf, __u32 buf_size) {
    if (buf_size < DTLS_HEADER_SIZE) {
        return false;
    }

    dtls_record_t *dtls_record = (dtls_record_t *)buf;
    // DTLS use the same content type than TLS
    if (!is_valid_tls_app(dtls_record->app)) {
        return false;
    }

    if (!is_valid_dtls_version(dtls_record->version)) {
        return false;
    }

    if (!is_dtls_payload_length_valid(dtls_record->app, dtls_record->length, buf_size)) {
        return false;
    }

    return true;
}

#endif
