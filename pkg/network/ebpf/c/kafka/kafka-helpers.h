#ifndef __KAFKA_HELPERS_H
#define __KAFKA_HELPERS_H

#include "kafka-types.h"

// Forward declaration
static __always_inline bool try_parse_produce_request(kafka_transaction_t *kafka_transaction);
static __always_inline bool try_parse_fetch_request(kafka_transaction_t *kafka_transaction);
static __always_inline bool extract_and_set_first_topic_name(kafka_transaction_t *kafka_transaction);

// Perform bound validation against the current offset in the Kafka message, so the verifier won't complain
#define VALIDATE_KAFKA_OFFSET(kafka_transaction, current_offset) \
    if (current_offset < kafka_transaction->request_fragment || \
        current_offset > (kafka_transaction->request_fragment + KAFKA_BUFFER_SIZE)) { \
            return false; \
    }

static __inline int32_t read_big_endian_int32(const char* buf) {
    int32_t *val = (int32_t*)buf;
    return bpf_ntohl(*val);
}

static __inline int16_t read_big_endian_int16(const char* buf) {
    int16_t *val = (int16_t*)buf;
    return bpf_ntohs(*val);
}

static __inline bool kafka_read_big_endian_int32(kafka_transaction_t *kafka_transaction, int32_t* result) {
    // Using the barrier macro instructs the compiler to not keep memory values cached in registers across the assembler instruction
    // If we don't use it here, the verifier will classify registers with false type and fail to load the program
    barrier();
    char* current_offset = kafka_transaction->request_fragment + kafka_transaction->base.current_offset_in_request_fragment;
    VALIDATE_KAFKA_OFFSET(kafka_transaction, current_offset);
    *result = read_big_endian_int32(current_offset);
    kafka_transaction->base.current_offset_in_request_fragment += 4;
    return true;
}

static __inline bool kafka_read_big_endian_int16(kafka_transaction_t *kafka_transaction, int16_t* result) {
    // Using the barrier macro instructs the compiler to not keep memory values cached in registers across the assembler instruction
    // If we don't use it here, the verifier will classify registers with false type and fail to load the program
    barrier();
    char* current_offset = kafka_transaction->request_fragment + kafka_transaction->base.current_offset_in_request_fragment;
    VALIDATE_KAFKA_OFFSET(kafka_transaction, current_offset);
    *result = read_big_endian_int16(current_offset);
    kafka_transaction->base.current_offset_in_request_fragment += 2;
    return true;
}

// Checking if the buffer represents kafka message
static __always_inline bool try_parse_request_header(kafka_transaction_t *kafka_transaction) {
    char *request_fragment = kafka_transaction->request_fragment;
    if (request_fragment == NULL) {
        return false;
    }

    int32_t message_size = 0;
    if (!kafka_read_big_endian_int32(kafka_transaction, &message_size)) {
        return false;
    }
    log_debug("kafka: message_size: %d\n", message_size);
    if (message_size <= 0) {
        return false;
    }

    int16_t request_api_key = 0;
    if (!kafka_read_big_endian_int16(kafka_transaction, &request_api_key)) {
        return false;
    }
    log_debug("kafka: request_api_key: %d\n", request_api_key);
    if (request_api_key != KAFKA_FETCH && request_api_key != KAFKA_PRODUCE) {
        // We are only interested in fetch and produce requests
        return false;
    }
    kafka_transaction->base.request_api_key = request_api_key;

    int16_t request_api_version = 0;
    if (!kafka_read_big_endian_int16(kafka_transaction, &request_api_version)) {
        return false;
    }
    log_debug("kafka: request_api_version: %d\n", request_api_version);
    if (request_api_version < 0 || request_api_version > KAFKA_MAX_SUPPORTED_REQUEST_API_VERSION) {
        return false;
    }
    if ((request_api_version == 0) && (request_api_key == KAFKA_PRODUCE)) {
        // We have seen some false positives when both request_api_version and request_api_key are 0,
        // so dropping support for this case
        return false;
    }
    kafka_transaction->base.request_api_version = request_api_version;

    int32_t correlation_id = 0;
    if (!kafka_read_big_endian_int32(kafka_transaction, &correlation_id)) {
        return false;
    }
    log_debug("kafka: correlation_id: %d\n", correlation_id);
    if (correlation_id < 0) {
        return false;
    }
    kafka_transaction->base.correlation_id = correlation_id;

    const int16_t MINIMUM_API_VERSION_FOR_CLIENT_ID = 1;
    if (request_api_version >= MINIMUM_API_VERSION_FOR_CLIENT_ID) {
        int16_t client_id_size = 0;
        if (!kafka_read_big_endian_int16(kafka_transaction, &client_id_size)) {
            return false;
        }
        if (client_id_size < 0) {
            return false;
        }
        kafka_transaction->base.current_offset_in_request_fragment += client_id_size;
        log_debug("kafka: client_id_size: %d\n", client_id_size);
    }
    return true;
}

static __always_inline bool try_parse_request(kafka_transaction_t *kafka_transaction) {
    char *request_fragment = (char*)kafka_transaction->request_fragment;
    if (request_fragment == NULL) {
        return false;
    }

    log_debug("kafka: current_offset: %d\n", kafka_transaction->base.current_offset_in_request_fragment);
    if (kafka_transaction->base.current_offset_in_request_fragment > sizeof(kafka_transaction->request_fragment)) {
        return false;
    }

    switch (kafka_transaction->base.request_api_key) {
        case KAFKA_PRODUCE:
            return try_parse_produce_request(kafka_transaction);
            break;
        case KAFKA_FETCH:
            return try_parse_fetch_request(kafka_transaction);
            break;
        default:
            log_debug("kafka: got unsupported request_api_key: %d\n", kafka_transaction->base.request_api_key);
            return false;
    }
}

static __always_inline bool isMSBSet(uint8_t byte) {
    return (byte & 0x80) != 0;
}

// Based on: https://stackoverflow.com/questions/19758270/read-varint-from-linux-sockets
// The specification for Kafka Unsigned Varints can be found here:
// https://cwiki.apache.org/confluence/display/KAFKA/KIP-482%3A+The+Kafka+Protocol+should+Support+Optional+Tagged+Fields
static __always_inline bool decode_unsigned_varint(kafka_transaction_t *kafka_transaction, uint64_t *decoded_value, uint32_t *decoded_bytes)
{
    uint32_t shift_amount = 0;
    uint64_t decoded_value_in_the_making = 0;

    uint32_t i = 0;
    uint8_t* current_offset = (kafka_transaction->request_fragment + kafka_transaction->base.current_offset_in_request_fragment);
    if (current_offset > kafka_transaction->request_fragment + KAFKA_BUFFER_SIZE) {
        return false;
    }

    #pragma unroll(sizeof(uint64_t))
    for (; i < sizeof(uint64_t); i++) {
        uint8_t current_byte = current_offset[i];
        decoded_value_in_the_making |= (uint64_t)(current_byte & 0x7F) << shift_amount;
        shift_amount += 7;

        if (!isMSBSet(current_offset[i])) {
            break;
        }
    }

    if ((i == sizeof(uint64_t) - 1) && isMSBSet(current_offset[i])) {
        // the last byte in the unsigned varint contains a continuation bit, this shouldn't happen
        return false;
    }

    *decoded_bytes = i + 1;
    *decoded_value = decoded_value_in_the_making;
    return true;
}

static __always_inline bool try_parse_produce_request(kafka_transaction_t *kafka_transaction) {
    log_debug("kafka: trying to parse produce request\n");
    if (kafka_transaction->base.request_api_version >= 10) {
        log_debug("kafka: Produce request version 10 and above is not supported: %d\n", kafka_transaction->base.request_api_version);
        return false;
    }

    if (kafka_transaction->base.request_api_version >= MINIMUM_PRODUCE_API_VERSION_FOR_TAGGED_FIELDS) {
        barrier();
        char* current_offset = kafka_transaction->request_fragment + kafka_transaction->base.current_offset_in_request_fragment;
        VALIDATE_KAFKA_OFFSET(kafka_transaction, current_offset);
        if (*current_offset != 0) {
            // We don't support tagged fields
            return false;
        }
        // Skip tagged fields
        kafka_transaction->base.current_offset_in_request_fragment += 1;
    }

    if (kafka_transaction->base.request_api_version >= 3 && kafka_transaction->base.request_api_version < 9) {
        // transactional_id is of type NULLABLE_STRING, meaning its size is represented as int16
        int16_t transactional_id_size = 0;
        if (!kafka_read_big_endian_int16(kafka_transaction, &transactional_id_size)) {
            return false;
        }
        log_debug("kafka: transactional_id_size: %d\n", transactional_id_size);
        if (transactional_id_size > 0) {
            kafka_transaction->base.current_offset_in_request_fragment += transactional_id_size;
        }
    } else if (kafka_transaction->base.request_api_version >= 9) {
        // transactional_id is of type COMPACT_NULLABLE_STRING, meaning its size is represented as UNSIGNED_VARINT
        uint32_t number_of_decoded_bytes = 0;
        uint64_t transactional_id_size = 0;

        if (!decode_unsigned_varint(kafka_transaction, &transactional_id_size, &number_of_decoded_bytes)) {
            return false;
        }
        kafka_transaction->base.current_offset_in_request_fragment += number_of_decoded_bytes;
        if (transactional_id_size >= 2) {
            // transactional_id_size == 1 -> empty string

            // From COMPACT_NULLABLE_STRING docs: "First the length N + 1 is given as an UNSIGNED_VARINT", so we need to subtract 1 from the real size
            transactional_id_size -= 1;
            log_debug("kafka: number_of_decoded_bytes: %d\n", number_of_decoded_bytes);
            log_debug("kafka: transactional_id_size: %d\n", transactional_id_size);
            kafka_transaction->base.current_offset_in_request_fragment += transactional_id_size;
        }
    }

    int16_t acks = 0;
    if (!kafka_read_big_endian_int16(kafka_transaction, &acks)) {
        return false;
    }

    if (acks > 1 || acks < -1) {
        // The number of acknowledgments the producer requires the leader to have received before considering a request
        // complete. Allowed values: 0 for no acknowledgments, 1 for only the leader and -1 for the full ISR.
        return false;
    }

    int32_t timeout_ms = 0;
    if (!kafka_read_big_endian_int32(kafka_transaction, &timeout_ms)) {
        return false;
    }

    log_debug("kafka: timeout_ms: %d\n", timeout_ms);
    if (timeout_ms < 0) {
        // timeout_ms cannot be negative.
        return false;
    }

    return extract_and_set_first_topic_name(kafka_transaction);
}

static __always_inline bool try_parse_fetch_request(kafka_transaction_t *kafka_transaction) {
    log_debug("kafka: trying to parse fetch request\n");
    if (kafka_transaction->base.request_api_version >= 12) {
        log_debug("kafka: fetch request version 12 and above is not supported: %d\n", kafka_transaction->base.request_api_version);
        return false;
    }

    // Skipping all fields that we don't need to parse at the moment:

    // replica_id => INT32
    // max_wait_ms => INT32
    // min_bytes => INT32
    kafka_transaction->base.current_offset_in_request_fragment += 12;

    if (kafka_transaction->base.request_api_version >= 3) {
        // max_bytes => INT32
        kafka_transaction->base.current_offset_in_request_fragment += 4;

        if (kafka_transaction->base.request_api_version >= 4) {
            // isolation_level => INT8
            kafka_transaction->base.current_offset_in_request_fragment += 1;

            if (kafka_transaction->base.request_api_version >= 7) {
                // session_id => INT32
                // session_epoch => INT32
                kafka_transaction->base.current_offset_in_request_fragment += 8;
            }
        }
    }

    return extract_and_set_first_topic_name(kafka_transaction);
}

static __always_inline bool extract_and_set_first_topic_name(kafka_transaction_t *kafka_transaction) {
    // Skipping number of entries for now
    if (kafka_transaction->base.request_api_version >= 9) {
        // number_of_entries is of type unsigned varint
        uint32_t number_of_decoded_bytes = 0;
        uint64_t number_of_entries = 0;

        if (!decode_unsigned_varint(kafka_transaction, &number_of_entries, &number_of_decoded_bytes)) {
            return false;
        }
        kafka_transaction->base.current_offset_in_request_fragment += number_of_decoded_bytes;
    } else {
        kafka_transaction->base.current_offset_in_request_fragment += 4;
    }

    if (kafka_transaction->base.current_offset_in_request_fragment > sizeof(kafka_transaction->request_fragment)) {
        log_debug("kafka: Current offset is above the request fragment size\n");
        return false;
    }

    int16_t topic_name_size = 0;
    if (kafka_transaction->base.request_api_version >= 9) {
        barrier();
        uint32_t number_of_decoded_bytes = 0;
        // topic_name_size is of type COMPACT_STRING, meaning its size is represented as UNSIGNED_VARINT
        uint64_t varint_topic_name_size = 0;

        if (!decode_unsigned_varint(kafka_transaction, &varint_topic_name_size, &number_of_decoded_bytes)) {
            return false;
        }
        kafka_transaction->base.current_offset_in_request_fragment += number_of_decoded_bytes;
        if (varint_topic_name_size == 0) {
            // size field in a COMPACT_STRING cannot be 0
            return false;
        }
        if (varint_topic_name_size < 2) {
            // topic_name_size == 0 -> isn't possible in COMPACT_STRING type
            // topic_name_size == 1 -> empty topic name
            return false;
        }
        // From COMPACT_STRING docs: "First the length N + 1 is given as an UNSIGNED_VARINT", so we need to subtract 1 from the real size
        varint_topic_name_size -= 1;
        if (varint_topic_name_size > TOPIC_NAME_MAX_STRING_SIZE) {
            return false;
        }
        topic_name_size = (int16_t)varint_topic_name_size;
    } else {
        if (!kafka_read_big_endian_int16(kafka_transaction, &topic_name_size)) {
                return false;
        }
    }
    log_debug("kafka: topic_name_size: %d\n", topic_name_size);
    if (topic_name_size <= 0 || topic_name_size > TOPIC_NAME_MAX_STRING_SIZE) {
        return false;
    }

    // Using the barrier macro instructs the compiler to not keep memory values cached in registers across the assembler instruction
    // If we don't use it here, the verifier will classify registers with false type and fail to load the program
    barrier();
    char* topic_name_beginning_offset = kafka_transaction->request_fragment + kafka_transaction->base.current_offset_in_request_fragment;

    // Make the verifier happy by checking that the topic name offset doesn't exceed the total fragment buffer size
    if (topic_name_beginning_offset > kafka_transaction->request_fragment + KAFKA_BUFFER_SIZE ||
            topic_name_beginning_offset + TOPIC_NAME_MAX_STRING_SIZE > kafka_transaction->request_fragment + KAFKA_BUFFER_SIZE) {
        return false;
    }

    __builtin_memcpy(kafka_transaction->base.topic_name, topic_name_beginning_offset, TOPIC_NAME_MAX_STRING_SIZE);

    // Making sure the topic name is a-z, A-Z, 0-9, dot, dash or underscore.
#pragma unroll(TOPIC_NAME_MAX_STRING_SIZE)
    for (int i = 0; i < TOPIC_NAME_MAX_STRING_SIZE; i++) {
        char ch = kafka_transaction->base.topic_name[i];
        log_debug("kafka: ch = %d\n", ch);
        if (ch == 0) {
            if (i < 3) {
                 log_debug("kafka: warning: topic name is %s (shorter than 3 letters), this could be a false positive\n", kafka_transaction->base.topic_name);
            }
            return i == topic_name_size;
        }
        if (('a' <= ch && ch <= 'z') || ('A' <= ch && ch <= 'Z') || ('0' <= ch && ch <= '9') || ch == '.' || ch == '_' || ch == '-') {
            continue;
        }
        return false;
    }
    return true;
}

#endif
