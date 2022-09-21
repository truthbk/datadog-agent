#ifndef __HTTP_DEBUG
#define __HTTP_DEBUG

#include "http-types.h"

#ifndef __LOAD_CONSTANT
#define LOAD_CONSTANT(param, var) asm("%0 = " param " ll" : "=r"(var))
#endif

#define STRINGIFY(x) #x
#define TO_STRING(x) STRINGIFY(x)

#define process_filter(http, param)                                     \
    do {                                                                \
        u64 has = (u64)(http)->tup.param;                               \
        u64 want = 0;                                                   \
        LOAD_CONSTANT(TO_STRING(filter_##param), want);                 \
        if (want && want != has) {                                      \
            return false;                                               \
        }                                                               \
    } while(0)                                                          \


// this is used in DEBUG mode as a filter for HTTP requests
static __always_inline bool http_should_process(http_transaction_t *http) {
    process_filter(http, sport);
    process_filter(http, dport);
    process_filter(http, saddr_h);
    process_filter(http, saddr_l);
    process_filter(http, daddr_h);
    process_filter(http, daddr_l);
    return true;
}
#endif
