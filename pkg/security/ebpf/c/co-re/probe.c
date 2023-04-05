#include "ktypes.h"
#include "bpf_endian.h"
#include "bpf_tracing.h"

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
#pragma clang diagnostic ignored "-Wunused-function"

#include "bpf_tracing.h"
#include "bpf_core_read.h"
#include "hooks/core_all.h"

#pragma clang diagnostic pop

// This number will be interpreted by elf-loader to set the current running kernel version
__u32 _version SEC("version") = 0xFFFFFFFE; // NOLINT(bugprone-reserved-identifier)

char _license[] SEC("license") = "GPL"; // NOLINT(bugprone-reserved-identifier)
