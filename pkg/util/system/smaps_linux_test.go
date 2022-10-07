package system

import (
	"path/filepath"
	"testing"

	"github.com/DataDog/datadog-agent/pkg/util/testutil"
	"github.com/stretchr/testify/assert"
)

func TestGetSelfSmapStats(t *testing.T) {
	dummyProcDir, err := testutil.NewTempFolder("test-smaps")
	assert.Nil(t, err)
	defer dummyProcDir.RemoveAll() // clean up
	for _, tc := range []struct {
		smap_contents string
		smap_parsed   SelfMemStats
	}{
		{
			smap_contents: testutil.Detab(`
00400000-0507f000 r-xp 00000000 fc:01 535287                             /home/lima.linux/dev/datadog-agent/bin/agent/agent
Size:              78332 kB
KernelPageSize:        4 kB
MMUPageSize:           4 kB
Rss:               13100 kB
Pss:               13100 kB
Shared_Clean:          0 kB
Shared_Dirty:          0 kB
Private_Clean:     13100 kB
Private_Dirty:         0 kB
Referenced:        11280 kB
Anonymous:             0 kB
LazyFree:              0 kB
AnonHugePages:         0 kB
ShmemPmdMapped:        0 kB
FilePmdMapped:         0 kB
Shared_Hugetlb:        0 kB
Private_Hugetlb:       0 kB
Swap:                  0 kB
SwapPss:               0 kB
Locked:                0 kB
THPeligible:    0
VmFlags: rd ex mr mw me
ffffbcbbe000-ffffbcbc0000 rw-p 0002c000 fc:01 34947                      /usr/lib/aarch64-linux-gnu/ld-linux-aarch64.so.1
Size:                  8 kB
KernelPageSize:        4 kB
MMUPageSize:           4 kB
Rss:                   8 kB
Pss:                   8 kB
Shared_Clean:          0 kB
Shared_Dirty:          0 kB
Private_Clean:         0 kB
Private_Dirty:         8 kB
Referenced:            8 kB
Anonymous:             8 kB
LazyFree:              0 kB
AnonHugePages:         0 kB
ShmemPmdMapped:        0 kB
FilePmdMapped:         0 kB
Shared_Hugetlb:        0 kB
Private_Hugetlb:       0 kB
Swap:                  0 kB
SwapPss:               0 kB
Locked:                0 kB
THPeligible:    0
VmFlags: rd wr mr mw me ac
ffffcfe9f000-ffffcfec0000 rw-p 00000000 00:00 0                          [stack]
Size:                132 kB
KernelPageSize:        4 kB
MMUPageSize:           4 kB
Rss:                  12 kB
Pss:                  12 kB
Shared_Clean:          0 kB
Shared_Dirty:          0 kB
Private_Clean:         0 kB
Private_Dirty:        12 kB
Referenced:           12 kB
Anonymous:            12 kB
LazyFree:              0 kB
AnonHugePages:         0 kB
ShmemPmdMapped:        0 kB
FilePmdMapped:         0 kB
Shared_Hugetlb:        0 kB
Private_Hugetlb:       0 kB
Swap:                  0 kB
SwapPss:               0 kB
Locked:                0 kB
THPeligible:    0
VmFlags: rd wr mr mw me gd ac
ffffbcb74000-ffffbcb75000 r--p 00004000 fc:01 1569687                    /home/lima.linux/dev/datadog-agent/dev/lib/libdatadog-agent-rtloader.so.0.1.0
Size:                  4 kB
KernelPageSize:        4 kB
MMUPageSize:           4 kB
Rss:                   4 kB
Pss:                   4 kB
Shared_Clean:          0 kB
Shared_Dirty:          0 kB
Private_Clean:         0 kB
Private_Dirty:         4 kB
Referenced:            4 kB
Anonymous:             4 kB
LazyFree:              0 kB
AnonHugePages:         0 kB
ShmemPmdMapped:        0 kB
FilePmdMapped:         0 kB
Shared_Hugetlb:        0 kB
Private_Hugetlb:       0 kB
Swap:                  0 kB
SwapPss:               0 kB
Locked:                0 kB
THPeligible:    0
            `),
			smap_parsed: SelfMemStats{
				"/home/lima.linux/dev/datadog-agent/dev/lib/libdatadog-agent-rtloader.so.0.1.0": {
					Rss:          4096,
					Pss:          4096,
					SharedClean:  0,
					SharedDirty:  0,
					PrivateClean: 0,
					PrivateDirty: 4096,
					Referenced:   4096,
					Anonymous:    4096,
					Swap:         0,
					SwapPss:      0,
				},
			},
		},
	} {
		t.Run("", func(t *testing.T) {
			// Create temporary files on disk with the routes and stats.
			err = dummyProcDir.Add(filepath.Join("self", "smaps"), tc.smap_contents)
			assert.NoError(t, err)

			stats, err := GetSelfSmapStats(dummyProcDir.RootPath)
			assert.NoError(t, err)
			assert.Equal(t, tc.smap_parsed, stats)
		})
	}
}
