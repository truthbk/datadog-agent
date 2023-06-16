// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build linux_bpf

package ebpf

import (
	"github.com/DataDog/datadog-agent/pkg/util/kernel"
	manager "github.com/DataDog/ebpf-manager"
	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

const (
	pageSize            = uint64(4096)
	pageSizeMask        = uint64(pageSize - 1)
	hashtabMapLockCount = uint64(8)
)

func roundUp(n, multiple int) int {
	if multiple == 0 {
		return n
	}
	return ((n + multiple - 1) / multiple) * multiple
}

func roundDown(n, multiple int) int {
	if multiple == 0 {
		return n
	}
	return n - (n % multiple)
}

func findLastSetBit(n uint64) uint64 {
	if n == 0 {
		return uint64(64)
	}

	const bitsInNum = uint64(64)
	res := bitsInNum - 1

	for numBitsToTest := (bitsInNum >> 1); numBitsToTest != 0; numBitsToTest >>= 1 {
		if (n & (^uint64(0) << (bitsInNum - numBitsToTest))) == 0 {
			res -= numBitsToTest
			n <<= numBitsToTest
		}
	}

	return res
}

func pageAlign(size uint64) uint64 {
	return (size + pageSizeMask) & ^pageSizeMask
}

func roundPowOfTwo(n uint64) uint64 {
	return uint64(1) << findLastSetBit(n-1)
}

func sizeOfHtabElemStruct(kv kernel.Version) uint64 {
	return uint64(48)
}

func sizeOfBucketStruct(kv kernel.Version) uint64 {
	return uint64(16)
}

func sizeOfBpfArrayStruct(kv kernel.Version) uint64 {
	return uint64(320)
}

func estimateHashTabMem(mapInfo *ebpf.MapInfo, kv kernel.Version, numCPU uint64) uint64 {
	perCPU := mapInfo.Type == ebpf.PerCPUHash || mapInfo.Type == ebpf.LRUCPUHash
	lru := mapInfo.Type == ebpf.LRUHash || mapInfo.Type == ebpf.LRUCPUHash
	perCPULRU := (mapInfo.Flags & unix.BPF_F_NO_COMMON_LRU) == 1
	preAlloc := (mapInfo.Flags & unix.BPF_F_NO_PREALLOC) == 0

	maxEntries := mapInfo.MaxEntries
	if perCPULRU {
		maxEntries = uint32(roundUp(int(maxEntries), int(numCPU)))
		if maxEntries < mapInfo.MaxEntries {
			maxEntries = uint32(roundDown(int(mapInfo.MaxEntries), int(numCPU)))
		}
	}

	numBuckets := roundPowOfTwo(uint64(maxEntries))
	elemSize := sizeOfHtabElemStruct(kv) + uint64(roundUp(int(mapInfo.KeySize), 8))
	if perCPU {
		elemSize += 8
	} else {
		elemSize += uint64(roundUp(int(mapInfo.ValueSize), 8))
	}

	bucketsMem := numBuckets * sizeOfBucketStruct(kv)
	mapLocksMem := 4 * hashtabMapLockCount * numCPU

	preAllocMem := uint64(0)
	if preAlloc {
		// prealloc_init
		numEntries := maxEntries
		if !perCPU && !lru {
			numEntries += uint32(numCPU)
		}
		htabElemsMem := elemSize * uint64(numEntries)
		perCPUMem := uint64(0)
		if perCPU {
			perCPUMem = uint64(numEntries) * uint64(roundUp(int(mapInfo.ValueSize), 8)) * uint64(numCPU)
		}
		// end prealloc_init
		extraElemsMem := uint64(0)
		if !perCPU && !lru {
			extraElemsMem = 8 * numCPU
		}
		preAllocMem = htabElemsMem + perCPUMem + extraElemsMem
	}

	return bucketsMem + mapLocksMem + preAllocMem
}

func estimateArrayMem(mapInfo *ebpf.MapInfo, kv kernel.Version, numCPU uint64) uint64 {
	perCPU := mapInfo.Type == ebpf.PerCPUArray
	elemSize := roundUp(int(mapInfo.ValueSize), 8)
	maxEntries := uint64(mapInfo.MaxEntries)

	arraySize := sizeOfBpfArrayStruct(kv)
	if perCPU {
		arraySize += 8 * maxEntries
	} else {
		if (mapInfo.Flags & unix.BPF_F_MMAPABLE) == 1 {
			arraySize = pageAlign(arraySize)
			arraySize += pageAlign(uint64(maxEntries) * uint64(elemSize))
		} else {
			arraySize += uint64(maxEntries) * uint64(elemSize)
		}
	}

	return arraySize
}

// EstimateMapSize returns an estimated size of the kernel memory used an eBPF map
func EstimateMapSize(m *ebpf.Map, kv kernel.Version, numCPU uint64) (uint64, error) {
	i, err := m.Info()
	if err != nil {
		return 0, err
	}

	switch i.Type {
	case ebpf.Hash, ebpf.PerCPUHash, ebpf.LRUHash, ebpf.LRUCPUHash:
		return estimateHashTabMem(i, kv, numCPU), nil
	case ebpf.Array, ebpf.PerCPUArray, ebpf.ProgramArray, ebpf.ArrayOfMaps, ebpf.CGroupArray, ebpf.PerfEventArray:
		return estimateArrayMem(i, kv, numCPU), nil
	case ebpf.RingBuf:
		return uint64(i.MaxEntries), nil
	default:
		return 0, nil
	}
}

func EstimateMapSizes(manager *manager.Manager, kv kernel.Version, numCPU uint64) (map[string]uint64, uint64, error) {
	maps, err := manager.GetMaps()
	if err != nil {
		return nil, 0, err
	}

	sumSizes := uint64(0)
	mapSizes := make(map[string]uint64, len(maps))
	for name, m := range maps {
		size, err := EstimateMapSize(m, kv, numCPU)
		if err != nil {
			return nil, 0, err
		}
		mapSizes[name] = size
		sumSizes += size
	}

	return mapSizes, sumSizes, nil
}
