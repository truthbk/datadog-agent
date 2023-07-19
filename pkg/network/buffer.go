// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package network

// DataBuffer encapsulates a resizing buffer for T objects
type DataBuffer[T any] struct {
	buf           []T
	off           int
	minBufferSize int
}

// NewDataBuffer creates a DataBuffer with initial size `initSize`.
func NewDataBuffer[T any](initSize, minSize int) *DataBuffer[T] {
	return &DataBuffer[T]{
		buf:           make([]T, initSize),
		minBufferSize: minSize,
	}
}

// Next returns the next `T` object available for writing.
// It will resize the internal buffer if necessary.
func (b *DataBuffer[T]) Next() *T {
	if b.off >= len(b.buf) {
		b.buf = append(b.buf, *new(T))
	}
	c := &b.buf[b.off]
	b.off++
	return c
}

// Append slice to DataBuffer
func (b *DataBuffer[T]) Append(slice []T) {
	b.buf = append(b.buf[:b.off], slice...)
	b.off += len(slice)
}

// Reclaim captures the last n entries for usage again.
func (b *DataBuffer[T]) Reclaim(n int) {
	b.off -= n
	if b.off < 0 {
		b.off = 0
	}
}

// Objects returns a slice of all the `T` objects returned via `Next`
// since the last `Reset`.
func (b *DataBuffer[T]) Objects() []T {
	return b.buf[:b.off]
}

// Len returns the count of the number of written `T` objects since last `Reset`.
func (b *DataBuffer[T]) Len() int {
	return b.off
}

// Capacity returns the current capacity of the buffer
func (b *DataBuffer[T]) Capacity() int {
	return cap(b.buf)
}

// Reset returns the written object count back to zero. It may resize the internal buffer based on past usage.
func (b *DataBuffer[T]) Reset() {
	// shrink buffer if less than half used
	half := cap(b.buf) / 2
	if b.off <= half && half >= b.minBufferSize {
		b.buf = make([]T, half)
		b.off = 0
		return
	}

	zero := *new(T)
	for i := 0; i < b.off; i++ {
		b.buf[i] = zero
	}
	b.off = 0
}
