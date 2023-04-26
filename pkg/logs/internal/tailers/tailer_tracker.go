package tailers

import "sync"

type TailerTracker struct {
	sync.RWMutex
	containers []AnyTailerContainer
}

func NewTailerTracker() *TailerTracker {
	return &TailerTracker{}
}

func (t *TailerTracker) Add(container AnyTailerContainer) {
	t.Lock()
	defer t.Unlock()
	t.containers = append(t.containers, container)
}

func (t *TailerTracker) All() []Tailer {
	t.RLock()
	defer t.RUnlock()
	tailers := []Tailer{}
	for _, container := range t.containers {
		tailers = append(tailers, container.Tailers()...)
	}
	return tailers
}

type AnyTailerContainer interface {
	Tailers() []Tailer
}

type TailerContainer[T Tailer] struct {
	sync.RWMutex
	tailers map[string]T
}

func NewTailerContainer[T Tailer]() *TailerContainer[T] {
	return &TailerContainer[T]{
		tailers: make(map[string]T),
	}
}

func (t *TailerContainer[T]) Get(id string) (T, bool) {
	t.RLock()
	defer t.RUnlock()
	tailer, ok := t.tailers[id]
	return tailer, ok
}

func (t *TailerContainer[T]) Add(tailer T) {
	t.Lock()
	defer t.Unlock()
	t.tailers[tailer.GetId()] = tailer
}

func (t *TailerContainer[T]) Remove(tailer T) {
	t.Lock()
	defer t.Unlock()
	delete(t.tailers, tailer.GetId())
}

func (t *TailerContainer[T]) All() []T {
	t.RLock()
	defer t.RUnlock()
	tailers := []T{}
	for _, tailer := range t.tailers {
		tailers = append(tailers, tailer)
	}
	return tailers
}

func (t *TailerContainer[T]) Count() int {
	t.RLock()
	defer t.RUnlock()
	return len(t.tailers)
}

func (t *TailerContainer[T]) Tailers() []Tailer {
	t.RLock()
	defer t.RUnlock()
	tailers := []Tailer{}
	for _, tailer := range t.tailers {
		tailers = append(tailers, tailer)
	}
	return tailers
}
