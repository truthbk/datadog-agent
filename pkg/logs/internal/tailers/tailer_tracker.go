package tailers

import "sync"

type TailerTracker struct {
	sync.RWMutex
	tailers map[string]Tailer
}

func NewTailerTracker() *TailerTracker {
	return &TailerTracker{}
}

func (t *TailerTracker) Add(tailer Tailer) {
	t.Lock()
	defer t.Unlock()
	t.tailers[tailer.GetId()] = tailer
}

func (t *TailerTracker) Remove(tailer Tailer) {
	t.Lock()
	defer t.Unlock()
	delete(t.tailers, tailer.GetId())
}
