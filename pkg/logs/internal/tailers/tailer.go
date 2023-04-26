package tailers

type Tailer interface {
	GetId() string
	GetStatus() map[string][]string
}
