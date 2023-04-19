package protocols

import (
	"github.com/DataDog/datadog-agent/pkg/network/protocols/http"
	manager "github.com/DataDog/ebpf-manager"
)

type EbpfProgram interface {
	ConfigureEbpfManager(program *http.EbpfProgram, options *manager.Options) error
	PreStart(program *http.EbpfProgram) error
	PostStart(program *http.EbpfProgram) error
	PreClose(program *http.EbpfProgram) error
	PostClose(program *http.EbpfProgram) error
}

type Protocol interface {
	EbpfProgram
	// TODO: How can we return a generic map?
	GetStats() map[http.Key]*http.RequestStats
}
