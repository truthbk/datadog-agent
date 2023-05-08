package otlpreceiverwrapper

import (
	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/receiver"
	"go.opentelemetry.io/collector/receiver/otlpreceiver"
)

type wrapperFactory struct {
	receiver.Factory
}

func (f *wrapperFactory) CreateDefaultConfig() component.Config {
	cfg := f.Factory.CreateDefaultConfig()

	c := cfg.(*otlpreceiver.Config)
	c.Protocols.GRPC.MaxRecvMsgSizeMiB = 10

	return c
}

func NewFactory() receiver.Factory {
	return &wrapperFactory{otlpreceiver.NewFactory()}
}
