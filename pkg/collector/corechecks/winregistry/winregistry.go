//go:build windows

package winregistry

import (
	"github.com/DataDog/datadog-agent/pkg/autodiscovery/integration"
	"github.com/DataDog/datadog-agent/pkg/collector/check"
	core "github.com/DataDog/datadog-agent/pkg/collector/corechecks"
	"github.com/DataDog/datadog-agent/pkg/metrics"
	"github.com/DataDog/datadog-agent/pkg/util/log"
	"github.com/DataDog/datadog-agent/pkg/util/winutil/etw"
	"gopkg.in/yaml.v2"
)

const (
	checkName = "windows_registry"
)

type metric struct {
	Name     string
	Mappings []map[string]float64 `yaml:"mapping"`
}

type registryKey struct {
	Name    string
	Metrics map[string]metric
}

type checkCfg struct {
	RegistryKeys map[string]registryKey `yaml:"registry_keys"`
}

// WindowsRegistryCheck contains the field for the WindowsRegistryCheck
type WindowsRegistryCheck struct {
	core.CheckBase
	metrics.Gauge
	DataChannel chan []string
}

func (c *WindowsRegistryCheck) Configure(integrationConfigDigest uint64, data integration.Data, initConfig integration.Data, source string) error {
	err := c.CommonConfigure(integrationConfigDigest, initConfig, data, source)
	if err != nil {
		return err
	}

	var conf checkCfg
	if err := yaml.Unmarshal(data, &conf); err != nil {
		return err
	}

	for regKey, regKeyConfig := range conf.RegistryKeys {
		log.Infof("Loading configuration for %s\n\tname: %s\n", regKey, regKeyConfig.Name)
		for metric, metricConfig := range regKeyConfig.Metrics {
			log.Infof("\tmetric %s\n", metric)
			if metricConfig.Mappings != nil {
				for _, mapping := range metricConfig.Mappings {
					for key, value := range mapping {
						log.Infof("\t\t%s -> %f\n", key, value)
						break
					}
				}
			}
		}
	}

	startingEtwChan := make(chan struct{})

	// Currently ETW needs be started on a separate thread
	// because it is blocked until subscription is stopped
	go func() {
		defer func() {
			etw.StopEtw("windows-registry")
			close(c.DataChannel)
		}()

		// By default this function call never exits and its callbacks or rather events
		// will be returned on the very the same thread until ETW is canceled via
		// etw.StopEtw(). There is asynchronous flag which implicitly will create a real
		// (Windows API) thread but it is not tested yet.
		log.Infof("Starting ETW Kernel Registry subscription")

		startingEtwChan <- struct{}{}

		err := etw.StartEtw("windows-registry", etw.EtwProviderRegistryService, c)

		if err == nil {
			log.Infof("ETW Kernel Registry subscription completed")
		} else {
			log.Errorf("ETW Kernel Registry subscription failed with error %v", err)
		}
	}()

	log.Infof("BEFORE eventLoopWG.Done")

	return nil
}

func (c *WindowsRegistryCheck) OnStart() {

}

func (c *WindowsRegistryCheck) OnStop() {

}

func (c *WindowsRegistryCheck) OnEvent(e *etw.DDEtwEventInfo) {
	log.Infof("OnEvent = %d\n", e.Event.Id)
}

func (c *WindowsRegistryCheck) Run() error {
	log.Debugf("Running = %s\n", "aaa")
	return nil
}

func windowsRegistryCheckFactory() check.Check {
	return &WindowsRegistryCheck{
		CheckBase:   core.NewCheckBase(checkName),
		DataChannel: make(chan []string),
	}
}

func init() {
	core.RegisterCheck(checkName, windowsRegistryCheckFactory)
}
