package client

import (
	"testing"

	"github.com/DataDog/test-infra-definitions/components/datadog/apmautoinjector"
)

type DriverStatus string

const (
	NotInstalled DriverStatus = "NOTINSTALLED"
	Running      DriverStatus = "RUNNING"
	Stopped      DriverStatus = "STOPPED"
)

var _ clientService[apmautoinjector.ClientData] = (*APMAutoInjector)(nil)

// A client APMAutoInjector that is connected to an [apmautoinjector.Installer].
type APMAutoInjector struct {
	*UpResultDeserializer[apmautoinjector.ClientData]
	*vmClient
}

// Create a new instance of Driver
func NewAPMAutoInjector(installer *apmautoinjector.Installer) *APMAutoInjector {
	injectorInstance := &APMAutoInjector{}
	injectorInstance.UpResultDeserializer = NewUpResultDeserializer[apmautoinjector.ClientData](installer, injectorInstance)
	return injectorInstance
}

func (inj *APMAutoInjector) DriverServiceStatus() (DriverStatus, error) {
	output, err := inj.vmClient.ExecuteWithError("try { (get-service \"ddapm\" -ErrorAction Stop).Status } catch { write-host \"NOTINSTALLED\" }")
	return DriverStatus(output), err
}

//lint:ignore U1000 Ignore unused function as this function is call using reflection
func (inj *APMAutoInjector) initService(t *testing.T, data *apmautoinjector.ClientData) error {
	var err error
	inj.vmClient, err = newVMClient(t, "", &data.Connection)
	return err
}
