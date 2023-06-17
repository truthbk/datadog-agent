package client

import (
	"testing"

	"github.com/DataDog/test-infra-definitions/components/datadog/driver"
	"github.com/DataDog/test-infra-definitions/components/vm"
)

var _ clientService[driver.ClientData] = (*Driver)(nil)

// A client Driver that is connected to an [driver.Installer].
type Driver struct {
	*UpResultDeserializer[driver.ClientData]
	*vmClient
	vm vm.VM
}

// Create a new instance of Driver
func NewDriver(installer *driver.Installer) *Driver {
	driverInstance := &Driver{
		vm: installer.VM(),
	}
	driverInstance.UpResultDeserializer = NewUpResultDeserializer[driver.ClientData](installer, driverInstance)
	return driverInstance
}

//lint:ignore U1000 Ignore unused function as this function is call using reflection
func (driver *Driver) initService(t *testing.T, data *driver.ClientData) error {
	var err error
	driver.vmClient, err = newVMClient(t, "", &data.Connection)
	return err
}

func (driver *Driver) CopyFolder(localPath, remotePath string) error {
	_, err := driver.vm.GetFileManager().CopyAbsoluteFolder(localPath, remotePath)
	return err
}
