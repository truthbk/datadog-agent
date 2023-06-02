package common

import (
	"time"

	"github.com/DataDog/datadog-agent/comp/core/config"
	pkgconfig "github.com/DataDog/datadog-agent/pkg/config"
)

type C config.Component

type conf struct {
}

var x config.Component = &conf{}

func (c *conf) Get(key string) interface{} {
	panic("not implemented") // TODO: Implement
}
func (c *conf) GetString(key string) string {
	panic("not implemented") // TODO: Implement
}
func (c *conf) GetBool(key string) bool {
	panic("not implemented") // TODO: Implement
}
func (c *conf) GetInt(key string) int {
	panic("not implemented") // TODO: Implement
}
func (c *conf) GetInt32(key string) int32 {
	panic("not implemented") // TODO: Implement
}
func (c *conf) GetInt64(key string) int64 {
	panic("not implemented") // TODO: Implement
}
func (c *conf) GetFloat64(key string) float64 {
	panic("not implemented") // TODO: Implement
}
func (c *conf) GetTime(key string) time.Time {
	panic("not implemented") // TODO: Implement
}
func (c *conf) GetDuration(key string) time.Duration {
	panic("not implemented") // TODO: Implement
}
func (c *conf) GetStringSlice(key string) []string {
	panic("not implemented") // TODO: Implement
}
func (c *conf) GetFloat64SliceE(key string) ([]float64, error) {
	panic("not implemented") // TODO: Implement
}
func (c *conf) GetStringMap(key string) map[string]interface{} {
	panic("not implemented") // TODO: Implement
}
func (c *conf) GetStringMapString(key string) map[string]string {
	panic("not implemented") // TODO: Implement
}
func (c *conf) GetStringMapStringSlice(key string) map[string][]string {
	panic("not implemented") // TODO: Implement
}
func (c *conf) GetSizeInBytes(key string) uint {
	panic("not implemented") // TODO: Implement
}
func (c *conf) GetProxies() *pkgconfig.Proxy {
	panic("not implemented") // TODO: Implement
}
func (c *conf) ConfigFileUsed() string {
	panic("not implemented") // TODO: Implement
}
func (c *conf) AllSettings() map[string]interface{} {
	panic("not implemented") // TODO: Implement
}
func (c *conf) AllSettingsWithoutDefault() map[string]interface{} {
	panic("not implemented") // TODO: Implement
}
func (c *conf) AllKeys() []string {
	panic("not implemented") // TODO: Implement
}
func (c *conf) IsSet(key string) bool {
	panic("not implemented") // TODO: Implement
}

// IsKnown returns whether this key is known
func (c *conf) IsKnown(key string) bool {
	panic("not implemented") // TODO: Implement
}

// GetKnownKeys returns all the keys that meet at least one of these criteria:
// 1) have a default, 2) have an environment variable binded, 3) are an alias or 4) have been SetKnown()
func (c *conf) GetKnownKeys() map[string]interface{} {
	panic("not implemented") // TODO: Implement
}

// GetEnvVars returns a list of the env vars that the config supports.
// These have had the EnvPrefix applied, as well as the EnvKeyReplacer.
func (c *conf) GetEnvVars() []string {
	panic("not implemented") // TODO: Implement
}

// IsSectionSet checks if a given section is set by checking if any of
// its subkeys is set.
func (c *conf) IsSectionSet(section string) bool {
	panic("not implemented") // TODO: Implement
}
func (c *conf) Warnings() *pkgconfig.Warnings {
	panic("not implemented") // TODO: Implement
}
