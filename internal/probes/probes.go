// Package probes
package probes

import (
	"fmt"

	"github.com/henrywhitaker3/probes"
)

var (
	Probes *probes.Probes
)

const (
	App   probes.Subject = "app"
	Redis probes.Subject = "redis"
)

func New(port int) *probes.Probes {
	p := probes.New(probes.ProbeOpts{}).WithHealthies(Redis).WithReadies(App)
	return p
}

func Healthy(s probes.Subject) error {
	if Probes == nil {
		return fmt.Errorf("global not set")
	}
	return Probes.Healthy(s)
}

func Unhealthy(s probes.Subject) error {
	if Probes == nil {
		return fmt.Errorf("global not set")
	}
	return Probes.Unhealthy(s)
}

func Ready(s probes.Subject) error {
	if Probes == nil {
		return fmt.Errorf("global not set")
	}
	return Probes.Ready(s)
}

func NotReady(s probes.Subject) error {
	if Probes == nil {
		return fmt.Errorf("global not set")
	}
	return Probes.NotReady(s)
}
