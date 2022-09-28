// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package stopper

import (
	"errors"
	"os"
	"os/signal"
	"syscall"

	"go.uber.org/fx"

	"github.com/DataDog/datadog-agent/cmd/agent/common/signals"
	"github.com/DataDog/datadog-agent/comp/core/internal"
	"github.com/DataDog/datadog-agent/comp/core/log"
)

type stopper struct {
	log        log.Component
	shutdowner fx.Shutdowner

	// stopOnSignals determines whether to stop on SIGINT and SIGTERM.
	stopOnSignals bool

	// stopErrorP is the location to which the stop error should be written.
	stopErrorP *error

	// stopCh carries a single message which leads to the App stopping.
	stopCh chan error
}

func newStopper(log log.Component, shutdowner fx.Shutdowner, bundleParams internal.BundleParams) Component {
	st := &stopper{
		log:           log,
		shutdowner:    shutdowner,
		stopOnSignals: bundleParams.StopOnSignals,
		stopErrorP:    bundleParams.StopErrorP,
		stopCh:        make(chan error, 1),
	}

	// This component starts immediately, so that shutdown signals can be
	// handled without waiting for Fx startup to complete.

	go st.wait()

	return st
}

// Stop implements Component#Stop.
func (st *stopper) Stop(err error) {
	if err != nil {
		_ = st.log.Critical("The Agent has encountered an error, shutting down...")
	} else {
		st.log.Info("Received stop command, shutting down...")
	}
	// a non-blocking send allows this to be resilient to multiple Stop calls
	select {
	case st.stopCh <- err:
	default:
	}
}

// wait runs in a dedicated goroutine and waits for a reason to stop.
func (st *stopper) wait() {
	signalCh := make(chan os.Signal, 1)
	sigpipeCh := make(chan os.Signal, 1)

	if st.stopOnSignals {
		// catch OS interrupt and term signals and report them via signalCh
		signal.Notify(signalCh, os.Interrupt, syscall.SIGTERM)

		// By default systemd redirects the stdout to journald. When journald
		// is stopped or crashes we receive a SIGPIPE signal.  Go ignores
		// SIGPIPE signals unless it is when stdout or stdout is closed, in
		// this case the agent is stopped.  We never want the agent to stop
		// upon receiving SIGPIPE, so we intercept the SIGPIPE signals and just
		// discard them below.
		signal.Notify(sigpipeCh, syscall.SIGPIPE)
	}

	for {
		select {
		case sig := <-signalCh:
			st.log.Infof("Received signal '%s', shutting down...", sig)
			st.shutdowner.Shutdown()
			return
		case err := <-st.stopCh:
			if st.stopErrorP != nil {
				*st.stopErrorP = err
			}
			st.shutdowner.Shutdown()
			return
		case <-sigpipeCh: // ignore SIGPIPE

		// temporary compatibility with the old cmd/agent/common/signals package
		case <-signals.Stopper:
			st.Stop(nil)
		case <-signals.ErrorStopper:
			st.Stop(errors.New("shutdown on error"))
		}
	}
}
