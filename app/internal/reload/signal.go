package reload

import (
	"os"
	"os/signal"
)

// signalNotify and signalStop are package-level indirections for
// os/signal so the production paths in reload.go stay short. Tests that
// need to drive signals directly inject Options.SignalNotify /
// Options.SignalStop instead — that path bypasses these vars entirely.
var (
	signalNotify = func(c chan<- os.Signal, sigs ...os.Signal) {
		signal.Notify(c, sigs...)
	}
	signalStop = func(c chan<- os.Signal) {
		signal.Stop(c)
	}
)
