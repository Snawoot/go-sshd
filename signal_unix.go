package main

import (
	"log"
	"os"
	"os/signal"
	"syscall"
)

// +build !windows
func registerReloadSignal() {
	c := make(chan os.Signal)
	signal.Notify(c, syscall.SIGUSR1)

	go func() {
		for sig := range c {
			if sig == syscall.SIGUSR1 {
				log.Printf("Received signal: SIGUSR1. Reloading authorised keys.")
				loadAuthorisedKeys(*authorisedkeys)
			} else {
				log.Printf("Received unexpected signal: \"%s\".", sig.String())
			}
		}

	}()
}
