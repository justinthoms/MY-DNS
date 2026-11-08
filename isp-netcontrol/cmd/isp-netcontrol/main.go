// Command isp-netcontrol runs ISP NetControl: the DNS resolver, the firewall
// manager and the console API.
package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/justinthoms/my-dns/isp-netcontrol/internal/license"
	"github.com/justinthoms/my-dns/isp-netcontrol/internal/nc"
)

func main() {
	log.SetFlags(log.LstdFlags | log.LUTC)
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "version":
			fmt.Println(nc.Version)
			return
		case "hardware-id":
			// Prints the fingerprint for offline activation without starting.
			cfg, _ := nc.ConfigFromEnv()
			id, err := license.HardwareID(license.HardwareSources{MachineIDPath: cfg.MachineIDPath, ProductUUIDPath: cfg.ProductUUIDPath})
			if err != nil {
				log.Fatal(err)
			}
			fmt.Println(id)
			return
		}
	}
	cfg, err := nc.ConfigFromEnv()
	if err != nil {
		log.Fatalf("config: %v", err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	app, err := nc.New(ctx, cfg)
	if err != nil {
		log.Fatalf("start: %v", err)
	}
	defer app.Close()
	if err := app.Run(ctx); err != nil {
		log.Fatalf("run: %v", err)
	}
}
