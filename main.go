// Command binny is OpenBIN's interactive terminal reverse-engineering agent.
//
// BINNY is the paid flagship (BYOK inference; Stripe gates access — both
// deferred during testing, so it's currently free + ungated). It orchestrates
// the EXISTING OpenBIN backend: it reads decompiled projects and writes draft
// reports/highlights through endpoints that already ship. It never
// re-implements analysis.
//
// Prerequisite: `openbin login` (BINNY reuses those Keycloak credentials).
// LLM keys are BYOK, read from env vars named in ~/.config/binny/config.json.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"

	tea "github.com/charmbracelet/bubbletea"

	"openbin.ai/binny/internal/api"
	"openbin.ai/binny/internal/app"
	"openbin.ai/binny/internal/auth"
	"openbin.ai/binny/internal/config"
	"openbin.ai/binny/internal/serve"
	"openbin.ai/binny/internal/tui"
)

// version is stamped by the release workflow via -ldflags "-X main.version=...".
var version = "dev"

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "binny: "+err.Error())
		os.Exit(1)
	}
}

func run() error {
	// --sample points BINNY at the raw sample on disk for active extraction.
	// The bytes never leave the machine — that's why extraction fits a local
	// agent. Optional: without it, extraction tools are simply unavailable.
	samplePath := flag.String("sample", "", "path to the raw sample on disk (enables active extraction)")
	showVersion := flag.Bool("version", false, "print the binny version and exit")
	serveMode := flag.Bool("serve", false, "run as the local HTTP backend for BINNY Desktop instead of the terminal UI")
	serveAddr := flag.String("serve-addr", "127.0.0.1:8899", "address for --serve to listen on (loopback only)")
	flag.Parse()
	if *showVersion {
		fmt.Println("binny " + version)
		return nil
	}

	// --serve: the engine behind BINNY Desktop. A new mode of this same binary;
	// the TUI below stays the default. See docs/DESKTOP.md.
	if *serveMode {
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
		defer stop()
		return serve.Run(ctx, serve.Options{Addr: *serveAddr, Version: version})
	}

	ep := config.LoadEndpoints()

	cfg, _, err := config.Load()
	if err != nil {
		return err
	}

	toks, err := auth.NewTokenSource(ep)
	if err != nil {
		return err
	}

	client := api.New(ep, toks)
	sess := app.NewSession(ep, cfg, client)
	sess.SamplePath = *samplePath

	// Offer key setup whenever no real BYOK key is configured yet — unless the
	// user has settled on Bedrock (ambient AWS creds), so bedrock users aren't
	// prompted every launch. Env-var and stored keys both count as configured.
	needSetup := !cfg.HasConfiguredKey()
	if dp := cfg.Find(cfg.DefaultProvider); dp != nil && dp.Kind == config.KindBedrock {
		needSetup = false
	}

	m := tui.New(sess, needSetup)
	p := tea.NewProgram(m, tea.WithAltScreen(), tea.WithMouseCellMotion())
	m.SetProgram(p) // lets the agent goroutine push streaming deltas to the UI
	_, err = p.Run()
	return err
}
