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
	"openbin.ai/binny/internal/update"
)

// version is stamped by the release workflow via -ldflags "-X main.version=...".
var version = "dev"

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "binny: "+err.Error())
		os.Exit(1)
	}
}

// usage is printed for -h/--help and bad flags: the flags, plus the one
// subcommand (binny desktop) that flag.PrintDefaults wouldn't mention.
func usage() {
	fmt.Fprintf(flag.CommandLine.Output(), `BINNY — an agent harness for reverse engineering.

  binny                 the terminal UI (pick a project, set a key, go)
  binny desktop         BINNY Desktop: the same engine with a graphical UI,
                        opened in your browser (binny desktop -h for options)
  binny update          update binny in place to the latest release
                        (--check to only report, --force to reinstall)

Flags:
`)
	flag.PrintDefaults()
}

// runUpdate is `binny update`: replace this binary with the latest release.
func runUpdate(args []string) error {
	fs := flag.NewFlagSet("binny update", flag.ContinueOnError)
	check := fs.Bool("check", false, "only report the installed and latest versions; don't install")
	force := fs.Bool("force", false, "reinstall even if already on the latest version")
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), `Usage: binny update [--check] [--force]

Updates binny in place to the latest published release — the same build the
website installer fetches — so you don't have to re-run the installer. Replaces
the running binary; set BINNY_RELEASE_BASE to pull from a different release.

`)
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return nil
		}
		return err
	}
	return update.Run(update.Options{Current: version, Check: *check, Force: *force})
}

func run() error {
	// `binny desktop` is a subcommand, not a flag, so it's read before the
	// flag set is parsed (and so `binny desktop -h` prints its own help).
	if len(os.Args) > 1 && os.Args[1] == "desktop" {
		return runDesktop(os.Args[2:])
	}
	if len(os.Args) > 1 && os.Args[1] == "update" {
		return runUpdate(os.Args[2:])
	}
	flag.Usage = usage
	// --sample points BINNY at the raw sample on disk for active extraction.
	// The bytes never leave the machine — that's why extraction fits a local
	// agent. Optional: without it, extraction tools are simply unavailable.
	samplePath := flag.String("sample", "", "path to the raw sample on disk (enables active extraction)")
	showVersion := flag.Bool("version", false, "print the binny version and exit")
	serveMode := flag.Bool("serve", false, "run only the local HTTP backend of BINNY Desktop (no browser; `binny desktop` is the usual way)")
	serveAddr := flag.String("serve-addr", "127.0.0.1:8899", "address for --serve to listen on (loopback only)")
	serveDir := flag.String("serve-dir", "", "a decompiled tree to serve in BINNY Desktop's Explorer/Code panes")
	flag.Parse()
	if *showVersion {
		fmt.Println("binny " + version)
		return nil
	}

	// --serve: the engine behind BINNY Desktop. A new mode of this same binary;
	// the TUI below stays the default. See docs/DESKTOP.md.
	if *serveMode {
		cfg, _, err := config.Load()
		if err != nil {
			return err
		}
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
		defer stop()
		return serve.Run(ctx, serve.Options{
			Addr:      *serveAddr,
			Version:   version,
			Dir:       *serveDir,
			Providers: cfg.Providers,
			Endpoints: config.LoadEndpoints(),
		})
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

// runDesktop is `binny desktop`: start the Desktop backend on a free loopback
// port and open the UI in the default browser. The Electron app in desktop/
// does exactly this with its own window; this is the no-install way to get the
// same thing from the binary users already have.
func runDesktop(args []string) error {
	fs := flag.NewFlagSet("binny desktop", flag.ContinueOnError)
	dir := fs.String("dir", "", "a decompiled tree to open in the Explorer/Code panes (optional)")
	addr := fs.String("addr", "127.0.0.1:0", "address to listen on (loopback only; :0 picks a free port)")
	noOpen := fs.Bool("no-open", false, "don't open the browser, just print the URL")
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), `Usage: binny desktop [--dir <decompiled tree>] [--addr host:port] [--no-open]

Starts BINNY Desktop and opens it in your browser: drop an APK or binary to
analyze it locally, or sign in (Cloud) to open a project from your OpenBin /
OpenAPK account. Same engine and models as the terminal UI. Ctrl+C stops it.

`)
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return nil
		}
		return err
	}
	cfg, _, err := config.Load()
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	return serve.Run(ctx, serve.Options{
		Addr:      *addr,
		Version:   version,
		Dir:       *dir,
		Providers: cfg.Providers,
		Endpoints: config.LoadEndpoints(),
		OnListen: func(url string) {
			fmt.Fprintf(os.Stderr, "\nBINNY Desktop is running at %s  (Ctrl+C to stop)\n", url)
			if *noOpen {
				return
			}
			if err := serve.OpenBrowser(url); err != nil {
				fmt.Fprintf(os.Stderr, "couldn't open a browser (%v) — open %s yourself\n", err, url)
			}
		},
	})
}
