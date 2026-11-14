// Package update implements `binny update`: replace the running binary in place
// with the latest published release, so users don't have to re-run the website
// installer each time. It pulls the same assets the installer does — the
// binny-releases GitHub "latest" release — so the two stay in lockstep.
package update

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// DefaultBase mirrors the installer's RELEASE_BASE: the latest release's asset
// directory. BINNY_RELEASE_BASE overrides it (same env var the installer honors).
const DefaultBase = "https://github.com/openbin-ai/binny-releases/releases/latest/download"

func base() string {
	if v := strings.TrimSpace(os.Getenv("BINNY_RELEASE_BASE")); v != "" {
		return strings.TrimRight(v, "/")
	}
	return DefaultBase
}

// Options configures a run.
type Options struct {
	Current string    // the running version (main.version)
	Check   bool      // report versions and whether an update exists, then stop
	Force   bool      // reinstall even when already on the latest version
	Out     io.Writer // progress sink (defaults to os.Stdout)
}

// assetName is the release asset for this OS/arch, matching the installer's
// naming (binny-<os>-<arch>.tar.gz, binny-windows-amd64.zip).
func assetName() (string, error) {
	goos, arch := runtime.GOOS, runtime.GOARCH
	switch goos {
	case "linux", "darwin":
		if arch != "amd64" && arch != "arm64" {
			return "", fmt.Errorf("no published build for %s/%s", goos, arch)
		}
		return fmt.Sprintf("binny-%s-%s.tar.gz", goos, arch), nil
	case "windows":
		if arch != "amd64" {
			return "", fmt.Errorf("no published build for windows/%s", arch)
		}
		return "binny-windows-amd64.zip", nil
	default:
		return "", fmt.Errorf("self-update isn't supported on %s — reinstall from https://openbin.ai", goos)
	}
}

// Run performs the update. It is safe to call on the running binary: on Unix the
// executable is swapped with an atomic rename (the running process keeps the old
// inode); on Windows the old file is moved aside first.
func Run(opts Options) error {
	out := opts.Out
	if out == nil {
		out = os.Stdout
	}

	latest, err := fetchVersion()
	if err != nil {
		return fmt.Errorf("couldn't check the latest version: %w", err)
	}
	cur := strings.TrimSpace(opts.Current)
	if cur == "" {
		cur = "unknown"
	}
	fmt.Fprintf(out, "installed: %s\nlatest:    %s\n", cur, latest)

	upToDate := normalize(cur) == normalize(latest)
	if opts.Check {
		if upToDate {
			fmt.Fprintln(out, "binny is up to date.")
		} else {
			fmt.Fprintln(out, "an update is available — run `binny update` to install it.")
		}
		return nil
	}
	if upToDate && !opts.Force {
		fmt.Fprintln(out, "already up to date (use --force to reinstall).")
		return nil
	}

	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("locate the running binary: %w", err)
	}
	if resolved, err := filepath.EvalSymlinks(exe); err == nil {
		exe = resolved
	}

	asset, err := assetName()
	if err != nil {
		return err
	}
	url := base() + "/" + asset
	fmt.Fprintf(out, "downloading %s…\n", asset)
	archive, err := download(url)
	if err != nil {
		return fmt.Errorf("download failed (%s): %w", url, err)
	}

	fmt.Fprintln(out, "extracting…")
	binName := "binny"
	if runtime.GOOS == "windows" {
		binName = "binny.exe"
	}
	newBin, err := extractBinary(archive, asset, binName)
	if err != nil {
		return err
	}

	// Stage the new binary next to the target so the replace is a rename on the
	// same filesystem (atomic), then make sure it actually runs on this machine
	// before we swap it in — a truncated download or wrong arch is caught here.
	dir := filepath.Dir(exe)
	staged := filepath.Join(dir, "."+filepath.Base(exe)+".new")
	if err := os.WriteFile(staged, newBin, 0o755); err != nil {
		return fmt.Errorf("writing the new binary to %s: %w (is the install dir writable? it may need the website installer or sudo)", dir, err)
	}
	defer os.Remove(staged) // no-op once renamed away

	if err := verify(staged, latest); err != nil {
		return fmt.Errorf("the downloaded binary didn't run (left your current one untouched): %w", err)
	}

	if err := replace(exe, staged); err != nil {
		return err
	}
	fmt.Fprintf(out, "updated binny to %s.\n", latest)
	return nil
}

// fetchVersion reads the release's VERSION file (the installer publishes it next
// to the assets).
func fetchVersion() (string, error) {
	body, err := download(base() + "/VERSION")
	if err != nil {
		return "", err
	}
	v := strings.TrimSpace(string(body))
	if v == "" {
		return "", fmt.Errorf("the release's VERSION file was empty")
	}
	return v, nil
}

// download GETs a URL, following redirects (GitHub release assets redirect to a
// CDN), and returns the body. It fails on non-200 so a 404 isn't mistaken for a
// valid (empty) asset.
func download(url string) ([]byte, error) {
	client := &http.Client{Timeout: 5 * time.Minute}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "binny-update")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d (is there a published release yet?)", resp.StatusCode)
	}
	return io.ReadAll(resp.Body)
}

// extractBinary pulls the named binary out of a .tar.gz or .zip archive.
func extractBinary(archive []byte, asset, binName string) ([]byte, error) {
	if strings.HasSuffix(asset, ".zip") {
		return fromZip(archive, binName)
	}
	return fromTarGz(archive, binName)
}

func fromTarGz(archive []byte, binName string) ([]byte, error) {
	gz, err := gzip.NewReader(bytes.NewReader(archive))
	if err != nil {
		return nil, fmt.Errorf("bad gzip: %w", err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("bad tar: %w", err)
		}
		if h.Typeflag == tar.TypeReg && filepath.Base(h.Name) == binName {
			return io.ReadAll(tr)
		}
	}
	return nil, fmt.Errorf("%q not found in the archive", binName)
}

func fromZip(archive []byte, binName string) ([]byte, error) {
	zr, err := zip.NewReader(bytes.NewReader(archive), int64(len(archive)))
	if err != nil {
		return nil, fmt.Errorf("bad zip: %w", err)
	}
	for _, f := range zr.File {
		if filepath.Base(f.Name) == binName {
			rc, err := f.Open()
			if err != nil {
				return nil, err
			}
			defer rc.Close()
			return io.ReadAll(rc)
		}
	}
	return nil, fmt.Errorf("%q not found in the archive", binName)
}

// verify runs the staged binary's --version so a corrupt or wrong-arch download
// is caught before it replaces a working install.
func verify(path, want string) error {
	out, err := exec.Command(path, "--version").CombinedOutput()
	if err != nil {
		return fmt.Errorf("%v (%s)", err, strings.TrimSpace(string(out)))
	}
	got := strings.TrimSpace(string(out))
	if want != "" && !strings.Contains(got, strings.TrimPrefix(want, "v")) && !strings.Contains(got, want) {
		return fmt.Errorf("version mismatch: new binary reports %q, expected %s", got, want)
	}
	return nil
}

// replace swaps the staged binary in for the running executable.
func replace(exe, staged string) error {
	if runtime.GOOS == "windows" {
		// Windows won't rename over a running .exe; move the old one aside first.
		old := exe + ".old"
		_ = os.Remove(old)
		if err := os.Rename(exe, old); err != nil {
			return fmt.Errorf("couldn't move the current binary aside: %w", err)
		}
		if err := os.Rename(staged, exe); err != nil {
			_ = os.Rename(old, exe) // roll back
			return fmt.Errorf("couldn't install the new binary: %w", err)
		}
		_ = os.Remove(old) // usually locked while running; harmless to leave
		return nil
	}
	// Unix: renaming over the running binary is fine — the process keeps the old
	// inode, and new invocations get the new file.
	if err := os.Rename(staged, exe); err != nil {
		return fmt.Errorf("couldn't install the new binary to %s: %w (is the install dir writable?)", exe, err)
	}
	return nil
}

// normalize lets "0.1.0" and "v0.1.0" compare equal.
func normalize(v string) string {
	return strings.TrimPrefix(strings.TrimSpace(strings.TrimPrefix(v, "binny ")), "v")
}
