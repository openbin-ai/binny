package serve

import (
	"fmt"
	"os/exec"
	"runtime"
)

// browserCommand picks the OS's "open this URL" launcher.
func browserCommand(goos, url string) (string, []string) {
	switch goos {
	case "darwin":
		return "open", []string{url}
	case "windows":
		return "rundll32", []string{"url.dll,FileProtocolHandler", url}
	default:
		return "xdg-open", []string{url}
	}
}

// OpenBrowser opens url in the user's default browser. It returns once the
// launcher has been started; the browser itself runs on.
func OpenBrowser(url string) error {
	name, args := browserCommand(runtime.GOOS, url)
	if err := exec.Command(name, args...).Start(); err != nil {
		return fmt.Errorf("open browser (%s): %w", name, err)
	}
	return nil
}
