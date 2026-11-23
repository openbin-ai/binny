package tui

import (
	"github.com/charmbracelet/lipgloss"

	"openbin.ai/binny/internal/agent"
)

// Binny mascot ASCII art, generated from ascii.txt (the raster of the robot).
// bannyArtFull is the full 45-row robot — the hero on the landing screen.
// bannyArtMini is a compact ~10-row body for the cramped menu/REPL screens.
// Regenerate from ascii.txt if the mascot changes; keep them accent-colored
// via banner()/bannerFull() rather than embedding color here.

const bannyArtFull = `
           ███
                       ██ █
                       ██ █
       ██
               █
               █               ███
   ██         ███      ██      ███
   ██                  ██

███     ██
█ █      █       ███        ██
███     ███      █ █         █       ██
                 ███        ███
           ██         ██
   ██
       ███      ███              ██
       █████  ██████████████     ██     ██
         ███████   ██████
    █████████████████████
    ██████  █████████████████  ██
    ███████████ ██████ ██████    ██
    █████████████████████████   █  ██
    █████████████████████████   ███  ██
    ████████████████  ███████   █████ ██
    █████████████████████████           ██
    █████████████████████████             ██
    ███████████████████████████████████   ██
    ███████████████████████████████████   ██
    ████████████   ████████   █████████   ██
    ████████████   ████████   █████████   ██
    ████████████   ████████   █████████   ██
    ███████████████████████████████████   ██
    ███████████████████████████████████   ██
    ███████████████████████████████████   ██
    ███████   ██████████████████   ████   ██
    ██████████   ████████████   ███████   ██
    ██████████   ████████████   ███████   ██
    █████████████            ██████████   ██
    ███████████████████████████████████   ██
    ███████████████████████████████████   ██
    ███████████████████████████████████   ██
    ███████████████████████████████████   ██
     █████████████████████████████████    ██
                                        ███
      ███████████████████████████████████
`

const bannyArtMini = `
  ████████████  ██  █
  █████████████████
  █████████████ █████
  ██████████████████ █
  ██████ █████ █████ █
  ██████████████████ █
  ██████████████████ █
  ██████████████████ █
  ██████████████████ █
   ███████████████████
`

// The crew's avatars are PNGs, which a terminal can't draw — here each crew
// member is a coloured name tag instead. The colours are the 256-colour
// neighbours of the accents in agent.Roles (the Desktop UI uses those exactly).
var crewColors = map[string]lipgloss.Color{
	agent.CaptainID: lipgloss.Color("255"), // BINNY — black/white
	"siggy":         lipgloss.Color("141"), // purple
	"twine":         lipgloss.Color("208"), // orange
	"trace":         lipgloss.Color("75"),  // blue
	"hex":           lipgloss.Color("41"),  // green
	"dex":           lipgloss.Color("203"), // red
	agent.ParityID:  lipgloss.Color("220"), // yellow
}

// crewStyle is the accent style for a crew member's tag and name.
func crewStyle(id string) lipgloss.Style {
	c, ok := crewColors[id]
	if !ok {
		c = colDim
	}
	return lipgloss.NewStyle().Foreground(c).Bold(true)
}

// crewTag renders a crew member's coloured name tag, e.g. "[hex]" in green.
func crewTag(id string) string { return crewStyle(id).Render("[" + id + "]") }
