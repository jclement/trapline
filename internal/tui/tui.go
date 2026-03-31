// Package tui provides terminal UI styling and formatting helpers for
// Trapline's interactive console output. It uses the lipgloss library from
// Charm for ANSI-styled rendering and provides a consistent visual language
// across all CLI commands (scan, status, doctor, etc.).
//
// The package defines:
//
//   - A color palette (Red, Yellow, Green, Cyan, Magenta, Dim, White) used
//     consistently throughout the application.
//
//   - Pre-built lipgloss styles (Title, Subtitle, Success, Warning, Error,
//     Critical, Dimmed, FindingBox, Banner, TaglineStyle) that map to semantic
//     concepts rather than raw colors, making it easy to maintain visual
//     consistency.
//
//   - A severity-to-style mapping ([SeverityStyle], [SeverityBadge]) that
//     translates finding severity levels to appropriate visual treatments:
//     critical = bold red, high = red, medium = yellow, info = dim gray.
//
//   - Formatting helpers ([FormatBanner], [FormatFinding], [FormatSection],
//     [FormatModuleStatus]) that render structured data into styled terminal
//     strings.
//
//   - TTY detection ([IsTTY]) so callers can decide whether to use styled
//     output or fall back to plain text when stdout is piped to a file or
//     another process. Lipgloss itself gracefully degrades when no TTY is
//     detected, but callers may want to switch output format entirely (e.g.
//     JSON instead of styled text).
package tui

import (
	"fmt"
	"os"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/jclement/trapline/pkg/finding"
)

// Color palette: these are the base hex colors used throughout the TUI. They
// are defined as lipgloss.Color values (which are just strings under the hood)
// and referenced by the style definitions below.
var (
	Red     = lipgloss.Color("#FF0000") // errors, critical severity
	Yellow  = lipgloss.Color("#FFAA00") // warnings, medium severity
	Green   = lipgloss.Color("#00FF00") // success indicators, passed checks
	Cyan    = lipgloss.Color("#00CCCC") // titles, banner text
	Magenta = lipgloss.Color("#FF00FF") // accent (reserved for future use)
	Dim     = lipgloss.Color("#666666") // de-emphasized text, info severity
	White   = lipgloss.Color("#FFFFFF") // subtitles, high-contrast text
)

// Pre-built semantic styles. Each style maps to a visual concept rather than a
// raw color, so the codebase references "Warning" instead of "yellow bold".
// This indirection makes it straightforward to update the entire application's
// visual theme by changing these definitions.
var (
	// Title is used for top-level section headers (e.g. "Scan Results").
	// Bold cyan with a bottom margin to separate it from content.
	Title = lipgloss.NewStyle().
		Bold(true).
		Foreground(Cyan).
		MarginBottom(1)

	// Subtitle is used for secondary headers within a section (e.g. module
	// names in status output). Bold white without margins.
	Subtitle = lipgloss.NewStyle().
			Bold(true).
			Foreground(White)

	// Success is used for positive indicators (checkmarks, "enabled" labels).
	Success = lipgloss.NewStyle().
		Foreground(Green)

	// Warning is used for cautionary indicators (warning triangles, medium
	// severity findings).
	Warning = lipgloss.NewStyle().
		Foreground(Yellow)

	// Error is used for failure indicators (crosses, high severity findings).
	Error = lipgloss.NewStyle().
		Foreground(Red)

	// Critical is used for the most severe indicators. Bold red to ensure
	// maximum visual prominence for critical severity findings.
	Critical = lipgloss.NewStyle().
			Bold(true).
			Foreground(Red)

	// Dimmed is used for de-emphasized text: finding IDs, info-level severity,
	// timestamps, and other secondary information.
	Dimmed = lipgloss.NewStyle().
		Foreground(Dim)

	// FindingBox wraps individual finding output in a rounded-border box with
	// dim borders and internal padding. The bottom margin provides spacing
	// between consecutive findings.
	FindingBox = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(Dim).
			Padding(0, 1).
			MarginBottom(1)

	// Banner is the style for the "TRAPLINE" ASCII banner text shown at the
	// top of interactive commands. Bold cyan for brand recognition.
	Banner = lipgloss.NewStyle().
		Bold(true).
		Foreground(Cyan)

	// TaglineStyle renders the application tagline (e.g. "Host integrity
	// monitoring") in italic dim text below the banner.
	TaglineStyle = lipgloss.NewStyle().
			Italic(true).
			Foreground(Dim)
)

// IsTTY returns true if stdout is connected to a terminal (as opposed to
// being piped to a file or another process). This is determined by checking
// whether stdout's file mode includes the ModeCharDevice flag, which is set
// for character devices (terminals) but not for regular files or pipes.
//
// Callers use this to decide between styled text output (when a human is
// watching) and structured JSON output (when the output is being consumed
// programmatically).
func IsTTY() bool {
	fi, err := os.Stdout.Stat()
	if err != nil {
		// If we cannot stat stdout, assume we are NOT a TTY to avoid sending
		// ANSI escape codes to an unknown destination.
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

// SeverityStyle returns the appropriate lipgloss style for a finding severity
// level. The mapping is:
//
//   - SeverityCritical -> Critical (bold red)
//   - SeverityHigh     -> Error (red)
//   - SeverityMedium   -> Warning (yellow)
//   - SeverityInfo     -> Dimmed (gray)
//   - unknown          -> unstyled (no color or formatting)
//
// This is used for rendering severity text inline (e.g. the severity word in
// a finding summary). For colored badge backgrounds, use [SeverityBadge].
func SeverityStyle(sev finding.Severity) lipgloss.Style {
	switch sev {
	case finding.SeverityCritical:
		return Critical
	case finding.SeverityHigh:
		return Error
	case finding.SeverityMedium:
		return Warning
	case finding.SeverityInfo:
		return Dimmed
	default:
		return lipgloss.NewStyle()
	}
}

// SeverityBadge returns a colored severity badge string like " CRITICAL " or
// " HIGH ". The badge uses a colored background with white bold text and
// horizontal padding, making it visually prominent in terminal output. The
// background colors are:
//
//   - SeverityCritical -> bright red (#FF0000)
//   - SeverityHigh     -> dark orange (#CC4400)
//   - SeverityMedium   -> dark yellow (#AA8800)
//   - SeverityInfo     -> dark gray (#444444)
//
// These background colors are intentionally different from the foreground
// colors in [SeverityStyle] to ensure readability with white text on top.
func SeverityBadge(sev finding.Severity) string {
	label := strings.ToUpper(string(sev))
	var bg lipgloss.Color
	switch sev {
	case finding.SeverityCritical:
		bg = Red
	case finding.SeverityHigh:
		bg = lipgloss.Color("#CC4400")
	case finding.SeverityMedium:
		bg = lipgloss.Color("#AA8800")
	case finding.SeverityInfo:
		bg = lipgloss.Color("#444444")
	}
	return lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color("#FFFFFF")).
		Background(bg).
		Padding(0, 1).
		Render(label)
}

// FormatFinding renders a [finding.Finding] as a styled terminal string inside
// a rounded-border box. The output includes:
//
//   - A colored severity badge (e.g. " CRITICAL ") followed by the bold
//     summary text on the first line.
//   - The finding ID in dimmed text on the second line (for cross-referencing
//     with JSON logs).
//   - Any key-value pairs from the finding's Detail map, each on its own
//     indented line with the key in dim text.
//
// The entire output is wrapped in the FindingBox style for visual separation.
func FormatFinding(f *finding.Finding) string {
	badge := SeverityBadge(f.Severity)
	id := Dimmed.Render(f.FindingID)
	summary := lipgloss.NewStyle().Bold(true).Render(f.Summary)

	content := fmt.Sprintf("%s %s\n%s", badge, summary, id)

	// Append detail key-value pairs if present. These provide additional
	// context about the finding (e.g. "path: /etc/shadow", "port: 4444").
	if f.Detail != nil {
		for k, v := range f.Detail {
			content += fmt.Sprintf("\n  %s %v",
				Dimmed.Render(k+":"),
				v)
		}
	}

	return FindingBox.Render(content)
}

// CheckMark returns a styled checkmark (green) or cross (red) depending on
// the passed boolean. Used by the doctor output and status displays.
func CheckMark(passed bool) string {
	if passed {
		return Success.Render("✓")
	}
	return Error.Render("✗")
}

// WarnMark returns a styled warning triangle in yellow. Used alongside
// [CheckMark] for three-state indicators (pass/warn/fail).
func WarnMark() string {
	return Warning.Render("⚠")
}

// FormatBanner renders the Trapline application banner with the version number
// and a tagline. This is displayed at the top of interactive commands like
// "trapline status" and "trapline scan". The output format is:
//
//	TRAPLINE v0.4.2
//	Host integrity monitoring for Linux servers
func FormatBanner(version, tagline string) string {
	art := Banner.Render("TRAPLINE")
	ver := Dimmed.Render("v" + version)
	tag := TaglineStyle.Render(tagline)
	return fmt.Sprintf("%s %s\n%s\n", art, ver, tag)
}

// FormatSection renders a section header with decorative horizontal lines on
// either side. Used to visually separate sections in status and scan output.
// Example: "--- Modules ---"
func FormatSection(title string) string {
	return Subtitle.Render("─── " + title + " ───")
}

// FormatModuleStatus renders a single module's status as a fixed-width line
// suitable for columnar display. The output includes:
//
//   - Module name (left-aligned, 20 characters wide)
//   - Scan interval (10 characters wide, dimmed)
//   - Enabled/disabled status (green "enabled" or dim "disabled")
//   - Optional detail string (dimmed, appended if non-empty)
//
// Example: "  file-integrity      5m0s       enabled  12 monitored paths"
func FormatModuleStatus(name string, enabled bool, interval string, detail string) string {
	status := Success.Render("enabled")
	if !enabled {
		status = Dimmed.Render("disabled")
	}

	// Fixed-width columns for aligned output across multiple module lines.
	nameStyled := lipgloss.NewStyle().Width(20).Render(name)
	intervalStyled := lipgloss.NewStyle().Width(10).Foreground(Dim).Render(interval)

	line := fmt.Sprintf("  %s %s  %s", nameStyled, intervalStyled, status)
	if detail != "" {
		line += "  " + Dimmed.Render(detail)
	}
	return line
}
