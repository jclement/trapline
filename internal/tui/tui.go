package tui

import (
	"fmt"
	"os"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/jclement/tripline/pkg/finding"
)

var (
	// Colors
	Red     = lipgloss.Color("#FF0000")
	Yellow  = lipgloss.Color("#FFAA00")
	Green   = lipgloss.Color("#00FF00")
	Cyan    = lipgloss.Color("#00CCCC")
	Magenta = lipgloss.Color("#FF00FF")
	Dim     = lipgloss.Color("#666666")
	White   = lipgloss.Color("#FFFFFF")

	// Styles
	Title = lipgloss.NewStyle().
		Bold(true).
		Foreground(Cyan).
		MarginBottom(1)

	Subtitle = lipgloss.NewStyle().
		Bold(true).
		Foreground(White)

	Success = lipgloss.NewStyle().
		Foreground(Green)

	Warning = lipgloss.NewStyle().
		Foreground(Yellow)

	Error = lipgloss.NewStyle().
		Foreground(Red)

	Critical = lipgloss.NewStyle().
		Bold(true).
		Foreground(Red)

	Dimmed = lipgloss.NewStyle().
		Foreground(Dim)

	FindingBox = lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(Dim).
		Padding(0, 1).
		MarginBottom(1)

	// For the banner
	Banner = lipgloss.NewStyle().
		Bold(true).
		Foreground(Cyan)

	TaglineStyle = lipgloss.NewStyle().
			Italic(true).
			Foreground(Dim)
)

// IsTTY returns true if stdout is a terminal.
func IsTTY() bool {
	fi, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

// SeverityStyle returns the appropriate style for a severity level.
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

// SeverityBadge returns a colored severity badge like " CRITICAL " or " HIGH ".
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

// FormatFinding renders a finding for TTY output.
func FormatFinding(f *finding.Finding) string {
	badge := SeverityBadge(f.Severity)
	id := Dimmed.Render(f.FindingID)
	summary := lipgloss.NewStyle().Bold(true).Render(f.Summary)

	content := fmt.Sprintf("%s %s\n%s", badge, summary, id)

	if f.Detail != nil {
		for k, v := range f.Detail {
			content += fmt.Sprintf("\n  %s %v",
				Dimmed.Render(k+":"),
				v)
		}
	}

	return FindingBox.Render(content)
}

// CheckMark returns a styled check/cross/warning mark.
func CheckMark(passed bool) string {
	if passed {
		return Success.Render("✓")
	}
	return Error.Render("✗")
}

// WarnMark returns a styled warning mark.
func WarnMark() string {
	return Warning.Render("⚠")
}

// FormatBanner renders the trapline banner with version and tagline.
func FormatBanner(version, tagline string) string {
	art := Banner.Render("TRAPLINE")
	ver := Dimmed.Render("v" + version)
	tag := TaglineStyle.Render(tagline)
	return fmt.Sprintf("%s %s\n%s\n", art, ver, tag)
}

// FormatSection renders a section header.
func FormatSection(title string) string {
	return Subtitle.Render("─── " + title + " ───")
}

// FormatModuleStatus renders a module status line.
func FormatModuleStatus(name string, enabled bool, interval string, detail string) string {
	status := Success.Render("enabled")
	if !enabled {
		status = Dimmed.Render("disabled")
	}

	nameStyled := lipgloss.NewStyle().Width(20).Render(name)
	intervalStyled := lipgloss.NewStyle().Width(10).Foreground(Dim).Render(interval)

	line := fmt.Sprintf("  %s %s  %s", nameStyled, intervalStyled, status)
	if detail != "" {
		line += "  " + Dimmed.Render(detail)
	}
	return line
}
