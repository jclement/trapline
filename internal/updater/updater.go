package updater

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"runtime"
	"strings"
	"time"
)

// Release represents a GitHub release.
type Release struct {
	TagName string  `json:"tag_name"`
	Assets  []Asset `json:"assets"`
}

// Asset represents a release asset.
type Asset struct {
	Name               string `json:"name"`
	BrowserDownloadURL string `json:"browser_download_url"`
}

// Updater checks for and applies updates from GitHub releases.
type Updater struct {
	Repo           string
	CurrentVersion string
	BinaryPath     string
	client         *http.Client
}

// New creates a new updater.
func New(repo, currentVersion, binaryPath string) *Updater {
	return &Updater{
		Repo:           repo,
		CurrentVersion: currentVersion,
		BinaryPath:     binaryPath,
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// CheckResult holds the result of an update check.
type CheckResult struct {
	Available      bool
	CurrentVersion string
	LatestVersion  string
	DownloadURL    string
	ChecksumURL    string
}

// Check queries GitHub for the latest release.
func (u *Updater) Check(ctx context.Context) (*CheckResult, error) {
	url := fmt.Sprintf("https://api.github.com/repos/%s/releases/latest", u.Repo)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github.v3+json")

	resp, err := u.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("checking for updates: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GitHub API returned %d", resp.StatusCode)
	}

	var release Release
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		return nil, fmt.Errorf("parsing release: %w", err)
	}

	latest := strings.TrimPrefix(release.TagName, "v")
	current := strings.TrimPrefix(u.CurrentVersion, "v")

	result := &CheckResult{
		CurrentVersion: u.CurrentVersion,
		LatestVersion:  release.TagName,
		Available:      latest != current && latest > current,
	}

	// Find the right binary for this platform
	binaryName := fmt.Sprintf("trapline_linux_%s", runtime.GOARCH)
	for _, asset := range release.Assets {
		if asset.Name == binaryName {
			result.DownloadURL = asset.BrowserDownloadURL
		}
		if asset.Name == "checksums.txt" {
			result.ChecksumURL = asset.BrowserDownloadURL
		}
	}

	return result, nil
}

// Apply downloads and installs the update.
func (u *Updater) Apply(ctx context.Context, result *CheckResult) error {
	if result.DownloadURL == "" {
		return fmt.Errorf("no download URL for %s/%s", runtime.GOOS, runtime.GOARCH)
	}

	// Download new binary
	tmpPath := u.BinaryPath + ".new"
	if err := u.download(ctx, result.DownloadURL, tmpPath); err != nil {
		return fmt.Errorf("downloading update: %w", err)
	}

	// Verify checksum if available
	if result.ChecksumURL != "" {
		if err := u.verifyChecksum(ctx, result.ChecksumURL, tmpPath); err != nil {
			os.Remove(tmpPath)
			return fmt.Errorf("checksum verification: %w", err)
		}
	}

	// Backup current binary
	backupPath := u.BinaryPath + ".bak"
	if err := copyFile(u.BinaryPath, backupPath); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("backing up current binary: %w", err)
	}

	// Atomic replace
	if err := os.Chmod(tmpPath, 0755); err != nil {
		os.Remove(tmpPath)
		return err
	}
	if err := os.Rename(tmpPath, u.BinaryPath); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("replacing binary: %w", err)
	}

	return nil
}

func (u *Updater) download(ctx context.Context, url, dest string) error {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return err
	}

	resp, err := u.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download returned %d", resp.StatusCode)
	}

	f, err := os.Create(dest)
	if err != nil {
		return err
	}
	defer f.Close()

	_, err = io.Copy(f, resp.Body)
	return err
}

func (u *Updater) verifyChecksum(ctx context.Context, checksumURL, filePath string) error {
	req, err := http.NewRequestWithContext(ctx, "GET", checksumURL, nil)
	if err != nil {
		return err
	}

	resp, err := u.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	// Parse checksums.txt
	expectedHash := ""
	binaryName := fmt.Sprintf("trapline_linux_%s", runtime.GOARCH)
	for _, line := range strings.Split(string(body), "\n") {
		parts := strings.Fields(line)
		if len(parts) == 2 && parts[1] == binaryName {
			expectedHash = parts[0]
			break
		}
	}

	if expectedHash == "" {
		return fmt.Errorf("no checksum found for %s", binaryName)
	}

	// Hash the downloaded file
	f, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return err
	}

	actualHash := hex.EncodeToString(h.Sum(nil))
	if actualHash != expectedHash {
		return fmt.Errorf("checksum mismatch: expected %s, got %s", expectedHash, actualHash)
	}

	return nil
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, in)
	return err
}
