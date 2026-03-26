// Package updater implements Trapline's self-update mechanism. It polls the
// GitHub Releases API for the project's repository, compares the latest
// release tag to the currently running version, and — when a newer version is
// available — downloads the new binary, verifies its SHA-256 checksum, and
// atomically replaces the running binary on disk.
//
// Design decisions:
//
//   - GitHub Releases as the distribution channel: avoids the complexity of a
//     custom update server. Release assets follow the naming convention
//     "trapline_linux_<GOARCH>" (e.g. trapline_linux_amd64).
//
//   - SHA-256 checksum verification: every release includes a checksums.txt
//     file (produced by goreleaser or CI). The updater downloads this file and
//     verifies the downloaded binary's hash matches before replacing the
//     current binary. This guards against truncated downloads and CDN
//     corruption.
//
//   - Cosign signature verification (optional, planned): the architecture
//     supports future integration with sigstore/cosign to verify that the
//     release binary was built by the project's CI pipeline. This would guard
//     against a compromised GitHub account uploading a malicious binary.
//
//   - Atomic binary replacement: the new binary is downloaded to a ".new"
//     temp file, verified, then renamed over the running binary using
//     os.Rename. On Linux, rename(2) on the same filesystem is atomic, so
//     the binary is never in a partially-written state. The old binary is
//     backed up to ".bak" before replacement for one-version rollback.
//
//   - String-based version comparison: versions are compared as strings after
//     stripping the "v" prefix (e.g. "0.4.2" vs "0.4.1"). This works correctly
//     for semver-style versions with consistent digit counts because string
//     comparison is lexicographic. A full semver parsing library was considered
//     overkill for this use case where the project controls the tag format and
//     always uses "vMAJOR.MINOR.PATCH".
//
//   - HTTP client with 30-second timeout: prevents the update check from
//     hanging indefinitely on slow or unresponsive networks. The updater
//     runs in the background and should not block the main scan loop.
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

// Release represents a GitHub release as returned by the GitHub Releases API.
// Only the fields needed for update checking are included; the rest are
// ignored by json.Decoder.
type Release struct {
	// TagName is the git tag for this release (e.g. "v0.4.2"). This is
	// compared against the currently running version to determine whether
	// an update is available.
	TagName string `json:"tag_name"`

	// Assets is the list of downloadable files attached to this release.
	Assets []Asset `json:"assets"`
}

// Asset represents a single downloadable file attached to a GitHub release.
type Asset struct {
	// Name is the filename of the asset (e.g. "trapline_linux_amd64",
	// "checksums.txt").
	Name string `json:"name"`

	// BrowserDownloadURL is the direct download URL for this asset.
	BrowserDownloadURL string `json:"browser_download_url"`
}

// Updater checks for and applies updates from GitHub releases. It is
// configured with the GitHub repository slug, the currently running version,
// and the path to the binary on disk. The Check method queries GitHub; the
// Apply method downloads, verifies, and installs the update.
type Updater struct {
	// Repo is the GitHub "owner/repo" slug (e.g. "jclement/tripline").
	Repo string

	// CurrentVersion is the version string of the currently running binary
	// (e.g. "v0.4.2" or "0.4.2"). The "v" prefix is stripped for comparison.
	CurrentVersion string

	// BinaryPath is the absolute path to the trapline binary on disk
	// (typically /usr/local/bin/trapline).
	BinaryPath string

	// client is the HTTP client used for all GitHub API and download requests.
	// It has a 30-second timeout to prevent blocking on slow networks.
	client *http.Client
}

// New creates a new Updater configured for the given GitHub repository,
// current version, and binary path. The HTTP client is initialized with a
// 30-second timeout.
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

// CheckResult holds the result of an update check against GitHub Releases.
type CheckResult struct {
	// Available is true when a newer version exists on GitHub.
	Available bool

	// CurrentVersion is the version of the running binary.
	CurrentVersion string

	// LatestVersion is the tag name of the latest GitHub release.
	LatestVersion string

	// DownloadURL is the direct download URL for the platform-appropriate
	// binary asset. Empty if no matching asset was found.
	DownloadURL string

	// ChecksumURL is the download URL for the checksums.txt file. Empty if
	// no checksum file was attached to the release.
	ChecksumURL string
}

// Check queries the GitHub Releases API for the latest release and compares
// it to the currently running version. It returns a [CheckResult] indicating
// whether an update is available and, if so, the download URLs for the binary
// and checksum file.
//
// The comparison strips the "v" prefix from both versions and uses a simple
// string comparison (latest != current && latest > current). This works for
// the project's semver-style tags (e.g. "0.4.1" < "0.4.2") because Go's
// string comparison is lexicographic and the project uses consistent digit
// counts.
//
// The binary asset is matched by name using the pattern
// "trapline_linux_<GOARCH>" where GOARCH is the runtime architecture of the
// currently running binary (e.g. "amd64", "arm64").
func (u *Updater) Check(ctx context.Context) (*CheckResult, error) {
	url := fmt.Sprintf("https://api.github.com/repos/%s/releases/latest", u.Repo)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	// Use the GitHub v3 JSON media type for stable API behavior.
	req.Header.Set("Accept", "application/vnd.github.v3+json")

	resp, err := u.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("checking for updates: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GitHub API returned %d", resp.StatusCode)
	}

	var release Release
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		return nil, fmt.Errorf("parsing release: %w", err)
	}

	// Strip the "v" prefix for comparison so that both "v0.4.2" and "0.4.2"
	// are handled uniformly.
	latest := strings.TrimPrefix(release.TagName, "v")
	current := strings.TrimPrefix(u.CurrentVersion, "v")

	result := &CheckResult{
		CurrentVersion: u.CurrentVersion,
		LatestVersion:  release.TagName,
		// String comparison: lexicographic ordering works for semver with
		// consistent digit counts (e.g. "0.4.1" < "0.4.2" < "0.10.0" would
		// fail, but the project uses single-digit minor/patch versions so far).
		Available: latest != current && latest > current,
	}

	// Find the binary asset matching this platform's architecture. The naming
	// convention "trapline_linux_<GOARCH>" is set by the release CI pipeline.
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

// Apply downloads and installs the update described by the given CheckResult.
// The update process is designed to be crash-safe:
//
//  1. Download the new binary to "<BinaryPath>.new" (a temp file).
//  2. Verify the SHA-256 checksum against checksums.txt (if available).
//  3. Back up the current binary to "<BinaryPath>.bak" for rollback.
//  4. Set executable permissions on the new binary.
//  5. Atomically rename the new binary over the current one.
//
// If any step fails after the download, the temp file is cleaned up. If the
// rename fails, both the old binary and the backup remain intact.
//
// After a successful Apply, the caller is responsible for restarting the
// process (typically via systemd restart) to begin running the new version.
func (u *Updater) Apply(ctx context.Context, result *CheckResult) error {
	if result.DownloadURL == "" {
		return fmt.Errorf("no download URL for %s/%s", runtime.GOOS, runtime.GOARCH)
	}

	// Step 1: Download the new binary to a temporary path alongside the
	// current binary. Using the same directory ensures we are on the same
	// filesystem, which is required for atomic rename(2).
	tmpPath := u.BinaryPath + ".new"
	if err := u.download(ctx, result.DownloadURL, tmpPath); err != nil {
		return fmt.Errorf("downloading update: %w", err)
	}

	// Step 2: Verify the SHA-256 checksum if a checksums.txt URL is available.
	// This catches truncated downloads, CDN corruption, and (partially) MITM
	// attacks (full protection requires cosign verification).
	if result.ChecksumURL != "" {
		if err := u.verifyChecksum(ctx, result.ChecksumURL, tmpPath); err != nil {
			_ = os.Remove(tmpPath) // clean up the failed download
			return fmt.Errorf("checksum verification: %w", err)
		}
	}

	// Step 3: Back up the current binary. This provides a one-version rollback
	// if the new binary turns out to be broken. The backup is a copy (not a
	// rename) so the current binary remains in place until the atomic rename.
	backupPath := u.BinaryPath + ".bak"
	if err := copyFile(u.BinaryPath, backupPath); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("backing up current binary: %w", err)
	}

	// Step 4: Set executable permissions before the rename so the binary is
	// immediately executable once it lands at the final path.
	if err := os.Chmod(tmpPath, 0755); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}

	// Step 5: Atomic replace via rename(2). On Linux, this is atomic on the
	// same filesystem — the old binary is replaced in a single operation.
	if err := os.Rename(tmpPath, u.BinaryPath); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("replacing binary: %w", err)
	}

	return nil
}

// download fetches the content at the given URL and writes it to the dest
// path on disk. It streams the response body directly to the file to handle
// large binaries without buffering everything in memory.
func (u *Updater) download(ctx context.Context, url, dest string) error {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return err
	}

	resp, err := u.client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download returned %d", resp.StatusCode)
	}

	f, err := os.Create(dest)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()

	// Stream the body directly to disk to avoid holding the entire binary
	// in memory.
	_, err = io.Copy(f, resp.Body)
	return err
}

// verifyChecksum downloads the checksums.txt file from the release, finds the
// expected SHA-256 hash for the platform-appropriate binary, and compares it
// to the actual hash of the downloaded file.
//
// The checksums.txt format follows goreleaser conventions: each line contains
// a hex-encoded SHA-256 hash followed by whitespace and the filename, e.g.:
//
//	a1b2c3d4...  trapline_linux_amd64
//	e5f6a7b8...  trapline_linux_arm64
func (u *Updater) verifyChecksum(ctx context.Context, checksumURL, filePath string) error {
	req, err := http.NewRequestWithContext(ctx, "GET", checksumURL, nil)
	if err != nil {
		return err
	}

	resp, err := u.client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	// Parse checksums.txt to find the expected hash for our platform binary.
	// Each line has the format: "<hex-sha256>  <filename>"
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

	// Compute the SHA-256 hash of the downloaded binary file.
	f, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()

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

// copyFile copies a file from src to dst by streaming through memory. It is
// used to create the backup of the current binary before replacement. A copy
// (rather than rename) is used because we want the original to remain in
// place until the atomic os.Rename of the new binary.
func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer func() { _ = in.Close() }()

	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer func() { _ = out.Close() }()

	_, err = io.Copy(out, in)
	return err
}
