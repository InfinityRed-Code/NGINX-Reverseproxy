// Package nginx steuert den nginx-Prozess: Konfigurationstest, Reload,
// Reopen und groessenbasierte Log-Rotation.
package nginx

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

type Controller struct {
	Bin         string
	PidFile     string
	WAFCheckBin string
}

func New(bin, wafCheckBin string) *Controller {
	if bin == "" {
		bin = "nginx"
	}
	return &Controller{Bin: bin, PidFile: "/run/nginx.pid", WAFCheckBin: wafCheckBin}
}

func (c *Controller) run(ctx context.Context, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	var out bytes.Buffer
	cmd := exec.CommandContext(ctx, c.Bin, args...)
	cmd.Stdout, cmd.Stderr = &out, &out
	err := cmd.Run()
	return strings.TrimSpace(out.String()), err
}

// Test prueft eine Konfigurationsdatei mit derselben Binary wie der Betrieb.
func (c *Controller) Test(ctx context.Context, conf string) (string, error) {
	out, err := c.run(ctx, "-t", "-q", "-c", conf)
	if err != nil {
		return out, fmt.Errorf("nginx -t: %w", err)
	}
	return out, nil
}

// Running prueft ueber die PID-Datei, ob der Master-Prozess laeuft.
func (c *Controller) Running() bool {
	raw, err := os.ReadFile(c.PidFile)
	if err != nil {
		return false
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(raw)))
	if err != nil || pid <= 0 {
		return false
	}
	_, err = os.Stat(filepath.Join("/proc", strconv.Itoa(pid)))
	return err == nil
}

var ErrNotRunning = errors.New("nginx laeuft nicht")

func (c *Controller) signal(ctx context.Context, sig string) error {
	if !c.Running() {
		return ErrNotRunning
	}
	if out, err := c.run(ctx, "-s", sig); err != nil {
		return fmt.Errorf("nginx -s %s: %w: %s", sig, err, out)
	}
	return nil
}

func (c *Controller) Reload(ctx context.Context) error { return c.signal(ctx, "reload") }
func (c *Controller) Reopen(ctx context.Context) error { return c.signal(ctx, "reopen") }

var versionRe = regexp.MustCompile(`nginx/([0-9.]+)`)

func (c *Controller) Version(ctx context.Context) string {
	out, _ := c.run(ctx, "-v")
	if m := versionRe.FindStringSubmatch(out); m != nil {
		return m[1]
	}
	return ""
}

// BuildInfo liefert die Ausgabe von nginx -V (fuer nrp doctor).
func (c *Controller) BuildInfo(ctx context.Context) (string, error) { return c.run(ctx, "-V") }

// Rotate benennt Logdateien ab maxBytes um (name.N) und behaelt keep Stueck.
// Liefert true, wenn nginx die Dateien neu oeffnen muss.
func Rotate(dir string, maxBytes int64, keep int) (bool, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	rotated := false
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".log") {
			continue
		}
		info, err := e.Info()
		if err != nil || info.Size() < maxBytes {
			continue
		}
		base := filepath.Join(dir, e.Name())
		// name.log.<n> aufruecken, aelteste zuerst entfernen.
		old, _ := filepath.Glob(base + ".*")
		var nums []int
		for _, o := range old {
			if n, err := strconv.Atoi(strings.TrimPrefix(o, base+".")); err == nil {
				nums = append(nums, n)
			}
		}
		sort.Sort(sort.Reverse(sort.IntSlice(nums)))
		for _, n := range nums {
			src := base + "." + strconv.Itoa(n)
			if n+1 >= keep {
				_ = os.Remove(src)
				continue
			}
			_ = os.Rename(src, base+"."+strconv.Itoa(n+1))
		}
		if err := os.Rename(base, base+".1"); err != nil {
			return rotated, err
		}
		rotated = true
	}
	return rotated, nil
}

// CheckWAF prueft mit nrp-check-waf, ob Coraza die Regelkette laden kann.
// nginx -t validiert die Regeln nicht (libcoraza wird erst im Worker geladen);
// eine fehlerhafte Regeldatei wuerde nach dem Reload alle Worker beenden.
// Fehlt das Hilfsprogramm (Entwicklungssystem), wird die Pruefung uebersprungen.
func (c *Controller) CheckWAF(ctx context.Context, rules string) (string, error) {
	if c.WAFCheckBin == "" {
		return "", nil
	}
	bin, err := exec.LookPath(c.WAFCheckBin)
	if err != nil {
		return "", nil
	}
	ctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	var out bytes.Buffer
	cmd := exec.CommandContext(ctx, bin, rules, "60")
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Run(); err != nil {
		return strings.TrimSpace(out.String()), fmt.Errorf("nrp-check-waf: %w", err)
	}
	return strings.TrimSpace(out.String()), nil
}
