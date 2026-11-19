// Package config liest die Laufzeitkonfiguration aus Umgebungsvariablen (NRP_*).
package config

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

type Config struct {
	DBDir         string
	BackupDir     string
	RunDir        string
	LogDir        string
	MasterKeyFile string
	CRSDir        string
	HTMLDir       string
	NginxBin      string
	NginxConf     string
	WAFCheckBin   string
	VersionsFile  string

	APIListen      string
	APITokenListen string
	APISANs        []string
	TokensEnabled  bool
	MetricsListen  string

	PublicEndpoint   string
	WireGuardEnabled bool
	WGOverlayCIDR    string
	WGPort           int

	ACMEDirectory string
	ACMEEmail     string
	ACMEWorkers   int
	// ACMECAFile: zusaetzliches Root-Zertifikat fuer interne ACME-CAs (z. B. Pebble).
	ACMECAFile string

	LogLevel    string
	CrowdsecURL string
	LogMaxBytes int64
	LogKeep     int
}

func env(key, def string) string {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		return v
	}
	return def
}

func envBool(key string, def bool) bool {
	v, err := strconv.ParseBool(env(key, ""))
	if err != nil {
		return def
	}
	return v
}

func envInt(key string, def int) int {
	v, err := strconv.Atoi(env(key, ""))
	if err != nil {
		return def
	}
	return v
}

func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func Load() Config {
	return Config{
		DBDir:         env("NRP_DB_DIR", "/var/lib/nrp/db"),
		BackupDir:     env("NRP_BACKUP_DIR", "/var/lib/nrp/backups"),
		RunDir:        env("NRP_RUN_DIR", "/run/nrp"),
		LogDir:        env("NRP_LOG_DIR", "/var/log/nrp"),
		MasterKeyFile: env("NRP_MASTER_KEY_FILE", "/run/secrets/nrp_master_key"),
		CRSDir:        env("NRP_CRS_DIR", "/usr/share/nrp/coreruleset"),
		HTMLDir:       env("NRP_HTML_DIR", "/usr/share/nrp/html"),
		NginxBin:      env("NRP_NGINX_BIN", "nginx"),
		NginxConf:     env("NRP_NGINX_CONF", "/etc/nginx/nginx.conf"),
		WAFCheckBin:   env("NRP_WAF_CHECK_BIN", "nrp-check-waf"),
		VersionsFile:  env("NRP_VERSIONS_FILE", "/usr/share/nrp/versions"),

		APIListen:      env("NRP_API_LISTEN", "127.0.0.1:8443"),
		APITokenListen: env("NRP_API_TOKEN_LISTEN", ""),
		APISANs:        splitList(env("NRP_API_SANS", "localhost,127.0.0.1")),
		TokensEnabled:  envBool("NRP_API_TOKENS_ENABLED", false),
		MetricsListen:  env("NRP_METRICS_LISTEN", ""),

		PublicEndpoint:   env("NRP_PUBLIC_ENDPOINT", ""),
		WireGuardEnabled: envBool("NRP_WIREGUARD_ENABLED", false),
		WGOverlayCIDR:    env("NRP_WG_OVERLAY_CIDR", "10.240.0.0/16"),
		WGPort:           envInt("NRP_WG_PORT", 51820),

		ACMEDirectory: env("NRP_ACME_DIRECTORY", "https://acme-v02.api.letsencrypt.org/directory"),
		ACMEEmail:     env("NRP_ACME_EMAIL", ""),
		ACMEWorkers:   envInt("NRP_ACME_WORKERS", 4),
		ACMECAFile:    env("NRP_ACME_CA_FILE", ""),

		LogLevel:    env("NRP_LOG_LEVEL", "info"),
		CrowdsecURL: env("NRP_CROWDSEC_LAPI_URL", ""),
		LogMaxBytes: int64(envInt("NRP_LOG_MAX_MB", 100)) << 20,
		LogKeep:     envInt("NRP_LOG_KEEP", 10),
	}
}

func (c Config) DBPath() string     { return filepath.Join(c.DBDir, "nrp.db") }
func (c Config) LockPath() string   { return filepath.Join(c.DBDir, "nrp.lock") }
func (c Config) SocketPath() string { return c.RunDir + "/nrp.sock" }
func (c Config) RenderDir() string  { return c.RunDir + "/render" }
func (c Config) CertsDir() string   { return c.RunDir + "/certs" }
func (c Config) AcmeDir() string    { return c.RunDir + "/acme" }
