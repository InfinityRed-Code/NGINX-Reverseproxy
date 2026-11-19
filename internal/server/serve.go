package server

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/SoftENGINE-IT/NGINX-Reverseproxy/internal/audit"
	"github.com/SoftENGINE-IT/NGINX-Reverseproxy/internal/auth"
	"github.com/SoftENGINE-IT/NGINX-Reverseproxy/internal/pki"
	"github.com/SoftENGINE-IT/NGINX-Reverseproxy/internal/secrets"
	"github.com/SoftENGINE-IT/NGINX-Reverseproxy/internal/store"
	"github.com/SoftENGINE-IT/NGINX-Reverseproxy/internal/store/dbq"
)

// EnsurePKI erzeugt beim Erststart die interne CA und das Server-Zertifikat
// der API. Aendern sich die SANs oder laeuft es ab, wird es neu ausgestellt.
func EnsurePKI(ctx context.Context, st *store.Store, box *secrets.Box, sans []string) (*pki.CA, tls.Certificate, error) {
	var none tls.Certificate
	row, err := st.Read().GetPki(ctx)
	fresh := isNoRows(err)
	if err != nil && !fresh {
		return nil, none, err
	}
	var caKeyPEM []byte
	if fresh {
		certPEM, keyPEM, err := pki.NewCA()
		if err != nil {
			return nil, none, err
		}
		row.CaCertPem, caKeyPEM = string(certPEM), keyPEM
		if row.CaKeyEnc, err = box.Seal(keyPEM); err != nil {
			return nil, none, err
		}
	} else if caKeyPEM, err = box.Open(row.CaKeyEnc); err != nil {
		return nil, none, fmt.Errorf("CA-Schluessel: %w", err)
	}
	ca, err := pki.LoadCA([]byte(row.CaCertPem), caKeyPEM)
	if err != nil {
		return nil, none, err
	}
	reissue := fresh || pki.ServerNeedsReissue([]byte(row.ServerCertPem), sans)
	var serverKey []byte
	if reissue {
		certPEM, keyPEM, err := ca.IssueServer(sans)
		if err != nil {
			return nil, none, err
		}
		row.ServerCertPem, serverKey = string(certPEM), keyPEM
		if row.ServerKeyEnc, err = box.Seal(keyPEM); err != nil {
			return nil, none, err
		}
		var arow dbq.AuditLog
		action := "pki.server_reissue"
		if fresh {
			action = "pki.init"
		}
		err = st.Write(ctx, func(q *dbq.Queries) error {
			if err := q.UpsertPki(ctx, dbq.UpsertPkiParams{CaCertPem: row.CaCertPem, CaKeyEnc: row.CaKeyEnc,
				ServerCertPem: row.ServerCertPem, ServerKeyEnc: row.ServerKeyEnc}); err != nil {
				return err
			}
			arow, err = audit.Append(ctx, q, audit.Entry{RequestID: "system", ActorType: audit.ActorSystem, ActorID: "nrpd",
				Action: action, ResourceType: "pki", ResourceID: "api", After: map[string]any{"sans": sans,
					"ca_sha256": pki.Fingerprint(ca.Cert)}})
			return err
		})
		if err != nil {
			return nil, none, err
		}
		audit.Emit(arow)
	} else if serverKey, err = box.Open(row.ServerKeyEnc); err != nil {
		return nil, none, fmt.Errorf("Server-Schluessel: %w", err)
	}
	cert, err := tls.X509KeyPair([]byte(row.ServerCertPem), serverKey)
	return ca, cert, err
}

func httpServer(h http.Handler) *http.Server {
	return &http.Server{Handler: h, ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 60 * time.Second,
		WriteTimeout: 120 * time.Second, IdleTimeout: 120 * time.Second, MaxHeaderBytes: 64 << 10}
}

func serveUntil(ctx context.Context, srv *http.Server, ln net.Listener) error {
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			sctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			_ = srv.Shutdown(sctx)
		case <-done:
		}
	}()
	err := srv.Serve(ln)
	close(done)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

// ServeMTLS startet den API-Listener: TLS 1.3, Client-Zertifikat der NRP-CA Pflicht.
func (s *Server) ServeMTLS(ctx context.Context, addr string, ca *pki.CA, cert tls.Certificate) error {
	pool := x509.NewCertPool()
	pool.AddCert(ca.Cert)
	ln, err := tls.Listen("tcp", addr, &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert},
		ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool})
	if err != nil {
		return fmt.Errorf("API-Listener %s: %w", addr, err)
	}
	return serveUntil(ctx, httpServer(s.Handler()), ln)
}

// ServeTokens startet den separaten Token-Listener (TLS ohne Client-Zertifikat).
func (s *Server) ServeTokens(ctx context.Context, addr string, cert tls.Certificate) error {
	ln, err := tls.Listen("tcp", addr, &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert}})
	if err != nil {
		return fmt.Errorf("Token-Listener %s: %w", addr, err)
	}
	srv := httpServer(s.Handler())
	srv.BaseContext = func(net.Listener) context.Context { return auth.WithTokenListener(context.Background()) }
	return serveUntil(ctx, srv, ln)
}

// ServeUnix startet den lokalen Socket (0600, root). Wer docker exec ausfuehren
// kann, hat ohnehin Root-aequivalenten Zugriff: UID 0 erhaelt die Rolle admin.
func (s *Server) ServeUnix(ctx context.Context, path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	_ = os.Remove(path)
	ln, err := net.Listen("unix", path)
	if err != nil {
		return fmt.Errorf("Socket %s: %w", path, err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		ln.Close()
		return err
	}
	srv := httpServer(s.Handler())
	self := uint32(os.Geteuid())
	srv.ConnContext = func(ctx context.Context, c net.Conn) context.Context {
		uid, err := auth.PeerUID(c)
		if err != nil || (uid != 0 && uid != self) {
			return ctx // keine Identitaet: die Anfrage scheitert mit 401
		}
		return auth.WithIdentity(ctx, auth.Identity{Type: auth.TypeLocal, ID: "uid=" + strconv.FormatUint(uint64(uid), 10), Role: auth.Admin})
	}
	defer os.Remove(path)
	return serveUntil(ctx, srv, ln)
}

// InProcess ruft den Handler ohne Netzwerk auf (Offline-Modus der CLI).
type InProcess struct {
	Handler  http.Handler
	Identity auth.Identity
}

type memResponse struct {
	header http.Header
	status int
	body   bytes.Buffer
}

func (m *memResponse) Header() http.Header { return m.header }
func (m *memResponse) WriteHeader(c int) {
	if m.status == 0 {
		m.status = c
	}
}
func (m *memResponse) Write(b []byte) (int, error) {
	m.WriteHeader(http.StatusOK)
	return m.body.Write(b)
}

func (t InProcess) RoundTrip(req *http.Request) (*http.Response, error) {
	rec := &memResponse{header: http.Header{}}
	if req.Body == nil {
		req.Body = http.NoBody
	}
	t.Handler.ServeHTTP(rec, req.WithContext(auth.WithIdentity(req.Context(), t.Identity)))
	rec.WriteHeader(http.StatusOK)
	return &http.Response{StatusCode: rec.status, Status: strconv.Itoa(rec.status) + " " + http.StatusText(rec.status),
		Proto: "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1, Header: rec.header,
		Body: io.NopCloser(bytes.NewReader(rec.body.Bytes())), ContentLength: int64(rec.body.Len()), Request: req}, nil
}
