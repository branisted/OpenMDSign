package server

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"
)

// loopbackOnly reports whether addr binds a loopback IP. PROTOCOL.md §1 requires
// the daemon to bind loopback ONLY; Run refuses a non-loopback bind.
func loopbackOnly(addr string) (bool, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false, fmt.Errorf("parse listen address %q: %w", addr, err)
	}
	if host == "" {
		// An empty host means "all interfaces" — explicitly disallowed.
		return false, nil
	}
	ip := net.ParseIP(host)
	if ip == nil {
		// A hostname (e.g. "localhost") — resolve and require every A/AAAA to be
		// loopback so we never accidentally bind a routable interface.
		addrs, err := net.LookupIP(host)
		if err != nil || len(addrs) == 0 {
			return false, fmt.Errorf("resolve listen host %q: %w", host, err)
		}
		for _, a := range addrs {
			if !a.IsLoopback() {
				return false, nil
			}
		}
		return true, nil
	}
	return ip.IsLoopback(), nil
}

// Run starts the HTTPS listener (and the optional plain-HTTP probe listener) and
// blocks until ctx is cancelled, then gracefully shuts them down. Both listeners
// serve the same CORS+routes handler. The HTTPS listener uses the persistent
// per-machine serving cert (Daemon Phase D, servingcert.go) unless
// EphemeralDevCert selects the in-memory dev fallback.
func (s *Server) Run(ctx context.Context) error {
	// Enforce loopback-only binding (PROTOCOL.md §1).
	if ok, err := loopbackOnly(s.cfg.HTTPSAddr); err != nil {
		return err
	} else if !ok {
		return fmt.Errorf("refusing to bind HTTPS to non-loopback address %q (PROTOCOL.md §1: loopback only)", s.cfg.HTTPSAddr)
	}

	cert, err := s.servingCert(ctx)
	if err != nil {
		return err
	}

	s.log.Info("openmdsignd starting",
		"https_addr", s.cfg.HTTPSAddr, "hostname", s.cfg.Hostname,
		"http_addr", orNone(s.cfg.HTTPAddr), "cors_allowlist", s.cfg.CORSAllowlist)

	httpsSrv := &http.Server{
		Addr:              s.cfg.HTTPSAddr,
		Handler:           s.handler,
		TLSConfig:         &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12},
		ReadHeaderTimeout: 10 * time.Second,
	}

	errCh := make(chan error, 2)

	// Bind the HTTPS listener up front so a bind failure surfaces immediately.
	httpsLn, err := net.Listen("tcp", s.cfg.HTTPSAddr)
	if err != nil {
		return fmt.Errorf("listen HTTPS %q: %w", s.cfg.HTTPSAddr, err)
	}
	go func() {
		// ServeTLS with empty file args uses TLSConfig.Certificates.
		if err := httpsSrv.ServeTLS(httpsLn, "", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- fmt.Errorf("HTTPS serve: %w", err)
		}
	}()

	var httpSrv *http.Server
	if s.cfg.HTTPAddr != "" {
		if ok, err := loopbackOnly(s.cfg.HTTPAddr); err != nil {
			return err
		} else if !ok {
			return fmt.Errorf("refusing to bind HTTP to non-loopback address %q (PROTOCOL.md §1: loopback only)", s.cfg.HTTPAddr)
		}
		httpSrv = &http.Server{
			Addr:              s.cfg.HTTPAddr,
			Handler:           s.handler,
			ReadHeaderTimeout: 10 * time.Second,
		}
		httpLn, err := net.Listen("tcp", s.cfg.HTTPAddr)
		if err != nil {
			return fmt.Errorf("listen HTTP %q: %w", s.cfg.HTTPAddr, err)
		}
		go func() {
			if err := httpSrv.Serve(httpLn); err != nil && !errors.Is(err, http.ErrServerClosed) {
				errCh <- fmt.Errorf("HTTP serve: %w", err)
			}
		}()
	}

	select {
	case <-ctx.Done():
		s.log.Info("shutdown requested")
	case err := <-errCh:
		// A serve error: shut the other listener down and return it.
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_ = httpsSrv.Shutdown(shutdownCtx)
		if httpSrv != nil {
			_ = httpSrv.Shutdown(shutdownCtx)
		}
		cancel()
		return err
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = httpsSrv.Shutdown(shutdownCtx)
	if httpSrv != nil {
		_ = httpSrv.Shutdown(shutdownCtx)
	}
	return nil
}

// servingCert resolves the TLS certificate the listener presents. It serves the
// persistent per-machine cert (generating it on first run) and, on macOS, logs a
// clear WARN pointing the user at `openmdsignd trust install` when that cert is
// not yet a trusted anchor. With EphemeralDevCert it serves the in-memory dev
// fallback instead. Trust is NEVER auto-installed here — that is the user's
// explicit, password-gated `trust install` action.
func (s *Server) servingCert(ctx context.Context) (tls.Certificate, error) {
	if s.cfg.EphemeralDevCert {
		cert, err := DevCert(s.cfg.Hostname)
		if err != nil {
			return tls.Certificate{}, fmt.Errorf("ephemeral dev certificate: %w", err)
		}
		s.log.Warn("serving an EPHEMERAL self-signed dev cert (--dev-cert) — browsers will NOT trust it. " +
			"For a trusted browser flow, drop --dev-cert and run 'openmdsignd trust install'. curl -k works for smoke testing.")
		return cert, nil
	}

	dir := s.cfg.TLSDir
	if dir == "" {
		d, err := DefaultTLSDir()
		if err != nil {
			return tls.Certificate{}, fmt.Errorf("resolve tls dir: %w", err)
		}
		dir = d
	}
	store := CertStore{Hostname: s.cfg.Hostname, Dir: dir}
	cert, err := store.EnsureCert()
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("serving certificate: %w", err)
	}
	s.warnIfUntrusted(ctx, store)
	return cert, nil
}

// warnIfUntrusted checks whether the serving cert is a trusted SSL anchor and
// logs guidance when it is not. It performs NO mutation — Status is read-only.
func (s *Server) warnIfUntrusted(ctx context.Context, store CertStore) {
	st, err := NewTrustStore(store).Status(ctx)
	if err != nil {
		// Non-macOS (or a status probe failure): we cannot verify OS trust.
		s.log.Warn("cannot verify serving-cert trust (browser trust management is macOS-only)",
			"cert", store.CertPath(), "err", err.Error())
		return
	}
	if st.Trusted {
		s.log.Info("serving cert is a trusted SSL anchor in the login keychain", "cert", store.CertPath())
		return
	}
	s.log.Warn("serving cert is NOT trusted by the OS — browsers will reject the TLS handshake. "+
		"Run 'openmdsignd trust install' (prompts for your login-keychain password) to add this "+
		"per-machine cert as a trusted SSL anchor. Also, '"+s.cfg.Hostname+"' must resolve to "+
		"127.0.0.1: public DNS provides this; add a hosts entry '127.0.0.1 "+s.cfg.Hostname+
		"' as an offline fallback.",
		"cert", store.CertPath())
}

func orNone(s string) string {
	if s == "" {
		return "(disabled)"
	}
	return s
}
