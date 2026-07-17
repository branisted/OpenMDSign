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
// serve the same CORS+routes handler. The HTTPS listener uses the Phase B
// self-signed dev cert (see DevCert / PROTOCOL.md §2 STOP note).
func (s *Server) Run(ctx context.Context) error {
	// Enforce loopback-only binding (PROTOCOL.md §1).
	if ok, err := loopbackOnly(s.cfg.HTTPSAddr); err != nil {
		return err
	} else if !ok {
		return fmt.Errorf("refusing to bind HTTPS to non-loopback address %q (PROTOCOL.md §1: loopback only)", s.cfg.HTTPSAddr)
	}

	cert, err := DevCert(s.cfg.Hostname, s.cfg.DevCertDir)
	if err != nil {
		return fmt.Errorf("dev certificate: %w", err)
	}

	s.log.Info("openmdsignd starting",
		"https_addr", s.cfg.HTTPSAddr, "hostname", s.cfg.Hostname,
		"http_addr", orNone(s.cfg.HTTPAddr), "cors_allowlist", s.cfg.CORSAllowlist)
	s.log.Warn("using a SELF-SIGNED dev certificate — browsers will not trust it. " +
		"The real publicly-trusted-cert trust gate is Daemon Phase D (PROTOCOL.md §2). " +
		"For a browser to reach this daemon, '" + s.cfg.Hostname + "' must resolve to " +
		"127.0.0.1: public DNS provides this, or add a hosts entry " +
		"'127.0.0.1 " + s.cfg.Hostname + "' as a fallback.")

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

func orNone(s string) string {
	if s == "" {
		return "(disabled)"
	}
	return s
}
