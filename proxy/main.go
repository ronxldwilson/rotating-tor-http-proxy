package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"sync/atomic"
	"time"
)

const socksAddr = "127.0.0.1:10000"

var (
	numInstances int
	reqCounter   atomic.Uint64
	statRequests atomic.Uint64
	statErrors   atomic.Uint64
)

// dialSOCKS5 opens a connection through a SOCKS5 proxy to targetAddr ("host:port").
// If username is non-empty, SOCKS5 username/password auth is performed — Tor uses
// this to isolate circuits per credential (IsolateSOCKSAuth).
func dialSOCKS5(proxyAddr, targetAddr, username, password string) (net.Conn, error) {
	host, portStr, err := net.SplitHostPort(targetAddr)
	if err != nil {
		return nil, fmt.Errorf("bad target addr: %w", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, fmt.Errorf("bad port: %w", err)
	}

	conn, err := net.DialTimeout("tcp", proxyAddr, 10*time.Second)
	if err != nil {
		return nil, err
	}

	// greeting — offer no-auth (0x00) and user/pass (0x02)
	if _, err = conn.Write([]byte{0x05, 0x02, 0x00, 0x02}); err != nil {
		conn.Close()
		return nil, err
	}
	method := make([]byte, 2)
	if _, err = io.ReadFull(conn, method); err != nil {
		conn.Close()
		return nil, err
	}

	switch method[1] {
	case 0x02:
		// username/password sub-negotiation (RFC 1929)
		auth := []byte{0x01, byte(len(username))}
		auth = append(auth, []byte(username)...)
		auth = append(auth, byte(len(password)))
		auth = append(auth, []byte(password)...)
		if _, err = conn.Write(auth); err != nil {
			conn.Close()
			return nil, err
		}
		resp := make([]byte, 2)
		if _, err = io.ReadFull(conn, resp); err != nil {
			conn.Close()
			return nil, err
		}
		if resp[1] != 0x00 {
			conn.Close()
			return nil, fmt.Errorf("SOCKS5 auth rejected")
		}
	case 0x00:
		// no auth accepted — fine
	default:
		conn.Close()
		return nil, fmt.Errorf("SOCKS5 no acceptable method: %x", method[1])
	}

	// CONNECT with domain name
	hostBytes := []byte(host)
	req := make([]byte, 0, 7+len(hostBytes))
	req = append(req, 0x05, 0x01, 0x00, 0x03, byte(len(hostBytes)))
	req = append(req, hostBytes...)
	req = append(req, byte(port>>8), byte(port&0xff))
	if _, err = conn.Write(req); err != nil {
		conn.Close()
		return nil, err
	}

	// response: VER REP RSV ATYP
	resp := make([]byte, 4)
	if _, err = io.ReadFull(conn, resp); err != nil {
		conn.Close()
		return nil, err
	}
	if resp[1] != 0x00 {
		conn.Close()
		return nil, fmt.Errorf("SOCKS5 CONNECT rejected: code %d", resp[1])
	}
	// drain bound address
	switch resp[3] {
	case 0x01:
		io.ReadFull(conn, make([]byte, 4+2))
	case 0x03:
		l := make([]byte, 1)
		io.ReadFull(conn, l)
		io.ReadFull(conn, make([]byte, int(l[0])+2))
	case 0x04:
		io.ReadFull(conn, make([]byte, 16+2))
	}

	return conn, nil
}

func dialViaTor(_ context.Context, _, addr string) (net.Conn, error) {
	tried := numInstances
	if tried > 3 {
		tried = 3
	}
	var lastErr error
	for i := 0; i < tried; i++ {
		idx := int(reqCounter.Add(1)-1) % numInstances
		// each credential maps to an isolated Tor circuit via IsolateSOCKSAuth
		user := fmt.Sprintf("i%d", idx)
		conn, err := dialSOCKS5(socksAddr, addr, user, "x")
		if err == nil {
			return conn, nil
		}
		lastErr = err
	}
	return nil, lastErr
}

func handleConnect(w http.ResponseWriter, r *http.Request) {
	remote, err := dialViaTor(r.Context(), "tcp", r.Host)
	if err != nil {
		statErrors.Add(1)
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}

	w.WriteHeader(http.StatusOK)
	hj, ok := w.(http.Hijacker)
	if !ok {
		remote.Close()
		return
	}
	local, _, err := hj.Hijack()
	if err != nil {
		remote.Close()
		return
	}

	done := make(chan struct{}, 2)
	cp := func(dst, src net.Conn) {
		io.Copy(dst, src)
		done <- struct{}{}
	}
	go cp(remote, local)
	go cp(local, remote)
	<-done
	remote.Close()
	local.Close()
	<-done
}

var hopByHop = []string{
	"Connection", "Keep-Alive", "Proxy-Authenticate", "Proxy-Authorization",
	"Proxy-Connection", "Te", "Trailers", "Transfer-Encoding", "Upgrade",
}

func handleHTTP(w http.ResponseWriter, r *http.Request) {
	r.RequestURI = ""
	for _, h := range hopByHop {
		r.Header.Del(h)
	}

	transport := &http.Transport{
		DialContext:           dialViaTor,
		ResponseHeaderTimeout: 60 * time.Second,
		DisableKeepAlives:     true,
	}
	client := &http.Client{
		Transport: transport,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Timeout: 90 * time.Second,
	}

	resp, err := client.Do(r)
	if err != nil {
		statErrors.Add(1)
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	for k, vs := range resp.Header {
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

func main() {
	n, err := strconv.Atoi(getenv("TOR_INSTANCES", "5"))
	if err != nil || n < 1 || n > 200 {
		log.Fatalf("TOR_INSTANCES must be 1-200")
	}
	numInstances = n

	go func() {
		log.Printf("[stats] listening on :4444")
		http.ListenAndServe(":4444", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{
				"tor_instances": numInstances,
				"requests":      statRequests.Load(),
				"errors":        statErrors.Load(),
			})
		}))
	}()

	log.Printf("[proxy] %d virtual instances on :3128 via single Tor process", numInstances)
	srv := &http.Server{
		Addr: ":3128",
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			statRequests.Add(1)
			if r.Method == http.MethodConnect {
				handleConnect(w, r)
			} else {
				handleHTTP(w, r)
			}
		}),
		ReadTimeout: 120 * time.Second,
		IdleTimeout: 120 * time.Second,
	}
	log.Fatal(srv.ListenAndServe())
}

func getenv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
