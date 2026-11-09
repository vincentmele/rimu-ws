// An HTTP/3 client (quic-go's http3 package) that runs the scenarios of .scripts/h3-interop.sh
// against one server and prints one line per scenario: "ok NAME" or "FAIL NAME: why". The exit
// status is non-zero if any failed. Every request has a 5 s limit (ruling T21-d).
//
//	quic-go-client -addr 127.0.0.1:8443 -ca server.crt -static /data/static [-seq 1000] [-par 64]
package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/quic-go/quic-go/http3"
)

const requestLimit = 5 * time.Second

var (
	addr      = flag.String("addr", "", "host:port of the server, [::1]:8443 for IPv6")
	ca        = flag.String("ca", "", "PEM file that holds the server's certificate")
	staticDir = flag.String("static", "", "directory that the server serves under /static")
	seq       = flag.Int("seq", 1000, "sequential requests on one connection")
	par       = flag.Int("par", 64, "parallel connections")
	bodyBytes = flag.Int("post", 1<<20, "bytes POSTed to /echo")
)

func main() {
	flag.Parse()
	if *addr == "" || *ca == "" || *staticDir == "" {
		fmt.Fprintln(os.Stderr, "-addr, -ca and -static are required")
		os.Exit(2)
	}
	pem, err := os.ReadFile(*ca)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		fmt.Fprintln(os.Stderr, "no certificate in", *ca)
		os.Exit(2)
	}
	failed := false
	report := func(name string, err error) {
		if err != nil {
			failed = true
			fmt.Printf("FAIL %s: %v\n", name, err)
		} else {
			fmt.Printf("ok %s\n", name)
		}
	}
	report("baseline", baseline(pool))
	report("static", static(pool))
	report("post-1mib", post(pool))
	report("sequential", sequential(pool))
	report("parallel", parallel(pool))
	if failed {
		os.Exit(1)
	}
}

// newTransport is a client whose connections are its own: a fresh transport opens a connection.
func newTransport(pool *x509.CertPool) *http3.Transport {
	return &http3.Transport{
		TLSClientConfig:    &tls.Config{RootCAs: pool},
		DisableCompression: true, // the scenarios set Accept-Encoding and read the bytes as sent
	}
}

func do(rt *http3.Transport, method, path string, hdr map[string]string, body []byte) (*http.Response, []byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), requestLimit)
	defer cancel()
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, "https://"+*addr+path, rd)
	if err != nil {
		return nil, nil, err
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	res, err := rt.RoundTrip(req)
	if err != nil {
		return nil, nil, err
	}
	defer res.Body.Close()
	data, err := io.ReadAll(res.Body)
	return res, data, err
}

func baseline(pool *x509.CertPool) error {
	rt := newTransport(pool)
	defer rt.Close()
	res, data, err := do(rt, "GET", "/baseline2?a=1&b=2", nil, nil)
	if err != nil {
		return err
	}
	if res.StatusCode != 200 || string(data) != "3" {
		return fmt.Errorf("status %d body %q", res.StatusCode, data)
	}
	return nil
}

// static asks for every file of the directory with br, gzip and identity, and compares the bytes
// with the file, or with its twin if the server must have served that.
func static(pool *x509.CertPool) error {
	entries, err := os.ReadDir(*staticDir)
	if err != nil {
		return err
	}
	var files []string
	for _, e := range entries {
		n := e.Name()
		if !strings.HasSuffix(n, ".br") && !strings.HasSuffix(n, ".gz") {
			files = append(files, n)
		}
	}
	sort.Strings(files)
	rt := newTransport(pool)
	defer rt.Close()
	for _, f := range files {
		for _, enc := range []string{"br", "gzip", "identity"} {
			want, twin, wantEnc, err := expected(f, enc)
			if err != nil {
				return err
			}
			res, data, err := do(rt, "GET", "/static/"+f, map[string]string{"Accept-Encoding": enc}, nil)
			if err != nil {
				return fmt.Errorf("%s (%s): %v", f, enc, err)
			}
			if res.StatusCode != 200 {
				return fmt.Errorf("%s (%s): status %d", f, enc, res.StatusCode)
			}
			if got := res.Header.Get("Content-Encoding"); got != wantEnc {
				return fmt.Errorf("%s (%s): content-encoding %q, want %q (twin %s)", f, enc, got, wantEnc, twin)
			}
			if !bytes.Equal(data, want) {
				return fmt.Errorf("%s (%s): %d bytes differ from %s (%d bytes)", f, enc, len(data), twin, len(want))
			}
		}
	}
	return nil
}

// expected is the file that a request for f with the coding enc must get, and the
// content-encoding that goes with it.
func expected(f, enc string) (data []byte, name, coding string, err error) {
	name = f
	switch enc {
	case "br":
		coding = "br"
		name = f + ".br"
	case "gzip":
		coding = "gzip"
		name = f + ".gz"
	}
	data, err = os.ReadFile(filepath.Join(*staticDir, name))
	if err != nil && coding != "" && os.IsNotExist(err) {
		coding, name = "", f
		data, err = os.ReadFile(filepath.Join(*staticDir, f))
	}
	return
}

func post(pool *x509.CertPool) error {
	rt := newTransport(pool)
	defer rt.Close()
	body := make([]byte, *bodyBytes)
	if _, err := rand.Read(body); err != nil {
		return err
	}
	res, data, err := do(rt, "POST", "/echo", map[string]string{"Content-Type": "application/octet-stream"}, body)
	if err != nil {
		return err
	}
	if res.StatusCode != 200 || !bytes.Equal(data, body) {
		return fmt.Errorf("status %d, %d bytes back of %d", res.StatusCode, len(data), len(body))
	}
	return nil
}

// sequential sends -seq requests one after the other on one connection and checks each answer.
func sequential(pool *x509.CertPool) error {
	rt := newTransport(pool)
	defer rt.Close()
	for i := 1; i <= *seq; i++ {
		res, data, err := do(rt, "GET", "/baseline2?a="+strconv.Itoa(i)+"&b=1", nil, nil)
		if err != nil {
			return fmt.Errorf("request %d: %v", i, err)
		}
		if res.StatusCode != 200 || string(data) != strconv.Itoa(i+1) {
			return fmt.Errorf("request %d: status %d body %q", i, res.StatusCode, data)
		}
	}
	return nil
}

// parallel opens -par connections at once, each of which sends five requests.
func parallel(pool *x509.CertPool) error {
	errs := make([]error, *par)
	var wg sync.WaitGroup
	for c := 0; c < *par; c++ {
		wg.Add(1)
		go func(c int) {
			defer wg.Done()
			rt := newTransport(pool)
			defer rt.Close()
			for i := 1; i <= 5; i++ {
				res, data, err := do(rt, "GET", "/baseline2?a="+strconv.Itoa(c)+"&b="+strconv.Itoa(i), nil, nil)
				if err != nil {
					errs[c] = fmt.Errorf("connection %d request %d: %v", c, i, err)
					return
				}
				if res.StatusCode != 200 || string(data) != strconv.Itoa(c+i) {
					errs[c] = fmt.Errorf("connection %d request %d: status %d body %q", c, i, res.StatusCode, data)
					return
				}
			}
		}(c)
	}
	wg.Wait()
	for _, err := range errs {
		if err != nil {
			return err
		}
	}
	return nil
}
