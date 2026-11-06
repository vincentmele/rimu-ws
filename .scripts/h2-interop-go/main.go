// h2-interop: an HTTP/2 client from Go's standard library against /baseline2.
//
//	h2-interop URL
//
// URL is http://host:port (prior-knowledge h2c) or https://host:port (h2 over TLS, certificate
// not verified). Sends 200 requests over one connection, 50 at a time, and checks that each body
// is a+b and that every response was HTTP/2. Exits 1 on the first mismatch.
package main

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: h2-interop URL")
		os.Exit(2)
	}
	base := strings.TrimSuffix(os.Args[1], "/")
	protocols := new(http.Protocols)
	if strings.HasPrefix(base, "https://") {
		protocols.SetHTTP2(true)
	} else {
		protocols.SetUnencryptedHTTP2(true)
	}
	transport := &http.Transport{
		MaxConnsPerHost: 1,
		Protocols:       protocols,
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: transport}
	var wg sync.WaitGroup
	errs := make(chan error, 200)
	sem := make(chan struct{}, 50)
	for i := 0; i < 200; i++ {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int) {
			defer wg.Done()
			defer func() { <-sem }()
			res, err := client.Get(fmt.Sprintf("%s/baseline2?a=%d&b=1", base, i))
			if err != nil {
				errs <- err
				return
			}
			defer res.Body.Close()
			body, err := io.ReadAll(res.Body)
			if err != nil {
				errs <- err
				return
			}
			if res.ProtoMajor != 2 {
				errs <- fmt.Errorf("request %d: protocol %s", i, res.Proto)
				return
			}
			if want := fmt.Sprint(i + 1); string(body) != want {
				errs <- fmt.Errorf("request %d: body %q, want %q", i, body, want)
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	failed := 0
	for err := range errs {
		failed++
		if failed <= 5 {
			fmt.Fprintln(os.Stderr, err)
		}
	}
	if failed > 0 {
		fmt.Fprintf(os.Stderr, "%d of 200 requests failed\n", failed)
		os.Exit(1)
	}
	fmt.Println("go: 200/200 ok")
}
