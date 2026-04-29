package checkhttp

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/dustin/go-humanize"
	"github.com/go-gost/x/ctx"
	"github.com/sni/go-flags"
)

const version = "0.020"

const (
	UNKNOWN  = 3
	CRITICAL = 2
	WARNING  = 1
	OK       = 0
)

type commandOpts struct {
	Timeout       time.Duration `short:"t" long:"timeout" default:"10s" description:"Timeout to wait for connection"`
	MaxBufferSize string        `long:"max-buffer-size" default:"1MB" description:"Max buffer size to read response body"`
	NoDiscard     bool          `long:"no-discard" description:"raise error when the response body is larger then max-buffer-size"`

	Consecutive int           `long:"consecutive" default:"1" description:"number of consecutive successful requests required"`
	Interim     time.Duration `long:"interim" default:"1s" description:"interval time after successful request for consecutive mode"`

	WaitFor             bool          `long:"wait-for" description:"retry until successful when enabled"`
	WaitForInterval     time.Duration `long:"wait-for-interval" default:"2s" description:"retry interval"`
	WaitForMax          time.Duration `long:"wait-for-max" description:"time to wait for success"`
	Hostname            string        `short:"H" long:"hostname" description:"Host name using Host headers"`
	IPAddress           string        `short:"I" long:"IP-address" description:"IP address or Host name"`
	Port                int           `short:"p" long:"port" description:"Port number"`
	Method              string        `short:"j" long:"method" default:"GET" description:"Set HTTP Method"`
	URI                 string        `short:"u" long:"uri" default:"/" description:"URI to request"`
	Expect              string        `short:"e" long:"expect" default:"" description:"Comma-delimited list of expected HTTP response status"`
	ExpectContent       string        `short:"s" long:"string" description:"String to expect in the content"`
	Base64ExpectContent string        `long:"base64-string" description:"Base64 Encoded string to expect the content"`
	UserAgent           string        `short:"A" long:"useragent" default:"check_http" description:"UserAgent to be sent"`
	Authorization       string        `short:"a" long:"authorization" description:"username:password on sites with basic authentication"`
	SSL                 bool          `short:"S" long:"ssl" description:"use https"`
	SNI                 bool          `long:"sni" description:"enable SNI"`
	TLSMaxVersion       string        `long:"tls-max" description:"maximum supported TLS version" choice:"1.0" choice:"1.1" choice:"1.2" choice:"1.3"`
	TCP4                bool          `short:"4" description:"use tcp4 only"`
	TCP6                bool          `short:"6" description:"use tcp6 only"`
	Version             bool          `short:"V" long:"version" description:"Show version"`
	Verbose             bool          `short:"v" long:"verbose" description:"Show verbose output"`
	Proxy               string        `long:"proxy" description:"Proxy that should be used"`
	RegexStr            string        `long:"regex" description:"Search page for case-sensitive regex string"`
	EregexStr           string        `long:"eregex" descirpition:"Search page for case-insensitive regex string"`
	ShowBody            bool          `long:"show-body" description:"Print body content bellow status line"`
	Follow              string        `long:"follow" description:"Redirection method" choice:"ok" choice:"warning" choice:"critical" choice:"follow" choice:"sticky" choice:"stickyport"`
	bufferSize          uint64
	expectByte          []byte
}

func makeTransport(opts commandOpts) (http.RoundTripper, error) {
	baseDialFunc := (&net.Dialer{
		Timeout:   opts.Timeout,
		KeepAlive: 30 * time.Second,
		DualStack: true,
	}).DialContext
	tcpMode := "tcp"
	if opts.TCP4 {
		tcpMode = "tcp4"
	}
	if opts.TCP6 {
		tcpMode = "tcp6"
	}
	dialFunc := func(ctx context.Context, _, _ string) (net.Conn, error) {
		addr := net.JoinHostPort(opts.IPAddress, fmt.Sprintf("%d", opts.Port))
		return baseDialFunc(ctx, tcpMode, addr)
	}

	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
	}
	if opts.SNI {
		host, _, err := net.SplitHostPort(opts.Hostname)
		if err != nil {
			host = opts.Hostname
		}
		tlsConfig.ServerName = host
	}

	if opts.TLSMaxVersion != "" {
		switch opts.TLSMaxVersion {
		case "1.0":
			tlsConfig.MinVersion = tls.VersionTLS10
			tlsConfig.MaxVersion = tls.VersionTLS10
		case "1.1":
			tlsConfig.MinVersion = tls.VersionTLS11
			tlsConfig.MaxVersion = tls.VersionTLS11
		case "1.2":
			tlsConfig.MaxVersion = tls.VersionTLS12
		case "1.3":
			tlsConfig.MaxVersion = tls.VersionTLS13
		}
	}

	proxy := http.ProxyFromEnvironment
	if opts.Proxy != "" {
		url, err := url.Parse(opts.Proxy)
		if err != nil {
			return nil, fmt.Errorf("Error while parsing Proxy URL. Error was: %s", err.Error())
		}
		proxy = http.ProxyURL(url)
	}

	return &http.Transport{
		// inherited http.DefaultTransport
		Proxy:                 proxy,
		DialContext:           dialFunc,
		IdleConnTimeout:       30 * time.Second,
		TLSHandshakeTimeout:   opts.Timeout,
		ExpectContinueTimeout: 1 * time.Second,
		// self-customized values
		ResponseHeaderTimeout: opts.Timeout,
		TLSClientConfig:       tlsConfig,
		ForceAttemptHTTP2:     true,
	}, nil
}

func buildRequest(ctx context.Context, opts commandOpts) (*http.Request, error) {
	schema := "http"
	if opts.SSL {
		schema = "https"
	}

	uri := fmt.Sprintf("%s://%s%s", schema, opts.Hostname, opts.URI)
	var b bytes.Buffer
	req, err := http.NewRequestWithContext(
		ctx,
		opts.Method,
		uri,
		&b,
	)
	if err != nil {
		return nil, err
	}
	if opts.Authorization != "" {
		a := strings.SplitN(opts.Authorization, ":", 2)
		if len(a) != 2 {
			return nil, fmt.Errorf("invalid authorization args")
		}
		req.SetBasicAuth(a[0], a[1])
	}
	req.Header.Set("User-Agent", opts.UserAgent)
	return req, nil
}

func expectedStatusCode(opts commandOpts, status string) string {
	expects := strings.Split(opts.Expect, ",")
	for _, e := range expects {
		if strings.Contains(status, e) {
			return e
		}
	}
	return ""
}

func printVersion(output io.Writer) {
	fmt.Fprintf(output, `%s Compiler: %s %s`,
		version,
		runtime.Compiler,
		runtime.Version())
}

type capWriter struct {
	Cap       uint64
	NoDiscard bool
	size      uint64
	buffer    []byte
}

func (w *capWriter) Write(p []byte) (int, error) {
	w.size += uint64(len(p))
	if w.size > w.Cap && w.NoDiscard {
		return 0, fmt.Errorf("could not write body buffer. buffer is full")
	}

	if w.size > w.Cap {
		q := w.Cap - uint64(len(w.buffer))
		if q != 0 {
			w.buffer = append(w.buffer, p[0:q-1]...)
		}
	} else {
		w.buffer = append(w.buffer, p...)
	}

	return len(p), nil
}

func (w *capWriter) Size() uint64 {
	return w.size
}

func (w *capWriter) Bytes() []byte {
	return w.buffer
}

type reqError struct {
	msg  string
	code int
}

func (e *reqError) Error() string {
	return e.msg
}

func (e *reqError) Code() int {
	return e.code
}

type RequestMetadata struct {
	req      *http.Request
	res      *http.Response
	duration time.Duration
	buffer   *capWriter
	body     string
	// if a follow up request was made due redirections
	followup *RequestMetadata
}

// Helper function to extract everything from *http.Request
func performHttpRequest(req *http.Request, client *http.Client, opts commandOpts) (metadata *RequestMetadata, err error) {
	if opts.Verbose {
		reqDump, _ := httputil.DumpRequest(req, true)
		log.Printf("request:\n%s", reqDump)
	}

	start := time.Now()
	res, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("Error when performing request: %s", err.Error())
	}

	if opts.Verbose {
		resDump, _ := httputil.DumpResponse(res, true)
		log.Printf("response:\n%s", resDump)
	}

	buffer := &capWriter{
		Cap:       opts.bufferSize,
		NoDiscard: opts.NoDiscard,
	}
	defer res.Body.Close()
	_, err = io.Copy(buffer, res.Body)
	body := string(buffer.Bytes())

	if err != nil {
		return nil, fmt.Errorf("Error when copying body buffer: %s", err.Error())
	}

	duration := time.Since(start)

	return &RequestMetadata{
		req,
		res,
		duration,
		buffer,
		body,
		nil,
	}, nil

}

// If a followup request is necessary, return it with err nil
// If a folllowup request is necessary and can not be generated, return nil with non-nil err
// If the function can return immediately
func generateFollowupRequest(ctx ctx.Context, opts commandOpts, res *http.Response, body string) (followup *http.Request, followupGenerationErr error, err *reqError) {
	createFollowupRequest := false

	// some HTTP codes force the request to be converted to a GET request.
	changeHTTPMethodToGet := false

	var locationHeader string
	useLocationHeader := false

	// some Requests give alternative links in the body.
	searchLinksInBody := false

	// https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/Redirections
	switch {
	case 200 <= res.StatusCode && res.StatusCode < 300:
		break
	case res.StatusCode == http.StatusMultipleChoices:
		// have to read the status body
	case res.StatusCode == http.StatusMovedPermanently:
		createFollowupRequest = true
		changeHTTPMethodToGet = true
	case res.StatusCode == http.StatusFound:
		createFollowupRequest = true
		changeHTTPMethodToGet = true
	case res.StatusCode == http.StatusSeeOther:
		changeHTTPMethodToGet = true
		createFollowupRequest = true
	case res.StatusCode == http.StatusNotModified:
		// cached response is still valid
		createFollowupRequest = false
	case res.StatusCode == http.StatusTemporaryRedirect:
		// web site is not available
		useLocationHeader := true
	case res.StatusCode == http.StatusPermanentRedirect:
		// method and body not changed
		// TODO
	default:
		return nil, nil, nil
	}

	// use the same context and options to build the followup, but modify it based on redirect
	followup, followupGenerationErr = buildRequest(ctx, opts)
	if followupGenerationErr != nil {
		return nil, fmt.Errorf("Error when building followup request: %s", err.Error()), nil
	}

	if useLocationHeader {
		locationHeader = res.Header.Get("Location")

		url, urlParseErr := url.Parse(locationHeader)
		if urlParseErr != nil {
			return nil, fmt.Errorf("Error when parsing redirection the url: %s", err.Error()), nil
		}
		followup.URL = url
		followup.Host = url.Host
	}

	if changeHTTPMethodToGet {
		followup.Method = "GET"
	}

}

// Check the body of the response for patterns.
// If a status code / byte sequence / regex is wanted and is not present return an error.
// If they are present, add them to the list of matches.
func searchForPatterns(bodyBytes *capWriter, bodyString string, proto string, status string, opts commandOpts) (matches []string, err *reqError) {
	statusLine := fmt.Sprintf("%s %s", proto, status)

	// matched portions in the page
	if opts.Expect != "" {
		m := expectedStatusCode(opts, status)
		if m == "" {
			return []string{}, &reqError{
				fmt.Sprintf("HTTP CRITICAL - Invalid HTTP response received from host on port %d: %s", opts.Port, statusLine),
				CRITICAL,
			}
		} else {
			matches = append(matches, fmt.Sprintf(`Status line output "%s" matched "%s"`, statusLine, opts.Expect))
		}
	} else {
		matches = append(matches, statusLine)
	}

	if len(opts.expectByte) > 0 {
		if !bytes.Contains(bodyBytes.Bytes(), opts.expectByte) {
			return matches, &reqError{
				fmt.Sprintf(`HTTP CRITICAL - HTTP response body Not matched %q from host on port %d`, string(opts.expectByte), opts.Port),
				CRITICAL,
			}
		} else {
			matches = append(matches, fmt.Sprintf(`Response body matched %q`, string(opts.expectByte)))
		}
	}

	if opts.RegexStr != "" {
		re := regexp.MustCompile(opts.RegexStr)
		if err != nil {
			return matches, &reqError{
				fmt.Sprintf(`Could not build case sensitive regex from option: '%s'`, opts.RegexStr),
				UNKNOWN,
			}
		}
		re_matched := re.FindStringSubmatch(bodyString)
		if len(re_matched) == 0 {
			return matches, &reqError{
				fmt.Sprintf(`HTTP CRITICAL - HTTP response body did not match regex: '%s' from host: %s on port: %d`, opts.RegexStr, string(opts.expectByte), opts.Hostname, opts.Port),
				CRITICAL,
			}
		}
		matches = append(matches, re_matched...)
	}

	if opts.EregexStr != "" {
		// as option add (%?) case insensitive
		re, err := regexp.Compile("(?i)" + opts.EregexStr)
		if err != nil {
			return matches, &reqError{
				fmt.Sprintf(`Could not build case insensitive regex from option: '%s'`, opts.EregexStr),
				UNKNOWN,
			}
		}
		re_matched := re.FindStringSubmatch(bodyString)
		if len(re_matched) == 0 {
			return matches, &reqError{
				fmt.Sprintf(`HTTP CRITICAL - HTTP response body did not match regex: '%s' from host: %s on port: %d`, opts.RegexStr, string(opts.expectByte), opts.Hostname, opts.Port),
				CRITICAL,
			}
		}
		matches = append(matches, re_matched...)
	}

	return matches, nil
}

// Naemon-Like function that returns naemon errors, handles redirections, checks body content
func request(ctx context.Context, client *http.Client, opts commandOpts) (string, *reqError) {
	req, err := buildRequest(ctx, opts)
	if err != nil {
		return "", &reqError{
			fmt.Sprintf("Error in building request: %v", err),
			UNKNOWN,
		}
	}

	meta, err := performHttpRequest(req, client, opts)
	if err != nil {
		return "", &reqError{
			fmt.Sprintf("HTTP UNKNOWN - Error when performing request: %s", err),
			UNKNOWN,
		}
	}

	reqErr := handleErroneusReturnCodes(meta.res)
	if reqErr != nil {
		return "", reqErr
	}

	followup, followupErr, reqErr := generateFollowupRequest(ctx, opts, meta.res, meta.body)
	if followupErr != nil {
		return "", &reqError{
			fmt.Sprintf("HTTP UNKNOWN - Error when generating followup request: %s", followupErr),
			UNKNOWN,
		}
	}
	if reqErr != nil {
		return "", reqErr
	}
	if followup != nil {

	}

	matches, reqErr := searchForPatterns(meta.buffer, meta.body, meta.res.Proto, meta.res.Status, opts)
	if reqErr != nil {
		return "", reqErr
	}

	statusLine := fmt.Sprintf("%s %s", meta.res.Proto, meta.res.Status)
	meta.buffer.Write([]byte(statusLine + "\r\n\r\n"))
	meta.res.Header.Write(meta.buffer)

	okMsg := fmt.Sprintf(`HTTP OK - %s - %d bytes in %.3f second response time | time=%fs;;;0.000000 size=%dB;;;0`, strings.Join(matches, ", "), meta.buffer.Size(), meta.duration.Seconds(), meta.duration.Seconds(), meta.buffer.Size())
	return okMsg, nil
}

// If the HTTP status code is erroneus, return a non-nil err
func handleErroneusReturnCodes(res *http.Response) (err *reqError) {
	if 400 <= res.StatusCode && res.StatusCode < 500 {
		return &reqError{
			fmt.Sprintf("HTTP WARNING - Invalid HTTP response received from host on port %d: %s", opts.Port, statusLine),
			WARNING,
		}
	}
	return nil
}

func Check(ctx context.Context, output io.Writer, osArgs []string) int {
	opts := commandOpts{}
	psr := flags.NewParser(&opts, flags.HelpFlag|flags.PassDoubleDash) // default flags without flags.PrintErrors
	psr.Name = "check_http"
	_, err := psr.ParseArgs(osArgs)
	if err != nil {
		fmt.Fprintf(output, "%s\n", err.Error())

		return UNKNOWN
	}

	if opts.Version {
		printVersion(output)
		return OK
	}

	bufferSize, err := humanize.ParseBytes(opts.MaxBufferSize)
	if err != nil {
		fmt.Fprintf(output, "Could not parse max-buffer-size: %v\n", err)
		return UNKNOWN
	}
	opts.bufferSize = bufferSize

	if opts.WaitFor && opts.WaitForMax == 0 {
		fmt.Fprintf(output, "wait-for-max is required when wait-for is enabled\n")
		return UNKNOWN
	}

	if opts.ExpectContent != "" && opts.Base64ExpectContent != "" {
		fmt.Fprintf(output, "Both string and base64-string are specified\n")
		return UNKNOWN
	}

	if opts.ExpectContent != "" {
		opts.expectByte = []byte(opts.ExpectContent)
	}
	if opts.Base64ExpectContent != "" {
		data, err := base64.StdEncoding.DecodeString(opts.Base64ExpectContent)
		if err != nil {
			fmt.Fprintf(output, "Failed decode base64-string: %v\n", err)
			return UNKNOWN
		}
		opts.expectByte = data
	}

	if opts.TCP4 && opts.TCP6 {
		fmt.Fprintf(output, "Both tcp4 and tcp6 are specified\n")
		return UNKNOWN
	}

	if opts.SNI && opts.Hostname == "" {
		fmt.Fprintf(output, "hostname is required when use sni\n")
		return UNKNOWN
	}

	if opts.Hostname == "" && opts.IPAddress == "" {
		fmt.Fprintf(output, "Specify either hostname or ipaddress\n")
		return UNKNOWN
	}

	if opts.Hostname == "" {
		opts.Hostname = opts.IPAddress
	}

	if opts.IPAddress == "" {
		host, _, err := net.SplitHostPort(opts.Hostname)
		if err != nil {
			opts.IPAddress = opts.Hostname
		} else {
			opts.IPAddress = host
		}
	}

	if opts.Port == 0 {
		_, port, err := net.SplitHostPort(opts.Hostname)
		if err == nil {
			p, _ := strconv.Atoi(port)
			// skip error check OK
			opts.Port = p
		}
	}

	if opts.Port == 0 {
		if opts.SSL {
			opts.Port = 443
		} else {
			opts.Port = 80
		}
	}

	if opts.URI == "" {
		opts.URI = "/"
	}

	transport, err := makeTransport(opts)

	if err != nil {
		fmt.Fprintf(output, "Error in http configuration: %s\n", err.Error())
	}

	client := &http.Client{
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Timeout: opts.Timeout,
	}

	timeout := opts.Timeout + 3*time.Second
	if opts.WaitForMax > 0 {
		timeout = opts.WaitForMax
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	requestNum := 0
	if opts.WaitFor {
		consecutive := opts.Consecutive - 1
		for ctx.Err() == nil {
			requestNum++
			okMsg, reqErr := request(ctx, client, opts)
			interval := opts.Interim
			if reqErr == nil && consecutive <= 0 {
				if opts.Verbose {
					log.Printf("request[%d]: %s", requestNum, okMsg)
				}
				fmt.Fprintf(output, okMsg)
				return OK
			} else if reqErr == nil {
				consecutive--
				if opts.Verbose {
					log.Printf("request[%d]: %s", requestNum, okMsg)
				}
			} else {
				interval = opts.WaitForInterval
				consecutive = opts.Consecutive - 1
				if opts.Verbose {
					log.Printf("request[%d]: %s", requestNum, reqErr.Error())
				}
			}
			select {
			case <-ctx.Done():
			case <-time.After(interval):
			}
		}
		fmt.Fprintf(output, "Give up waiting for success\n")
		return UNKNOWN
	}

	consecutive := opts.Consecutive - 1
	var reqErr *reqError
	for ctx.Err() == nil {
		var okMsg string
		requestNum++
		okMsg, reqErr = request(ctx, client, opts)
		if reqErr == nil && consecutive <= 0 {
			if opts.Verbose {
				log.Printf("request[%d]: %s", requestNum, okMsg)
			}
			fmt.Fprintf(output, okMsg)
			return OK
		} else if reqErr == nil {
			consecutive--
			if opts.Verbose {
				log.Printf("request[%d]: %s", requestNum, okMsg)
			}
		} else {
			break
		}
		select {
		case <-ctx.Done():
		case <-time.After(opts.Interim):
		}
	}
	fmt.Fprintf(output, reqErr.Error())
	return reqErr.Code()
}
