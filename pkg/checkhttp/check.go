package checkhttp

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
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
	Certificate         string        `short:"C" long:"certificate" description:"check certificates instead of content. Specified in days left to warn and optionally crit: <warn_days>[,<crit_days>]" `
	certificateWarnDays int           // parsed version of certificateWarnDay
	certificateCritDays *int          // parsed version of certificateCritDay. This is optional and may not be specified.
	SSL                 bool          `short:"S" long:"ssl" description:"use https"`
	SNI                 bool          `long:"sni" description:"enable SNI"`
	TLSMinVersion       string        `long:"tls-min" description:"minimum supported TLS version. Values with plus set the max tls version as well to latest version: 1.3" choice:"1.0" choice:"1.0+" choice:"1.1" choice:"1.1+" choice:"1.2" choice:"1.2+" choice:"1.3"`
	tlsMinVersion       uint16        // parsed version of tlsMinVersion from crypto/tls
	TLSMaxVersion       string        `long:"tls-max" description:"maximum supported TLS version" choice:"1.0" choice:"1.1" choice:"1.2" choice:"1.3"`
	tlsMaxVersion       uint16        // parsed version of tlsMinVersion from crypto/tls
	TCP4                bool          `short:"4" description:"use tcp4 only"`
	TCP6                bool          `short:"6" description:"use tcp6 only"`
	Version             bool          `short:"V" long:"version" description:"Show version"`
	Verbose             bool          `short:"v" long:"verbose" description:"Show verbose output"`
	Proxy               string        `long:"proxy" description:"Proxy that should be used"`
	RegexStr            string        `long:"regex" description:"Search page for case-sensitive regex string"`
	EregexStr           string        `long:"eregex" description:"Search page for case-insensitive regex string"`
	ShowBody            bool          `long:"show-body" description:"Print body content bellow status line"`
	Follow              string        `long:"follow" description:"Redirection method" choice:"ok" choice:"warning" choice:"critical" choice:"follow" choice:"sticky" choice:"stickyport"`
	MaxRedirects        int           `long:"max-redirs" description:"Maximum redirects before giving up on following"`
	bufferSize          uint64
	expectByte          []byte
}

func makeTlsConfig(opts commandOpts) (conf *tls.Config) {
	conf = &tls.Config{
		InsecureSkipVerify: true,
	}
	if opts.SNI {
		host, _, err := net.SplitHostPort(opts.Hostname)
		if err != nil {
			host = opts.Hostname
		}
		conf.ServerName = host
	}

	if opts.tlsMinVersion != 0 {
		conf.MinVersion = opts.tlsMinVersion
	}

	if opts.tlsMaxVersion != 0 {
		conf.MaxVersion = opts.tlsMaxVersion
	}

	return conf
}

// net.Dialer is for creating a TCP connection
func makeDialer(opts commandOpts) func(ctx context.Context, _ string, _ string) (net.Conn, error) {
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

	return dialFunc
}

func makeTransport(opts commandOpts) (http.RoundTripper, error) {

	dialFunc := makeDialer(opts)

	tlsConfig := makeTlsConfig(opts)

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

type CheckResult struct {
	msg  string
	code int
}

func (e *CheckResult) Error() string {
	return e.msg
}

func (e *CheckResult) Code() int {
	return e.code
}

type RequestMetadata struct {
	req      *http.Request
	res      *http.Response
	duration time.Duration
	buffer   *capWriter
	body     string
	// redirection error from custom handler
	redirectionErr *clientRedirectError
}

// Helper function to extract everything from *http.Request
func performHttpRequest(req *http.Request, client *http.Client, opts commandOpts) (metadata *RequestMetadata, err error) {
	if opts.Verbose {
		reqDump, _ := httputil.DumpRequest(req, true)
		log.Printf("request:\n%s", reqDump)
	}

	start := time.Now()
	res, err := client.Do(req)
	duration := time.Since(start)

	var redirectionErr *clientRedirectError
	if err != nil {
		if urlErr, ok := errors.AsType[*url.Error](err); ok {
			if clientRedirectErr, ok := errors.AsType[*clientRedirectError](urlErr.Err); ok {
				// this is not really an error, we pack information into this error struct
				// the code acts according to the chosen follow strategy
				log.Printf("Found a clientRedirectError")
				redirectionErr = clientRedirectErr
			} else {
				return nil, fmt.Errorf("error during request: %w", err)
			}
		} else {
			return nil, fmt.Errorf("error during request: %w", err)
		}
	}

	if opts.Verbose {
		resDump, _ := httputil.DumpResponse(res, true)
		log.Printf("response:\n%s", resDump)
	}

	var buffer *capWriter = &capWriter{
		Cap:       opts.bufferSize,
		NoDiscard: opts.NoDiscard,
	}
	var body string
	if redirectionErr == nil && res != nil && res.Body != nil {
		writtenByteCount, ioCopyErr := io.Copy(buffer, res.Body)
		defer res.Body.Close()

		if ioCopyErr != nil {
			return nil, fmt.Errorf("Error when copying request body buffer: %s , written bytes: %d", ioCopyErr.Error(), writtenByteCount)
		}

		body = string(buffer.Bytes())
	}

	// the returned err might be of type clientRedirectError
	return &RequestMetadata{
		req,
		res,
		duration,
		buffer,
		body,
		redirectionErr,
	}, nil

}

// Check the body of the response for patterns.
// If a status code / byte sequence / regex is wanted and is not present return an error.
// If they are present, add them to the list of matches.
func searchForPatterns(bodyBytes *capWriter, bodyString string, proto string, status string, opts commandOpts) (matches []string, err *CheckResult) {
	statusLine := fmt.Sprintf("%s %s", proto, status)

	// matched portions in the page
	if opts.Expect != "" {
		m := expectedStatusCode(opts, status)
		if m == "" {
			return []string{}, &CheckResult{
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
			return matches, &CheckResult{
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
			return matches, &CheckResult{
				fmt.Sprintf(`Could not build case sensitive regex from option: '%s'`, opts.RegexStr),
				UNKNOWN,
			}
		}
		re_matched := re.FindStringSubmatch(bodyString)
		if len(re_matched) == 0 {
			return matches, &CheckResult{
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
			return matches, &CheckResult{
				fmt.Sprintf(`Could not build case insensitive regex from option: '%s'`, opts.EregexStr),
				UNKNOWN,
			}
		}
		re_matched := re.FindStringSubmatch(bodyString)
		if len(re_matched) == 0 {
			return matches, &CheckResult{
				fmt.Sprintf(`HTTP CRITICAL - HTTP response body did not match regex: '%s' from host: %s on port: %d`, opts.RegexStr, string(opts.expectByte), opts.Hostname, opts.Port),
				CRITICAL,
			}
		}
		matches = append(matches, re_matched...)
	}

	return matches, nil
}

type clientRedirectError struct {
	followOption string
	originalHost string
	originalPort int
	// if this is not nil it is the final result of the check
	// it can be returned immediately
	checkResult *CheckResult
	// stop the redirection. if this is catched, the current page should be check
	stopRedirect bool
	// next redirection
	redirectedReq *http.Request
}

func (e *clientRedirectError) Error() string {
	str := fmt.Sprintf("clientRedirectHandlerError, this value encapsulates the follow command line option: '%s' .", e.followOption)
	switch {
	case e.followOption == "":
		str += "Follow option is not specified. This means following is not allowed."
	case e.followOption == "follow":
		str += "This uses the default behavior of go standard http package for redirections."
	case e.followOption == "ok":
		str += "This means that any redirection is an OK result."
	case e.followOption == "warning":
		str += "This means that any redirection is an WARNING result."
	case e.followOption == "critical":
		str += "This means that any redirection is an CRITICAL result."
	case e.followOption == "sticky":
		str += "This means that redirections are allowed, but the hostanme/IP and the port is forced to stay the same."
	case e.followOption == "stickyport":
		str += "This means that redirections are allowed, but the hostanme/IP and the port is forced to stay the same."
	}
	return str
}

func clientRedirectErrorHandler(err clientRedirectError, meta *RequestMetadata, opts commandOpts) (checkResult *CheckResult, nextReq *http.Request) {
	switch {
	case err.followOption == "":
		return nil, nil
	case err.followOption == "follow":
		log.Panicf("This option should have returned nil and continued redirection in redirection handler.")
		return nil, nil
	// HTTP OK: 302 Found - 215 bytes in 0.045 second response time |time=0.045s size=215B
	case err.followOption == "ok":
		return &CheckResult{
			fmt.Sprintf("HTTP OK: %d - %d bytes in %.3f second response time | time=%.3f size=%dB", meta.res.StatusCode, meta.res.ContentLength, meta.duration.Seconds(), meta.duration.Seconds(), meta.res.ContentLength),
			0,
		}, nil
	case err.followOption == "warning":
		return &CheckResult{
			fmt.Sprintf("HTTP WARNING: %d - %d bytes in %.3f second response time | time=%.3f size=%dB", meta.res.StatusCode, meta.res.ContentLength, meta.duration.Seconds(), meta.duration.Seconds(), meta.res.ContentLength),
			0,
		}, nil
	case err.followOption == "critical":
		return &CheckResult{
			fmt.Sprintf("HTTP CRITICAL: %d - %d bytes in %.3f second response time | time=%.3f size=%dB", meta.res.StatusCode, meta.res.ContentLength, meta.duration.Seconds(), meta.duration.Seconds(), meta.res.ContentLength),
			0,
		}, nil
	case err.followOption == "sticky", err.followOption == "stickyport":
		nextReq = err.redirectedReq

		// http.Request ignores req.URL.Host is set

		var origHost, origPortStr string
		_, _, splitErr := net.SplitHostPort(err.originalHost)
		if splitErr == nil {
			origHost, origPortStr, _ = net.SplitHostPort(err.originalHost)
			if origPortStr == "" {
				// fallback to opts.Port logic
				if opts.SSL {
					origPortStr = "443"
				} else {
					origPortStr = "80"
				}
			}

			if err.followOption == "sticky" {
				// sticky: keep original host, follow redirect port
				nextReq.URL.Host = net.JoinHostPort(origHost, nextReq.URL.Port())
			} else if err.followOption == "stickyport" {
				// stickyport: keep both host and port
				nextReq.URL.Host = net.JoinHostPort(origHost, origPortStr)
			}

		}

		nextReq.Host = nextReq.URL.Hostname()

		return nil, nextReq
	default:
		return &CheckResult{
			fmt.Sprintf("HTTP UNKNOWN: Unknown follow strategy: %s", err.followOption),
			0,
		}, nil
	}
}

// if this function does not return an error, the redirection can continue
// The arguments req and via are the upcoming request and the requests made already, oldest first.
// This function is used to continue following, or encapsulate the follow strategy in an custom error type
func clientRedirectHandler(req *http.Request, via []*http.Request, opts commandOpts) (err error) {
	clientHandlerErr := &clientRedirectError{
		followOption:  opts.Follow,
		redirectedReq: req,
	}
	if len(via) > 0 {
		clientHandlerErr.originalHost = via[0].URL.Host
		if clientHandlerErr.originalHost == "" {
			clientHandlerErr.originalHost = via[0].Host
		}
	} else {
		clientHandlerErr.originalHost = req.URL.Host // fallback
	}
	clientHandlerErr.originalPort = opts.Port

	switch {
	case opts.Follow == "":
		// following is not enabled by default
		clientHandlerErr.stopRedirect = true
	case opts.Follow == "follow":
		return nil
	case opts.Follow == "ok",
		opts.Follow == "warning",
		opts.Follow == "critical",
		opts.Follow == "sticky",
		opts.Follow == "stickyport":
	default:
		return fmt.Errorf("Unknown/Unsupported follow option: %s", opts.Follow)
	}

	return clientHandlerErr
}

// Naemon-Like function that returns naemon errors, handles redirections, checks body content
func request(ctx context.Context, client *http.Client, opts commandOpts) (okMsg string, result *CheckResult) {

	req, err := buildRequest(ctx, opts)
	if err != nil {
		return "", &CheckResult{
			fmt.Sprintf("Error in building request: %v", err),
			UNKNOWN,
		}
	}

	var meta *RequestMetadata
	var nextReq *http.Request
	// first request is not a redirection , second is the first redirection
	redirectionCount := -1
	for req != nil {
		if redirectionCount > opts.MaxRedirects {
			return "", &CheckResult{
				"HTTP UNKNOWN - Max redirections reached",
				UNKNOWN,
			}
		}

		meta, err = performHttpRequest(req, client, opts)
		if err != nil {
			return "", &CheckResult{
				fmt.Sprintf("HTTP UNKNOWN - Error when performing request: %s", err),
				UNKNOWN,
			}
		}
		if meta.redirectionErr != nil {
			result, nextReq = clientRedirectErrorHandler(*meta.redirectionErr, meta, opts)
		}
		req = nextReq
		redirectionCount++
	}

	// redirection might have given us a check result
	// we should return this immediately
	if result != nil {
		return "", result
	}

	// sanity check
	if meta == nil {
		return "", &CheckResult{
			"HTTP UNKNOWN - Error when performing request",
			UNKNOWN,
		}
	}

	reqErr := handleErroneusReturnCodes(meta.res, opts, meta.res.Proto, meta.res.Status)
	if reqErr != nil {
		return "", reqErr
	}

	matches, reqErr := searchForPatterns(meta.buffer, meta.body, meta.res.Proto, meta.res.Status, opts)
	if reqErr != nil {
		return "", reqErr
	}

	statusLine := fmt.Sprintf("%s %s", meta.res.Proto, meta.res.Status)
	meta.buffer.Write([]byte(statusLine + "\r\n\r\n"))
	meta.res.Header.Write(meta.buffer)

	okMsg = fmt.Sprintf(`HTTP OK - %s - %d bytes in %.3f second response time | time=%fs;;;0.000000 size=%dB;;;0`, strings.Join(matches, ", "), meta.buffer.Size(), meta.duration.Seconds(), meta.duration.Seconds(), meta.buffer.Size())
	return okMsg, nil
}

// If the HTTP status code is erroneus, return a non-nil err
func handleErroneusReturnCodes(res *http.Response, opts commandOpts, proto string, status string) (err *CheckResult) {
	statusLine := fmt.Sprintf("%s %s", proto, status)
	if 400 <= res.StatusCode && res.StatusCode < 500 {
		return &CheckResult{
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

	if opts.MaxRedirects == 0 {
		opts.MaxRedirects = 15
	}

	switch opts.TLSMinVersion {
	// argument parser only accepts these values as valid
	case "1.0":
		opts.tlsMinVersion = tls.VersionTLS10
	case "1.0+":
		opts.tlsMinVersion = tls.VersionTLS10
		opts.tlsMaxVersion = tls.VersionTLS13
	case "1.1":
		opts.tlsMinVersion = tls.VersionTLS11
	case "1.1+":
		opts.tlsMinVersion = tls.VersionTLS11
		opts.tlsMaxVersion = tls.VersionTLS13
	case "1.2":
		opts.tlsMinVersion = tls.VersionTLS12
	case "1.2+":
		opts.tlsMinVersion = tls.VersionTLS12
		opts.tlsMaxVersion = tls.VersionTLS13
	case "1.3":
		opts.tlsMinVersion = tls.VersionTLS13
	}

	switch opts.TLSMaxVersion {
	// argument parser only accepts these values as valid
	case "1.0":
		opts.tlsMaxVersion = tls.VersionTLS10
	case "1.1":
		opts.tlsMaxVersion = tls.VersionTLS11
	case "1.2":
		opts.tlsMaxVersion = tls.VersionTLS12
	case "1.3":
		opts.tlsMaxVersion = tls.VersionTLS13
	}

	if opts.tlsMinVersion > opts.tlsMaxVersion {
		fmt.Fprintf(output, "TLS min version value is higher than TLS max version value, check your arguments.\n")
		return UNKNOWN
	}

	if opts.Certificate != "" {
		splits := strings.SplitN(opts.Certificate, ",", 2)

		parseDays := func(str string) (int, error) {
			var i int64
			var err error
			if str == "" {
				return 0, nil
			}
			i, err = strconv.ParseInt(str, 10, 32)
			if err != nil {
				return 0, err
			}
			if i < 0 {
				return 0, fmt.Errorf("days remaining cannot be a negative value")
			}
			return int(i), nil
		}

		warnDays, err := parseDays(splits[0])
		if err != nil {
			fmt.Fprintf(output, "Certificate check warning days could not be parsed: %s.\n", err.Error())
			return UNKNOWN
		}
		opts.certificateWarnDays = warnDays

		if len(splits) == 2 {
			critDays, err := parseDays(splits[1])
			if err != nil {
				fmt.Fprintf(output, "Certificate check critical days could not be parsed: %s.\n", err.Error())
				return UNKNOWN
			}

			if critDays > warnDays {
				fmt.Fprintf(output, "Certificate check critical days is higher than warning days. That is illogical, higher tier alert critical may be raised before lower tier altert warning.\n")
				return UNKNOWN
			}

			opts.certificateCritDays = &critDays
		}
	}

	transport, err := makeTransport(opts)

	if err != nil {
		fmt.Fprintf(output, "Error in http configuration: %s\n", err.Error())
	}

	client := &http.Client{
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return clientRedirectHandler(req, via, opts)
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
	var reqErr *CheckResult
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
