package checkhttp

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
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
	//nolint:varnamelen // it is simply short
	OK = 0
)

const (
	defaultKeepAliveSeconds       = 30
	defaultIdleConnTimeoutSeconds = 30
	defaultExpectContinueTimeoutSeconds
	hoursInDays = 24
)

// this struct is big, order fields from big to small and avoid wasting space due to memory packing
// govet complains otherwise
type commandOpts struct {
	certificateCritDays *int
	Hostname            string `short:"H" long:"hostname" description:"Host name using Host headers"`
	IPAddress           string `short:"I" long:"IP-address" description:"IP address or Host name"`
	Method              string `short:"j" long:"method" default:"GET" description:"Set HTTP Method"`
	URI                 string `short:"u" long:"uri" default:"/" description:"URI to request"`
	Expect              string `short:"e" long:"expect" default:"" description:"Comma-delimited list of expected HTTP response status"`
	ExpectContent       string `short:"s" long:"string" description:"String to expect in the content"`
	Base64ExpectContent string `long:"base64-string" description:"Base64 Encoded string to expect the content"`
	UserAgent           string `short:"A" long:"useragent" default:"check_http" description:"UserAgent to be sent"`
	Authorization       string `short:"a" long:"authorization" description:"username:password on sites with basic authentication"`
	Certificate         string `short:"C" long:"certificate" description:"check certificates instead of content. Specified in days left to warn and optionally crit: <warn_days>[,<crit_days>]" `
	//nolint:staticcheck,lll // SA5008: multiple "choice" tags are required by our CLI parser. The line is long due to a lot of possible choices.
	TLSMinVersion string `long:"tls-min" description:"minimum supported TLS version. Values with plus set the max tls version as well to latest version: 1.3" choice:"1.0" choice:"1.0+" choice:"1.1" choice:"1.1+" choice:"1.2" choice:"1.2+" choice:"1.3"`
	//nolint:staticcheck // SA5008: multiple "choice" tags are required by our CLI parser
	TLSMaxVersion string `long:"tls-max" description:"maximum supported TLS version" choice:"1.0" choice:"1.1" choice:"1.2" choice:"1.3"`
	Proxy         string `long:"proxy" description:"Proxy that should be used"`
	RegexStr      string `long:"regex" description:"Search page for case-sensitive regex string"`
	EregexStr     string `long:"eregex" description:"Search page for case-insensitive regex string"`
	//nolint:staticcheck // SA5008: multiple "choice" tags are required by our CLI parser
	Follow              string `long:"follow" description:"Redirection method" choice:"ok" choice:"warning" choice:"critical" choice:"follow" choice:"sticky" choice:"stickyport"`
	MaxBufferSize       string `long:"max-buffer-size" default:"1MB" description:"Max buffer size to read response body"`
	expectByte          []byte
	WaitForInterval     time.Duration `long:"wait-for-interval" default:"2s" description:"retry interval"`
	WaitForMax          time.Duration `long:"wait-for-max" description:"time to wait for success"`
	Consecutive         int           `long:"consecutive" default:"1" description:"number of consecutive successful requests required"`
	Port                int           `short:"p" long:"port" description:"Port number"`
	certificateWarnDays int
	MaxRedirects        int           `long:"max-redirs" description:"Maximum redirects before giving up on following"`
	Interim             time.Duration `long:"interim" default:"1s" description:"interval time after successful request for consecutive mode"`
	bufferSize          uint64
	Timeout             time.Duration `short:"t" long:"timeout" default:"10s" description:"Timeout to wait for connection"`
	tlsMaxVersion       uint16
	tlsMinVersion       uint16
	NoDiscard           bool `long:"no-discard" description:"raise error when the response body is larger then max-buffer-size"`
	WaitFor             bool `long:"wait-for" description:"retry until successful when enabled"`
	SSL                 bool `short:"S" long:"ssl" description:"use https"`
	SNI                 bool `long:"sni" description:"enable SNI"`
	TCP4                bool `short:"4" description:"use tcp4 only"`
	TCP6                bool `short:"6" description:"use tcp6 only"`
	Version             bool `short:"V" long:"version" description:"Show version"`
	Verbose             bool `short:"v" long:"verbose" description:"Show verbose output"`
	ShowBody            bool `long:"show-body" description:"Print body content bellow status line"`
}

func makeTLSConfig(opts *commandOpts) (conf *tls.Config) {
	//nolint:gosec // TLS check is deliberately skipped, certificate checks are done in its separate function
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

// net.Dialer is for creating a TCP connection.
func makeDialer(opts *commandOpts) func(ctx context.Context, _ string, _ string) (net.Conn, error) {
	baseDialFunc := (&net.Dialer{
		Timeout:   opts.Timeout,
		KeepAlive: defaultKeepAliveSeconds * time.Second,
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
		addr := net.JoinHostPort(opts.IPAddress, strconv.Itoa(opts.Port))

		return baseDialFunc(ctx, tcpMode, addr)
	}

	return dialFunc
}

//nolint:ireturn // it has to return an interface, http package is built that way
func makeTransport(opts *commandOpts, dialFunc func(ctx context.Context, _ string, _ string) (net.Conn, error), tlsConfig *tls.Config) (http.RoundTripper, error) {
	proxy := http.ProxyFromEnvironment

	if opts.Proxy != "" {
		urll, err := url.Parse(opts.Proxy)
		if err != nil {
			return nil, fmt.Errorf("Error while parsing Proxy URL. Error was: %s", err.Error())
		}

		proxy = http.ProxyURL(urll)
	}

	return &http.Transport{
		// inherited http.DefaultTransport
		Proxy:                 proxy,
		DialContext:           dialFunc,
		IdleConnTimeout:       defaultIdleConnTimeoutSeconds * time.Second,
		TLSHandshakeTimeout:   opts.Timeout,
		ExpectContinueTimeout: defaultExpectContinueTimeoutSeconds * time.Second,
		// self-customized values
		ResponseHeaderTimeout: opts.Timeout,
		TLSClientConfig:       tlsConfig,
		ForceAttemptHTTP2:     true,
	}, nil
}

func buildRequest(ctx context.Context, opts *commandOpts) (*http.Request, error) {
	schema := "http"
	if opts.SSL {
		schema = "https"
	}

	uri := fmt.Sprintf("%s://%s%s", schema, opts.Hostname, opts.URI)

	var buffer bytes.Buffer

	req, err := http.NewRequestWithContext(
		ctx,
		opts.Method,
		uri,
		&buffer,
	)
	if err != nil {
		return nil, err
	}

	if opts.Authorization != "" {
		a := strings.SplitN(opts.Authorization, ":", 2)
		if len(a) != 2 {
			return nil, errors.New("invalid authorization args")
		}

		req.SetBasicAuth(a[0], a[1])
	}

	req.Header.Set("User-Agent", opts.UserAgent)

	return req, nil
}

func expectedStatusCode(opts *commandOpts, status string) string {
	expects := strings.SplitSeq(opts.Expect, ",")
	for e := range expects {
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
	buffer    []byte
	Cap       uint64
	size      uint64
	NoDiscard bool
}

func (w *capWriter) Write(data []byte) (int, error) {
	w.size += uint64(len(data))
	if w.size > w.Cap && w.NoDiscard {
		return 0, errors.New("could not write body buffer. buffer is full")
	}

	if w.size > w.Cap {
		q := w.Cap - uint64(len(w.buffer))
		if q != 0 {
			w.buffer = append(w.buffer, data[0:q-1]...)
		}
	} else {
		w.buffer = append(w.buffer, data...)
	}

	return len(data), nil
}

func (w *capWriter) Size() uint64 {
	return w.size
}

func (w *capWriter) Bytes() []byte {
	return w.buffer
}

//nolint:errname // The original author used it as an error type extensively
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
	req            *http.Request
	res            *http.Response
	buffer         *capWriter
	redirectionErr *clientRedirectError
	body           string
	duration       time.Duration
}

// Helper function to extract everything from *http.Request.
func performHTTPRequest(req *http.Request, client *http.Client, opts *commandOpts) (metadata *RequestMetadata, err error) {
	if opts.Verbose {
		reqDump, _ := httputil.DumpRequest(req, true)
		//nolint:gosec // G706: Logging the request (which might leak secrets) is wanted by design in verbose mode
		log.Printf("request:\n%s", reqDump)
	}

	start := time.Now()
	//nolint:gosec // G704: Server side request forgery is flagged because req is built from CLI args. This is what the tool wants.
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
		//nolint:gosec // G706: Logging the response (which might leak secrets) is wanted by design in verbose mode
		log.Printf("response:\n%s", resDump)
	}

	var (
		buffer = &capWriter{Cap: opts.bufferSize, NoDiscard: opts.NoDiscard}
		body   string
	)

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
		buffer,
		redirectionErr,
		body,
		duration,
	}, nil
}

// Check the body of the response for patterns.
// If a status code / byte sequence / regex is wanted and is not present return an error.
// If they are present, add them to the list of matches.
func searchForPatterns(bodyBytes *capWriter, bodyString, proto, status string, opts *commandOpts) (matches []string, err *CheckResult) {
	statusLine := fmt.Sprintf("%s %s", proto, status)

	// matched portions in the page
	if opts.Expect != "" {
		m := expectedStatusCode(opts, status)
		if m == "" {
			return []string{}, &CheckResult{
				fmt.Sprintf("HTTP CRITICAL - Invalid HTTP response received from host on port %d: %s", opts.Port, statusLine),
				CRITICAL,
			}
		}

		matches = append(matches, fmt.Sprintf(`Status line output %q matched %q`, statusLine, opts.Expect))
	} else {
		matches = append(matches, statusLine)
	}

	if len(opts.expectByte) > 0 {
		if !bytes.Contains(bodyBytes.Bytes(), opts.expectByte) {
			return matches, &CheckResult{
				fmt.Sprintf(`HTTP CRITICAL - HTTP response body Not matched %q from host on port %d`, string(opts.expectByte), opts.Port),
				CRITICAL,
			}
		}

		matches = append(matches, fmt.Sprintf(`Response body matched %q`, string(opts.expectByte)))
	}

	if opts.RegexStr != "" {
		regex, err := regexp.Compile(opts.RegexStr)
		if err != nil {
			return matches, &CheckResult{
				fmt.Sprintf(`Could not build case sensitive regex from option: '%s'`, opts.RegexStr),
				UNKNOWN,
			}
		}

		regexMatched := regex.FindStringSubmatch(bodyString)
		if len(regexMatched) == 0 {
			return matches, &CheckResult{
				fmt.Sprintf(`HTTP CRITICAL - HTTP response body did not match regex: '%s' from host: %s on port: %d`, opts.RegexStr, opts.Hostname, opts.Port),
				CRITICAL,
			}
		}

		matches = append(matches, regexMatched...)
	}

	if opts.EregexStr != "" {
		// as option add (%?) case insensitive
		regex, err := regexp.Compile("(?i)" + opts.EregexStr)
		if err != nil {
			return matches, &CheckResult{
				fmt.Sprintf(`Could not build case insensitive regex from option: '%s'`, opts.EregexStr),
				UNKNOWN,
			}
		}

		regexMatched := regex.FindStringSubmatch(bodyString)
		if len(regexMatched) == 0 {
			return matches, &CheckResult{
				fmt.Sprintf(`HTTP CRITICAL - HTTP response body did not match eregex: '%s' from host: %s on port: %d`, opts.EregexStr, opts.Hostname, opts.Port),
				CRITICAL,
			}
		}

		matches = append(matches, regexMatched...)
	}

	return matches, nil
}

type clientRedirectError struct {
	redirectedReq *http.Request
	followOption  string
	originalHost  string
	originalPort  int
	stopRedirect  bool
}

func (e *clientRedirectError) Error() string {
	str := fmt.Sprintf("clientRedirectHandlerError, this value encapsulates the follow command line option: '%s' .", e.followOption)

	switch e.followOption {
	case "":
		str += "Follow option is not specified. This means following is not allowed."
	case "follow":
		str += "This uses the default behavior of go standard http package for redirections."
	case "ok":
		str += "This means that any redirection is an OK result."
	case "warning":
		str += "This means that any redirection is an WARNING result."
	case "critical":
		str += "This means that any redirection is an CRITICAL result."
	case "sticky":
		str += "This means that redirections are allowed, but the hostanme/IP and the port is forced to stay the same."
	case "stickyport":
		str += "This means that redirections are allowed, but the hostanme/IP and the port is forced to stay the same."
	}

	return str
}

func clientRedirectErrorHandler(err clientRedirectError, meta *RequestMetadata, opts *commandOpts) (checkResult *CheckResult, nextReq *http.Request) {
	switch err.followOption {
	case "":
		return nil, nil
	case "follow":
		log.Panicf("This option should have returned nil and continued redirection in redirection handler.")

		return nil, nil
	// HTTP OK: 302 Found - 215 bytes in 0.045 second response time |time=0.045s size=215B
	case "ok":
		return &CheckResult{
			fmt.Sprintf("HTTP OK: %d - %d bytes in %.3f second response time | time=%.3f size=%dB",
				meta.res.StatusCode, meta.res.ContentLength, meta.duration.Seconds(), meta.duration.Seconds(), meta.res.ContentLength),
			OK,
		}, nil
	case "warning":
		return &CheckResult{
			fmt.Sprintf("HTTP WARNING: %d - %d bytes in %.3f second response time | time=%.3f size=%dB",
				meta.res.StatusCode, meta.res.ContentLength, meta.duration.Seconds(), meta.duration.Seconds(), meta.res.ContentLength),
			WARNING,
		}, nil
	case "critical":
		return &CheckResult{
			fmt.Sprintf("HTTP CRITICAL: %d - %d bytes in %.3f second response time | time=%.3f size=%dB",
				meta.res.StatusCode, meta.res.ContentLength, meta.duration.Seconds(), meta.duration.Seconds(), meta.res.ContentLength),
			CRITICAL,
		}, nil
	case "sticky", "stickyport":
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

			switch err.followOption {
			case "sticky":
				// sticky: keep original host, follow redirect port
				nextReq.URL.Host = net.JoinHostPort(origHost, nextReq.URL.Port())
			case "stickyport":
				// stickyport: keep both host and port
				nextReq.URL.Host = net.JoinHostPort(origHost, origPortStr)
			}
		}

		nextReq.Host = nextReq.URL.Hostname()

		return nil, nextReq
	default:
		return &CheckResult{
			"HTTP UNKNOWN: Unknown follow strategy: " + err.followOption,
			0,
		}, nil
	}
}

// if this function does not return an error, the redirection can continue
// The arguments req and via are the upcoming request and the requests made already, oldest first.
// This function is used to continue following, or encapsulate the follow strategy in an custom error type.
func clientRedirectHandler(req *http.Request, via []*http.Request, opts *commandOpts) (err error) {
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

	switch opts.Follow {
	case "":
		// following is not enabled by default
		clientHandlerErr.stopRedirect = true
	case "follow":
		return nil
	case "ok", "warning", "critical", "sticky", "stickyport":
	default:
		return fmt.Errorf("Unknown/Unsupported follow option: %s", opts.Follow)
	}

	return clientHandlerErr
}

// Naemon-Like function that returns naemon errors, handles redirections, checks body content.
func request(ctx context.Context, client *http.Client, opts *commandOpts) (okMsg string, result *CheckResult) {
	req, err := buildRequest(ctx, opts)
	if err != nil {
		return "", &CheckResult{
			fmt.Sprintf("Error in building request: %v", err),
			UNKNOWN,
		}
	}

	var (
		meta    *RequestMetadata
		nextReq *http.Request
	)
	// first request is not a redirection , second is the first redirection
	redirectionCount := -1
	for req != nil {
		if redirectionCount > opts.MaxRedirects {
			return "", &CheckResult{
				"HTTP UNKNOWN - Max redirections reached",
				UNKNOWN,
			}
		}

		meta, err = performHTTPRequest(req, client, opts)
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

	_, err = meta.buffer.Write([]byte(statusLine + "\r\n\r\n"))
	if err != nil {
		return "", &CheckResult{
			fmt.Sprintf("HTTP UNKNOWN - Error when performing request: %s", err),
			UNKNOWN,
		}
	}

	err = meta.res.Header.Write(meta.buffer)
	if err != nil {
		return "", &CheckResult{
			fmt.Sprintf("HTTP UNKNOWN - Error when performing request: %s", err),
			UNKNOWN,
		}
	}

	okMsg = fmt.Sprintf(`HTTP OK - %s - %d bytes in %.3f second response time | time=%fs;;;0.000000 size=%dB;;;0`,
		strings.Join(matches, ", "), meta.buffer.Size(), meta.duration.Seconds(), meta.duration.Seconds(), meta.buffer.Size())

	return okMsg, nil
}

// If the HTTP status code is erroneus, return a non-nil err.
func handleErroneusReturnCodes(res *http.Response, opts *commandOpts, proto, status string) (err *CheckResult) {
	statusLine := fmt.Sprintf("%s %s", proto, status)
	// Between 400 and 500
	if http.StatusBadRequest <= res.StatusCode && res.StatusCode < http.StatusInternalServerError {
		return &CheckResult{
			fmt.Sprintf("HTTP WARNING - Invalid HTTP response received from host on port %d: %s", opts.Port, statusLine),
			WARNING,
		}
	}

	// Above 500
	if http.StatusInternalServerError <= res.StatusCode {
		return &CheckResult{
			fmt.Sprintf("HTTP CRITICAL - Invalid HTTP response received from host on port %d: %s", opts.Port, statusLine),
			CRITICAL,
		}
	}

	return nil
}

// checkCertificate establishes a TLS connection to the server and validates the certificate
// against the warning and critical thresholds. It returns immediately without checking the HTTP content.
func checkCertificate(ctx context.Context, opts *commandOpts, dialFunc func(ctx context.Context, _ string, _ string) (net.Conn, error), tlsConfig *tls.Config) *CheckResult {
	// For certificate checking, we need to set ServerName for SNI
	if tlsConfig.ServerName == "" {
		host, _, err := net.SplitHostPort(opts.Hostname)
		if err != nil {
			host = opts.Hostname
		}

		tlsConfig.ServerName = host
	}

	conn, err := dialFunc(ctx, "", "")
	if err != nil {
		return &CheckResult{
			fmt.Sprintf("HTTP CRITICAL - Error connecting to host %s on port %d: %v", opts.IPAddress, opts.Port, err),
			CRITICAL,
		}
	}
	defer conn.Close()

	tlsConn := tls.Client(conn, tlsConfig)

	handshakeErr := tlsConn.HandshakeContext(ctx)
	if handshakeErr != nil {
		return &CheckResult{
			fmt.Sprintf("HTTP CRITICAL - TLS handshake failed for host %s on port %d: %v", opts.IPAddress, opts.Port, handshakeErr),
			CRITICAL,
		}
	}

	certs := tlsConn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return &CheckResult{
			fmt.Sprintf("HTTP CRITICAL - No certificate returned from host %s on port %d", opts.IPAddress, opts.Port),
			CRITICAL,
		}
	}

	// certs[0] is the leaf certificate, the certificate belonging to the site that we are visitng
	// certs[1..n-1] are the intermediate certificates sign each other and go up in scope
	// certs[n] is the root certificate. this is either from the web browser / system
	cert := certs[0]

	expiry := cert.NotAfter
	daysLeft := int(time.Until(expiry).Hours() / hoursInDays)

	critDaysPerfStr := ""
	if opts.certificateCritDays != nil {
		critDaysPerfStr = strconv.Itoa(*opts.certificateCritDays)
	}

	var perfParts []string

	for i, c := range certs {
		chainDaysLeft := int(time.Until(c.NotAfter).Hours() / hoursInDays)
		if i == 0 {
			perfParts = append(perfParts, fmt.Sprintf("expire=%dd;%d;%s;0", chainDaysLeft, opts.certificateWarnDays, critDaysPerfStr))
		} else {
			perfParts = append(perfParts, fmt.Sprintf("expire_chain_%d=%dd;;;0", i, chainDaysLeft))
		}
	}

	perfData := strings.Join(perfParts, " ")

	// formatCertSubject returns a formatted string with the certificate subject details
	formatCertSubject := func(cert *x509.Certificate) string {
		return fmt.Sprintf(" (subject: %s, issuer: %s)", cert.Subject.CommonName, cert.Issuer.CommonName)
	}

	var result *CheckResult

	switch {
	case opts.certificateCritDays != nil && daysLeft <= *opts.certificateCritDays:
		result = &CheckResult{
			fmt.Sprintf("HTTP CRITICAL - Certificate expiration for host %s on port %d: %s - %d days left%s | %s",
				opts.Hostname, opts.Port, expiry.Format(time.RFC3339), daysLeft,
				formatCertSubject(cert), perfData),
			CRITICAL,
		}
	case daysLeft <= opts.certificateWarnDays:
		result = &CheckResult{
			fmt.Sprintf("HTTP WARNING - Certificate expiration for host %s on port %d: %s - %d days left%s | %s",
				opts.Hostname, opts.Port, expiry.Format(time.RFC3339), daysLeft,
				formatCertSubject(cert), perfData),
			WARNING,
		}
	default:
		result = &CheckResult{
			fmt.Sprintf("HTTP OK - Certificate expiration for host %s on port %d: %s - %d days left%s | %s",
				opts.Hostname, opts.Port, expiry.Format(time.RFC3339), daysLeft,
				formatCertSubject(cert), perfData),
			OK,
		}
	}

	return result
}

//nolint:gocognit,cyclo,funlen,maintidx //the main function has a lot of argument parsing
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
		data, decodeErr := base64.StdEncoding.DecodeString(opts.Base64ExpectContent)
		if decodeErr != nil {
			fmt.Fprintf(output, "Failed decode base64-string: %v\n", decodeErr)

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
		host, _, splitErr := net.SplitHostPort(opts.Hostname)
		if splitErr != nil {
			opts.IPAddress = opts.Hostname
		} else {
			opts.IPAddress = host
		}
	}

	if opts.Port == 0 {
		_, port, splitErr := net.SplitHostPort(opts.Hostname)
		if splitErr == nil {
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

	if opts.tlsMinVersion != 0 && opts.tlsMaxVersion != 0 && opts.tlsMinVersion > opts.tlsMaxVersion {
		fmt.Fprintf(output, "TLS min version value is higher than TLS max version value, check your arguments.\n")

		return UNKNOWN
	}

	if opts.Certificate != "" {
		splits := strings.SplitN(opts.Certificate, ",", 2)

		parseDays := func(str string) (int, error) {
			var (
				parsedInt int64
				parseErr  error
			)

			if str == "" {
				return 0, nil
			}

			parsedInt, parseErr = strconv.ParseInt(str, 10, 32)
			if parseErr != nil {
				return 0, parseErr
			}

			if parsedInt < 0 {
				return 0, errors.New("days remaining cannot be a negative value")
			}

			return int(parsedInt), nil
		}

		warnDays, parseWarnErr := parseDays(splits[0])
		if parseWarnErr != nil {
			fmt.Fprintf(output, "Certificate check warning days could not be parsed: %s.\n", parseWarnErr.Error())

			return UNKNOWN
		}

		opts.certificateWarnDays = warnDays

		if len(splits) == 2 {
			critDays, parseCritErr := parseDays(splits[1])
			if parseCritErr != nil {
				fmt.Fprintf(output, "Certificate check critical days could not be parsed: %s.\n", parseCritErr.Error())

				return UNKNOWN
			}

			if critDays > warnDays {
				fmt.Fprintf(output, "Certificate check critical days is higher than warning days. That is illogical, higher tier alert critical may be raised before lower tier altert warning.\n")

				return UNKNOWN
			}

			opts.certificateCritDays = &critDays
		}
	}

	// Build shared TLS config and dialer
	tlsConfig := makeTLSConfig(&opts)
	dialFunc := makeDialer(&opts)

	// If certificate check is enabled, perform certificate validation and return
	if opts.Certificate != "" {
		if !opts.SSL {
			fmt.Fprintf(output, "SSL must be enabled for certificate check\n")

			return UNKNOWN
		}

		timeout := opts.Timeout

		certCtx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()

		certResult := checkCertificate(certCtx, &opts, dialFunc, tlsConfig)
		fmt.Fprintf(output, "%s\n", certResult.Error())

		return certResult.Code()
	}

	transport, err := makeTransport(&opts, dialFunc, tlsConfig)
	if err != nil {
		fmt.Fprintf(output, "Error in http configuration: %s\n", err.Error())

		return UNKNOWN
	}

	client := &http.Client{
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return clientRedirectHandler(req, via, &opts)
		},
		Timeout: opts.Timeout,
	}

	timeout := opts.Timeout
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
			okMsg, reqErr := request(ctx, client, &opts)

			interval := opts.Interim

			switch {
			case reqErr == nil && consecutive <= 0:
				if opts.Verbose {
					log.Printf("request[%d]: %s", requestNum, okMsg)
				}

				fmt.Fprint(output, okMsg)

				return OK
			case reqErr == nil:
				consecutive--

				if opts.Verbose {
					log.Printf("request[%d]: %s", requestNum, okMsg)
				}
			default:
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

		fmt.Fprint(output, "Give up waiting for success\n")

		return UNKNOWN
	}

	consecutive := opts.Consecutive - 1

	var reqErr *CheckResult

requestLoop:
	for ctx.Err() == nil {
		var okMsg string

		requestNum++

		okMsg, reqErr = request(ctx, client, &opts)
		switch {
		case reqErr == nil && consecutive <= 0:
			if opts.Verbose {
				log.Printf("request[%d]: %s", requestNum, okMsg)
			}

			fmt.Fprint(output, okMsg)

			return OK
		case reqErr == nil:
			consecutive--

			if opts.Verbose {
				log.Printf("request[%d]: %s", requestNum, okMsg)
			}
		default:
			break requestLoop
		}

		select {
		case <-ctx.Done():
		case <-time.After(opts.Interim):
		}
	}

	fmt.Fprint(output, reqErr.Error())

	return reqErr.Code()
}
