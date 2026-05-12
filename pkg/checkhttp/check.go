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
	"unicode"
	"unicode/utf8"

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

// this struct is big, order fields from big to small and avoid wasting space due to memory packing.
// govet complains otherwise.
type commandOpts struct {
	certificateCritDays *int
	Hostname            string   `short:"H" long:"hostname" description:"Host name using Host headers"`
	IPAddress           string   `short:"I" long:"IP-address" description:"IP address or Host name"`
	Method              string   `short:"j" long:"method" default:"GET" description:"Set HTTP Method"`
	URI                 string   `short:"u" long:"uri" default:"/" description:"URI to request"`
	ExpectStr           string   `short:"e" long:"expect" default:"" description:"Comma-delimited list of expected HTTP response status"`
	Expect              []string // parsed version of ExpectStr
	ExpectContent       string   `short:"s" long:"string" description:"String to expect in the content"`
	Base64ExpectContent string   `long:"base64-string" description:"Base64 Encoded string to expect the content"`
	UserAgent           string   `short:"A" long:"useragent" default:"check_http" description:"UserAgent to be sent"`
	Authorization       string   `short:"a" long:"authorization" description:"username:password on sites with basic authentication"`
	//nolint:lll // Explanations are long
	Certificate string `short:"C" long:"certificate" description:"check certificates instead of content. Specified in mandatory days left to warn and optional days to crit with a comma: warn_days[,<crit_days>]" `
	//nolint:staticcheck,lll // SA5008: multiple "choice" tags are required by our CLI parser. The line is long due to a lot of possible choices.
	TLSMinVersion string `long:"tls-min" description:"minimum supported TLS version. Values with plus set the max tls version as well to latest version: 1.3" choice:"1.0" choice:"1.0+" choice:"1.1" choice:"1.1+" choice:"1.2" choice:"1.2+" choice:"1.3"`
	//nolint:staticcheck // SA5008: multiple "choice" tags are required by our CLI parser
	TLSMaxVersion string `long:"tls-max" description:"maximum supported TLS version" choice:"1.0" choice:"1.1" choice:"1.2" choice:"1.3"`
	Proxy         string `long:"proxy" description:"Proxy that should be used"`
	RegexStr      string `short:"r" long:"regex" description:"Search page for case-sensitive regex string"`
	RegexiStr     string `short:"R" long:"regexi" description:"Search page for case-insensitive regex string"`
	//nolint:staticcheck,lll // SA5008: multiple "choice" tags are required by our CLI parser. The line is long due to a lot of possible choices.
	Onredirect    string `short:"f" long:"onredirect" description:"What strategy to use when encountering a redirect. ok/warning/critical returns immediately. follow uses the new URL returned by golang HTTP client. Sticky keeps the hostname to be same after redirect, and stickyport persists the port as well." choice:"ok" choice:"warning" choice:"critical" choice:"follow" choice:"sticky" choice:"stickyport"`
	MaxBufferSize string `long:"max-buffer-size" default:"1MB" description:"Max buffer size to read response body"`
	TimeoutStr    string `short:"t" long:"timeout" default:"10" description:"Timeout to wait for connection. If no time unit is given at the end, default of seconds is assumed"`
	//nolint:lll // Explanations are long
	WarningThresholdStr string `short:"w" long:"warning" default:"30" description:"If the request+response takes longer specified warning threshold, raises a warning. If no time unit is given at the end, default of seconds is assumed. Value is truncated to milliseconds."`
	//nolint:lll // Explanations are long
	CriticalThresholdStr    string `short:"c" long:"critical" default:"60" description:"If the request+response takes longer specified critical threshold, raises a critical. If no time unit is given at the end, default of seconds is assumed. Value is truncated to milliseconds."`
	expectByte              []byte
	WaitForInterval         time.Duration `long:"wait-for-interval" default:"2s" description:"retry interval"`
	WaitForMax              time.Duration `long:"wait-for-max" description:"time to wait for success"`
	Interim                 time.Duration `long:"interim" default:"1s" description:"interval time after successful request for consecutive mode"`
	TimeoutParsed           time.Duration // parsed version of the timeoutStr after possibly appending time unit seconds
	warningThresholdParsed  time.Duration // parsed version of the warningThreshold after possibly appending time unit seconds
	criticalThresholdParsed time.Duration // parsed version of the warningThreshold after possibly appending time unit seconds
	Consecutive             int           `long:"consecutive" default:"1" description:"number of consecutive successful requests required"`
	Port                    int           `short:"p" long:"port" description:"Port number"`
	certificateWarnDays     int
	MaxRedirects            int `long:"max-redirs" description:"Maximum redirects before giving up on following"`
	bufferSize              uint64
	tlsMaxVersion           uint16
	tlsMinVersion           uint16
	NoDiscard               bool `long:"no-discard" description:"raise error when the response body is larger then max-buffer-size"`
	WaitFor                 bool `long:"wait-for" description:"retry until successful when enabled"`
	SSL                     bool `short:"S" long:"ssl" description:"use https"`
	SNI                     bool `long:"sni" description:"enable SNI"`
	TCP4                    bool `short:"4" description:"use tcp4 only"`
	TCP6                    bool `short:"6" description:"use tcp6 only"`
	Version                 bool `short:"V" long:"version" description:"Show version"`
	Verbose                 bool `short:"v" long:"verbose" description:"Show verbose output"`
	ShowBody                bool `long:"show-body" description:"Print body content below status line"`
	IgnoreCertificateChain  bool `long:"ignore-certificate-chain" description:"by default all certificates are checked in many aspects. Toggle this option to only check the leaf (final) certificate."`
	//nolint:lll // Explanations are long
	DontIgnoreHostCN bool `long:"dont-ignore-host-cn" description:"Certificate subject's Common Name should matches the hostname. Common Name field is now largely unused in modern web, with Subject Alternative Name fields taking their place when present. It is ignored by default, use this flag to enable it."`
	//nolint:lll // Explanations are long
	IgnoreSAN                bool `long:"ignore-san" description:"Skip checking Subject Alternative Names against the hostname. SANs contain the hostnames and IP addresses this certificate is valid for."`
	IgnoreNotAfter           bool `long:"ignore-not-after" description:"Certificates are invalid after the timestamp in their NotAfter has passed. This field can be ignored with this flag."`
	IgnoreNotBefore          bool `long:"ignore-not-before" description:"Certificates are invalid before the timestamp in their NotBefore is reached. This field can be ignored with this flag."`
	IgnoreSignatureAlgorithm bool `long:"ignore-signature-algorithm" description:"Some signature algorithms are deemed insecure, and are deprecated. The algorithm used can be ignored with this flag."`
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
		Timeout:   opts.TimeoutParsed,
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
		parsedURL, err := url.Parse(opts.Proxy)
		if err != nil {
			return nil, fmt.Errorf("Error while parsing Proxy URL. Error was: %s", err.Error())
		}

		proxy = http.ProxyURL(parsedURL)
	}

	return &http.Transport{
		// inherited http.DefaultTransport
		Proxy:                 proxy,
		DialContext:           dialFunc,
		IdleConnTimeout:       defaultIdleConnTimeoutSeconds * time.Second,
		TLSHandshakeTimeout:   opts.TimeoutParsed,
		ExpectContinueTimeout: defaultExpectContinueTimeoutSeconds * time.Second,
		// self-customized values
		ResponseHeaderTimeout: opts.TimeoutParsed,
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

func printVersion(output io.Writer) {
	fmt.Fprintf(output, `%s Compiler: %s %s`,
		version,
		runtime.Compiler,
		runtime.Version())
}

type RequestMetadata struct {
	req            *http.Request
	res            *http.Response
	buffer         *capWriter
	redirectionErr *clientRedirectError
	body           string
	duration       time.Duration
}

func (m *RequestMetadata) String() string {
	if m == nil {
		return "<nil RequestMetadata>"
	}

	var status string
	if m.res != nil {
		status = m.res.Status
	} else {
		status = "(no response)"
	}

	var bodyPreview string
	if len(m.body) > 0 {
		if len(m.body) > 256 {
			bodyPreview = m.body[:256] + "..."
		} else {
			bodyPreview = m.body
		}
	} else {
		bodyPreview = "(empty)"
	}

	return fmt.Sprintf("RequestMetadata{duration: %v, status: %s, body_size: %d, body_preview: %q, redirects: %v}",
		m.duration,
		status,
		m.buffer.Size(),
		bodyPreview,
		m.redirectionErr != nil,
	)
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
	duration := time.Since(start).Truncate(time.Millisecond)

	var redirectionErr *clientRedirectError

	if err != nil {
		if urlErr, ok := errors.AsType[*url.Error](err); ok {
			if clientRedirectErr, ok := errors.AsType[*clientRedirectError](urlErr.Err); ok {
				// this is not really an error, we pack information into this error struct
				// the code acts according to the chosen follow strategy
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
func searchForPatterns(meta *RequestMetadata, opts *commandOpts) (matches []string, err *CheckResult) {
	if opts.Verbose {
		log.Printf("searching for patterns")
	}

	statusLine := fmt.Sprintf("%s %s", meta.req.Proto, meta.res.Status)

	// matched portions in the page
	if len(opts.Expect) > 0 {
		found := false
		for _, exceptedStatusLine := range opts.Expect {
			if strings.Contains(statusLine, exceptedStatusLine) {
				if opts.Verbose {
					log.Printf("response stausLine: %s contains expected status line: %s", statusLine, exceptedStatusLine)
				}
				found = true
				break
			}
		}

		if found {
			matches = append(matches, fmt.Sprintf(`Status line output %q matched %q`, statusLine, opts.ExpectStr))
		} else {
			return []string{}, &CheckResult{
				nil,
				fmt.Sprintf("HTTP CRITICAL: %s - invalid status line, does not contain any options: %v", statusLine, opts.Expect),
				CRITICAL,
			}
		}
	}

	if len(opts.expectByte) > 0 {
		if !bytes.Contains(meta.buffer.Bytes(), opts.expectByte) {
			return matches, &CheckResult{
				nil,
				fmt.Sprintf(`HTTP CRITICAL: %s - response body not matched bytes %v from`, statusLine, opts.expectByte),
				CRITICAL,
			}
		}

		matches = append(matches, fmt.Sprintf(`%s`, string(opts.expectByte)))
	}

	if opts.RegexStr != "" {
		regex, err := regexp.Compile(opts.RegexStr)
		if err != nil {
			return matches, &CheckResult{
				nil,
				fmt.Sprintf(`HTTP UNKNOWN: %s - Could not build case sensitive regex from option: '%s'`, statusLine, opts.RegexStr),
				UNKNOWN,
			}
		}

		regexMatched := regex.FindStringSubmatch(meta.body)
		if len(regexMatched) == 0 {
			return matches, &CheckResult{
				nil,
				fmt.Sprintf(`HTTP CRITICAL: %s - HTTP response body did not match regex: '%s' `, statusLine, opts.RegexStr),
				CRITICAL,
			}
		}

		matches = append(matches, regexMatched...)
	}

	if opts.RegexiStr != "" {
		// as option add (%?) case insensitive
		regex, err := regexp.Compile("(?i)" + opts.RegexiStr)
		if err != nil {
			return matches, &CheckResult{
				nil,
				fmt.Sprintf(`HTTP UNKNOWN: %s - Could not build case insensitive regex from option: '%s'`, statusLine, opts.RegexiStr),
				UNKNOWN,
			}
		}

		regexMatched := regex.FindStringSubmatch(meta.body)
		if len(regexMatched) == 0 {
			return matches, &CheckResult{
				nil,
				fmt.Sprintf(`HTTP CRITICAL: %s - HTTP response body did not match eregex: '%s'`, statusLine, opts.RegexiStr),
				CRITICAL,
			}
		}

		matches = append(matches, regexMatched...)
	}

	return matches, nil
}

// the request+response duration is saved onto the metadata.
// the command line arguments might have specified warning/critical thresholds to check against.
func checkDurationThresholds(meta *RequestMetadata, opts *commandOpts) (err *CheckResult) {
	if opts.Verbose {
		log.Printf("checking duration thresholds")
	}
	statusLine := fmt.Sprintf("%s %s", meta.res.Proto, meta.res.Status)

	if opts.CriticalThresholdStr != "" && opts.criticalThresholdParsed != 0 && meta.duration > opts.criticalThresholdParsed {
		return &CheckResult{
			nil,
			fmt.Sprintf("HTTP CRITICAL - %s - %d bytes in %.3f second response time (took longer than the critical threshold %.3fs) | %s",
				statusLine, meta.buffer.Size(), meta.duration.Seconds(), opts.criticalThresholdParsed.Seconds(), buildPerfdataString(opts, meta)),
			CRITICAL,
		}
	}

	if opts.WarningThresholdStr != "" && opts.warningThresholdParsed != 0 && meta.duration > opts.warningThresholdParsed {
		return &CheckResult{
			nil,
			fmt.Sprintf("HTTP WARNING - %s - %d bytes in %.3f second response time (took longer than the warning threshold %.3fs) | %s",
				statusLine, meta.buffer.Size(), meta.duration.Seconds(), opts.warningThresholdParsed.Seconds(), buildPerfdataString(opts, meta)),
			WARNING,
		}
	}

	return nil
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
		str += "This means that any redirection is a WARNING result."
	case "critical":
		str += "This means that any redirection is a CRITICAL result."
	case "sticky":
		str += "This means that redirections are allowed, but the hostname/IP and the port is forced to stay the same."
	case "stickyport":
		str += "This means that redirections are allowed, but the hostname/IP and the port is forced to stay the same."
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
			nil,
			fmt.Sprintf("HTTP OK: %d - %d bytes in %.3f second response time | %s",
				meta.res.StatusCode, meta.res.ContentLength, meta.duration.Seconds(), buildPerfdataString(opts, meta)),
			OK,
		}, nil
	case "warning":
		return &CheckResult{
			nil,
			fmt.Sprintf("HTTP WARNING: %d - %d bytes in %.3f second response time | %s",
				meta.res.StatusCode, meta.res.ContentLength, meta.duration.Seconds(), buildPerfdataString(opts, meta)),
			WARNING,
		}, nil
	case "critical":
		return &CheckResult{
			nil,
			fmt.Sprintf("HTTP CRITICAL: %d - %d bytes in %.3f second response time | %s",
				meta.res.StatusCode, meta.res.ContentLength, meta.duration.Seconds(), buildPerfdataString(opts, meta)),
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
			nil,
			"HTTP UNKNOWN: Unknown follow strategy: " + err.followOption,
			0,
		}, nil
	}
}

func buildPerfdataString(opts *commandOpts, meta *RequestMetadata) string {
	durationStr := strconv.FormatFloat(meta.duration.Seconds(), 'f', 3, 64)

	var warnThresholdStr string
	if opts.WarningThresholdStr != "" && opts.warningThresholdParsed != 0 {
		warnThresholdStr = strconv.FormatFloat(opts.warningThresholdParsed.Seconds(), 'f', 3, 64)
	}

	var criticalThresholdStr string
	if opts.CriticalThresholdStr != "" && opts.criticalThresholdParsed != 0 {
		criticalThresholdStr = strconv.FormatFloat(opts.criticalThresholdParsed.Seconds(), 'f', 3, 64)
	}

	return fmt.Sprintf(`time=%ss;%s;%s;0; size=%dB;;;0`,
		durationStr,
		warnThresholdStr,
		criticalThresholdStr,
		meta.buffer.Size(),
	)
}

// if this function does not return an error, the redirection can continue
// The arguments req and via are the upcoming request and the requests made already, oldest first.
// This function is used to continue following, or encapsulate the follow strategy in an custom error type.
func clientRedirectHandler(req *http.Request, via []*http.Request, opts *commandOpts) (err error) {
	clientHandlerErr := &clientRedirectError{
		followOption:  opts.Onredirect,
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

	switch opts.Onredirect {
	case "":
		// following is not enabled by default
		clientHandlerErr.stopRedirect = true
	case "follow":
		return nil
	case "ok", "warning", "critical", "sticky", "stickyport":
	default:
		return fmt.Errorf("Unknown/Unsupported follow option: %s", opts.Onredirect)
	}

	return clientHandlerErr
}

// Naemon-Like function that returns naemon errors, handles redirections, checks body content.
func request(ctx context.Context, client *http.Client, opts *commandOpts) (okMsg string, result *CheckResult) {
	req, err := buildRequest(ctx, opts)
	if err != nil {
		return "", &CheckResult{
			nil,
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
				nil,
				"HTTP UNKNOWN - Max redirections reached",
				UNKNOWN,
			}
		}

		meta, err = performHTTPRequest(req, client, opts)
		if err != nil {
			return "", &CheckResult{
				nil,
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
			nil,
			"HTTP UNKNOWN - Error when performing request",
			UNKNOWN,
		}
	}

	if opts.Verbose {
		log.Printf("request metadata: %v", meta)
	}

	var reqErr *CheckResult

	reqErr = checkDurationThresholds(meta, opts)
	if reqErr != nil {
		return "", reqErr
	}

	matches, reqErr := searchForPatterns(meta, opts)
	if reqErr != nil {
		reqErr.msg += " | " + buildPerfdataString(opts, meta)

		return "", reqErr
	}

	matchesOutputStr := ""
	if len(matches) > 0 {
		matchesOutputStr = fmt.Sprintf("Response body matched: [%s] - ", strings.Join(matches, ", "))
	}

	reqErr = handleErroneousReturnCodes(meta.res, opts, meta)
	if reqErr != nil {
		reqErr.msg += " | " + buildPerfdataString(opts, meta)

		return "", reqErr
	}

	statusLine := fmt.Sprintf("%s %s", meta.res.Proto, meta.res.Status)

	_, err = meta.buffer.Write([]byte(statusLine + "\r\n\r\n"))
	if err != nil {
		return "", &CheckResult{
			nil,
			fmt.Sprintf("HTTP UNKNOWN - Error when performing request: %s", err),
			UNKNOWN,
		}
	}

	err = meta.res.Header.Write(meta.buffer)
	if err != nil {
		return "", &CheckResult{
			nil,
			fmt.Sprintf("HTTP UNKNOWN - Error when performing request: %s", err),
			UNKNOWN,
		}
	}

	okMsg = fmt.Sprintf(`HTTP OK: %s - %s %d bytes in %.3fs response time %s`,
		statusLine, matchesOutputStr, meta.buffer.Size(), meta.duration.Seconds(),
		buildPerfdataString(opts, meta),
	)

	return okMsg, nil
}

// If the HTTP status code is erroneus, return a non-nil err.
func handleErroneousReturnCodes(res *http.Response, opts *commandOpts, meta *RequestMetadata) (err *CheckResult) {
	if opts.Verbose {
		log.Printf("checking for erroneus error codes")
	}

	statusLine := fmt.Sprintf("%s %s", meta.res.Proto, meta.res.Status)
	// Between 400 and 500
	if http.StatusBadRequest <= res.StatusCode && res.StatusCode < http.StatusInternalServerError {
		return &CheckResult{
			nil,
			fmt.Sprintf("HTTP WARNING - Invalid HTTP response received from host on port %d: %s", opts.Port, statusLine),
			WARNING,
		}
	}

	// Above 500
	if http.StatusInternalServerError <= res.StatusCode {
		return &CheckResult{
			nil,
			fmt.Sprintf("HTTP CRITICAL - Invalid HTTP response received from host on port %d: %s", opts.Port, statusLine),
			CRITICAL,
		}
	}

	return nil
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

	if opts.ExpectStr != "" {
		opts.Expect = strings.Split(opts.ExpectStr, ",")
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

	timeoutStrLastRune, _ := utf8.DecodeLastRuneInString(opts.TimeoutStr)
	if unicode.IsDigit(timeoutStrLastRune) {
		opts.TimeoutStr += "s"
	}

	var timeoutParseErr error

	opts.TimeoutParsed, timeoutParseErr = time.ParseDuration(opts.TimeoutStr)
	if timeoutParseErr != nil {
		fmt.Fprintf(output, "Error parsing timeoutStr: %q , %s", opts.TimeoutStr, timeoutParseErr.Error())

		return UNKNOWN
	}

	warningThresholdLastRune, _ := utf8.DecodeLastRuneInString(opts.WarningThresholdStr)
	if unicode.IsDigit(warningThresholdLastRune) {
		opts.WarningThresholdStr += "s"
	}

	var warningThresholdParseErr error

	opts.warningThresholdParsed, warningThresholdParseErr = time.ParseDuration(opts.WarningThresholdStr)
	if warningThresholdParseErr != nil {
		fmt.Fprintf(output, "Error parsing warningThresholdStr: %q , %s", opts.WarningThresholdStr, warningThresholdParseErr.Error())

		return UNKNOWN
	}

	opts.warningThresholdParsed = opts.warningThresholdParsed.Truncate(time.Millisecond)

	criticalThresholdLastRune, _ := utf8.DecodeLastRuneInString(opts.CriticalThresholdStr)
	if unicode.IsDigit(criticalThresholdLastRune) {
		opts.CriticalThresholdStr += "s"
	}

	var criticalThresholdParseErr error

	opts.criticalThresholdParsed, criticalThresholdParseErr = time.ParseDuration(opts.CriticalThresholdStr)
	if criticalThresholdParseErr != nil {
		fmt.Fprintf(output, "Error parsing criticalThresholdStr: %q , %s", opts.CriticalThresholdStr, criticalThresholdParseErr.Error())

		return UNKNOWN
	}

	opts.criticalThresholdParsed = opts.criticalThresholdParsed.Truncate(time.Millisecond)

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
				fmt.Fprintf(output, "Certificate expiration date check: critical days cannot be higher than warning days.\n")

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
			// automatically enable SSL, this is the behavior of monitoring-plugins check_http
			// fmt.Fprintf(output, "SSL must be enabled for certificate check\n")
			// return UNKNOWN
			opts.SSL = true
		}

		timeout := opts.TimeoutParsed

		certCtx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()

		certResult := checkCertificate(certCtx, output, &opts, dialFunc, tlsConfig)
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
		Timeout: opts.TimeoutParsed,
	}

	timeout := opts.TimeoutParsed
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
