package checkhttp

import (
	"container/heap"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

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
	// use a dedicated function to check the chain, the logic is too long

	return checkCertificateChain(opts, certs)
}

// The main inspiration is from https://github.com/matteocorti/check_ssl_cert.
// That project has many options, this function implements only a subset of them.
func checkCertificateChain(opts *commandOpts, certs []*x509.Certificate) *CheckResult {
	// OK - Certificate 'se1-mon-q001.sys.schwarz' will expire on Sat 27 May 2028 04:55:09 PM GMT +0000 (expires in X days)
	const customTimeLayout = "Mon 02 Jan 2006 03:04:05 PM MST -0700"

	resultsPQ := &CheckResultPQ{}
	heap.Init(resultsPQ)

	var perfParts []string

	critDaysPerfStr := ""
	if opts.certificateCritDays != nil {
		critDaysPerfStr = strconv.Itoa(*opts.certificateCritDays)
	}

	// Determine the hostname to match against the certificate's CN and SANs.
	// When SNI is enabled the TLS ServerName is already set in the tls.Config,
	// but we derive it from opts.Hostname here to match consistently.
	matchHostname := opts.Hostname

	host, _, splitErr := net.SplitHostPort(opts.Hostname)
	if opts.SNI && splitErr == nil {
		matchHostname = host
	}

	for idx, cert := range certs {
		shouldCheck := idx == 0 || !opts.IgnoreCertificateChain
		// the output of the check_ssl_cert tool indexes from 1
		perfIndex := idx + 1

		// Expiry check and perfdata.
		expiry := cert.NotAfter
		daysLeft := int(time.Until(expiry).Hours() / hoursInDays)

		if shouldCheck {
			perfParts = append(perfParts, fmt.Sprintf("days_chain_elem%d=%dd;%d;%s;0", perfIndex, daysLeft, opts.certificateWarnDays, critDaysPerfStr))

			// The flag is false by default, it has to be manually toggled
			if opts.DontIgnoreHostCN {
				pushCNCehck(cert, matchHostname, opts, resultsPQ)
			}

			if !opts.IgnoreSAN {
				pushSANCheck(cert, matchHostname, idx, opts, resultsPQ)
			}

			if !opts.IgnoreNotBefore {
				pushNotBeforeCheck(cert, opts, idx, customTimeLayout, resultsPQ)
			}

			if !opts.IgnoreNotAfter {
				pushNotAfterCheck(cert, opts, idx, customTimeLayout, resultsPQ)
			}

			if !opts.IgnoreSignatureAlgorithm {
				// Signature algorithm check.
				pushSignatureCheck(cert, opts, idx, resultsPQ)
			}
		} else {
			perfParts = append(perfParts, fmt.Sprintf("days_chain_elem%d=%dd;;;0", perfIndex, daysLeft))
		}
	}

	subchecks := []*CheckResult{}
	for resultsPQ.Len() > 0 {
		top, ok := heap.Pop(resultsPQ).(*CheckResult)
		if !ok {
			break
		}
		subchecks = append(subchecks, top)
	}

	if opts.Verbose {
		for idx, subcheck := range subchecks {
			fmt.Printf("subcheck %d\ncode: %d | msg: %s\n", idx, subcheck.code, subcheck.msg)
		}
	}

	if len(subchecks) == 0 {
		return &CheckResult{
			"HTTP UNKNOWN - Internal error during certificate check: unexpected type in priority queue",
			UNKNOWN,
		}
	}

	top := subchecks[0]

	perfData := strings.Join(perfParts, " ")
	if perfData != "" {
		top.msg += " | " + perfData
	}

	return top
}

// formatCertSubject returns a formatted string with the certificate subject details.
func formatCertSubject(cert *x509.Certificate) string {
	return fmt.Sprintf("(subject: %s, issuer: %s)", cert.Subject.CommonName, cert.Issuer.CommonName)
}

// Taken from:  /usr/local/go/src/crypto/x509/verify.go as it was not exported.
// Useful for checking CommonName
// validHostname reports whether host is a valid hostname that can be matched or
// matched against according to RFC 6125 2.2, with some leniency to accommodate
// legacy values.
func validHostname(host string, isPattern bool) bool {
	if !isPattern {
		host = strings.TrimSuffix(host, ".")
	}
	if len(host) == 0 {
		return false
	}
	if host == "*" {
		// Bare wildcards are not allowed, they are not valid DNS names,
		// nor are they allowed per RFC 6125.
		return false
	}

	for i, part := range strings.Split(host, ".") {
		if part == "" {
			// Empty label.
			return false
		}
		if isPattern && i == 0 && part == "*" {
			// Only allow full left-most wildcards, as those are the only ones
			// we match, and matching literal '*' characters is probably never
			// the expected behavior.
			continue
		}
		for j, c := range part {
			if 'a' <= c && c <= 'z' {
				continue
			}
			if '0' <= c && c <= '9' {
				continue
			}
			if 'A' <= c && c <= 'Z' {
				continue
			}
			if c == '-' && j != 0 {
				continue
			}
			if c == '_' {
				// Not a valid character in hostnames, but commonly
				// found in deployments outside the WebPKI.
				continue
			}
			return false
		}
	}

	return true
}

// taken from: /usr/local/go/src/crypto/x509/verify.go as it was not exported
// Useful for checking CommonName
func matchHostnames(pattern, host string) bool {
	pattern = toLowerCaseASCII(pattern)
	host = toLowerCaseASCII(strings.TrimSuffix(host, "."))

	if len(pattern) == 0 || len(host) == 0 {
		return false
	}

	patternParts := strings.Split(pattern, ".")
	hostParts := strings.Split(host, ".")

	if len(patternParts) != len(hostParts) {
		return false
	}

	for i, patternPart := range patternParts {
		if i == 0 && patternPart == "*" {
			continue
		}
		if patternPart != hostParts[i] {
			return false
		}
	}

	return true
}

// taken from: /usr/local/go/src/crypto/x509/verify.go as it was not exported
// toLowerCaseASCII returns a lower-case version of in. See RFC 6125 6.4.1. We use
// an explicitly ASCII function to avoid any sharp corners resulting from
// performing Unicode operations on DNS labels.
func toLowerCaseASCII(in string) string {
	// If the string is already lower-case then there's nothing to do.
	isAlreadyLowerCase := true
	for _, c := range in {
		if c == utf8.RuneError {
			// If we get a UTF-8 error then there might be
			// upper-case ASCII bytes in the invalid sequence.
			isAlreadyLowerCase = false
			break
		}
		if 'A' <= c && c <= 'Z' {
			isAlreadyLowerCase = false
			break
		}
	}

	if isAlreadyLowerCase {
		return in
	}

	out := []byte(in)
	for i, c := range out {
		if 'A' <= c && c <= 'Z' {
			out[i] += 'a' - 'A'
		}
	}
	return string(out)
}

func pushCNCehck(cert *x509.Certificate, hostname string, opts *commandOpts, resultsPQ *CheckResultPQ) {
	cn_is_valid := validHostname(cert.Subject.CommonName, false) || validHostname(hostname, true)
	if !cn_is_valid {
		heap.Push(resultsPQ, &CheckResult{
			fmt.Sprintf("HTTP CRITICAL - Certificate Common Name %q is not a valid DNS name/pattern for host %q on port %d",
				cert.Subject.CommonName, hostname, opts.Port),
			CRITICAL,
		})
	}

	cn_same_as_hostname := matchHostnames(cert.Subject.CommonName, hostname)
	if !cn_same_as_hostname {
		heap.Push(resultsPQ, &CheckResult{
			fmt.Sprintf("HTTP CRITICAL - Certificate Common Name %q does not match the host %q on port %d",
				cert.Subject.CommonName, hostname, opts.Port),
			CRITICAL,
		})
	}

	heap.Push(resultsPQ, &CheckResult{
		fmt.Sprintf("HTTP OK - Certificate CN match host name %q for host %q on port %d",
			hostname, opts.Hostname, opts.Port),
		OK,
	})
}

// pushSANCheck verifies that the leaf certificate's IP or DNS SAN names
// match the expected hostname (or SNI name). It pushes the result to the PQ.
func pushSANCheck(cert *x509.Certificate, hostname string, index int, opts *commandOpts, resultsPQ *CheckResultPQ) {
	// if the certificate is an CA or Root cert, no need to check its SANs

	if cert.IsCA {
		heap.Push(resultsPQ, &CheckResult{
			fmt.Sprintf("HTTP OK - Certificate %q at chain position %d is a CA cert, no need to check its IP/DNS SAN for host name %q on port %d - (IP SANs: %v, DNS SANs: %v)",
				formatCertSubject(cert), index, hostname, opts.Port, cert.IPAddresses, cert.DNSNames),
			OK,
		})
		return
	}

	// verifyHostname ignores legacy CommonName field
	// it checks using x509.Certificate.IPAdresses (IP SANs)
	// or  x509.Certificate.DnsNames (Hostname SANs)
	err := cert.VerifyHostname(hostname)
	if err != nil {
		heap.Push(resultsPQ, &CheckResult{
			fmt.Sprintf("HTTP CRITICAL - Certificate %q at chain position %d has IP/DNS SANs that do not match host name %q for host %q on port %d - (IP SANs: %v, DNS SANs: %v)",
				formatCertSubject(cert), index, hostname, opts.Hostname, opts.Port, cert.IPAddresses, cert.DNSNames),
			CRITICAL,
		})

		return
	}

	heap.Push(resultsPQ, &CheckResult{
		fmt.Sprintf("HTTP OK - Certificate %q at chain position %d has IP/DNS SANs match host name %q for host %q on port %d - (IP SANs: %v, DNS SANs: %v)",
			formatCertSubject(cert), index, hostname, opts.Hostname, opts.Port, cert.IPAddresses, cert.DNSNames),
		OK,
	})
}

// pushNotAfterCheck checks the certificate's NotAfter expiry against warning/critical thresholds.
func pushNotAfterCheck(cert *x509.Certificate, opts *commandOpts, idx int, timeLayout string, resultsPQ *CheckResultPQ) {
	expiry := cert.NotAfter
	daysLeft := int(time.Until(expiry).Hours() / hoursInDays)

	switch {
	case opts.certificateCritDays != nil && daysLeft <= *opts.certificateCritDays:
		heap.Push(resultsPQ, &CheckResult{
			fmt.Sprintf("HTTP CRITICAL - Certificate %q for host %q:%d at chain position %d will expire on %s - (expires in %d days)",
				formatCertSubject(cert), opts.Hostname, opts.Port, idx, expiry.Format(timeLayout), daysLeft),
			CRITICAL,
		})
	case daysLeft <= opts.certificateWarnDays:
		heap.Push(resultsPQ, &CheckResult{
			fmt.Sprintf("HTTP WARNING - Certificate %q for host %q:%d at chain position %d will expire on %s - (expires in %d days)",
				formatCertSubject(cert), opts.Hostname, opts.Port, idx, expiry.Format(timeLayout), daysLeft),
			WARNING,
		})
	default:
		heap.Push(resultsPQ, &CheckResult{
			fmt.Sprintf("HTTP OK - Certificate %q for host %q:%d at chain position %d will expire on %s - (expires in %d days)",
				formatCertSubject(cert), opts.Hostname, opts.Port, idx, expiry.Format(timeLayout), daysLeft),
			OK,
		})
	}
}

// pushSignatureCheck validates that the certificate is not signed using a weak algorithm.
func pushSignatureCheck(cert *x509.Certificate, opts *commandOpts, idx int, resultsPQ *CheckResultPQ) {
	sigAlgo := cert.SignatureAlgorithm.String()

	switch cert.SignatureAlgorithm {
	case x509.MD2WithRSA, x509.MD5WithRSA:
		heap.Push(resultsPQ, &CheckResult{
			fmt.Sprintf("HTTP CRITICAL - Certificate %q for host %q:%d at chain position %d uses weak signature algorithm %s",
				formatCertSubject(cert), opts.Hostname, opts.Port, idx, sigAlgo),
			CRITICAL,
		})
	case x509.SHA1WithRSA:
		heap.Push(resultsPQ, &CheckResult{
			fmt.Sprintf("HTTP WARNING - Certificate %q for host %q:%d at chain position %d uses deprecated SHA1 signature algorithm %s",
				formatCertSubject(cert), opts.Hostname, opts.Port, idx, sigAlgo),
			WARNING,
		})
	default:
		heap.Push(resultsPQ, &CheckResult{
			fmt.Sprintf("HTTP OK - Certificate %q for host %q:%d at chain position %d uses signature algorithm %s",
				formatCertSubject(cert), opts.Hostname, opts.Port, idx, sigAlgo),
			OK,
		})
	}
}

// pushNotBeforeCheck verifies the certificate is not used before its validity period begins.
func pushNotBeforeCheck(cert *x509.Certificate, opts *commandOpts, idx int, timeLayout string, resultsPQ *CheckResultPQ) {
	notBefore := cert.NotBefore
	if time.Now().Before(notBefore) {
		heap.Push(resultsPQ, &CheckResult{
			fmt.Sprintf("HTTP CRITICAL - Certificate %q for host %q:%d at chain position %d is before its validity start time (valid from %s)",
				formatCertSubject(cert), opts.Hostname, opts.Port, idx, notBefore.Format(timeLayout)),
			CRITICAL,
		})

		return
	}

	heap.Push(resultsPQ, &CheckResult{
		fmt.Sprintf("HTTP OK - Certificate %q for host %q:%d at chain position %d is beyond its validity start time",
			formatCertSubject(cert), opts.Hostname, opts.Port, idx),
		OK,
	})
}
