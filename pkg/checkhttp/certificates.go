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

	leafCert := certs[0]

	// Check that the certificate's CN or SAN matches the hostname (leaf only).
	pushHostnameCheck(leafCert, matchHostname, opts, resultsPQ)

	for idx, cert := range certs {
		shouldCheck := idx == 0 || !opts.IgnoreCertificateChain

		// Expiry check and perfdata.
		expiry := cert.NotAfter
		daysLeft := int(time.Until(expiry).Hours() / hoursInDays)

		if shouldCheck {
			perfParts = append(perfParts, fmt.Sprintf("days_chain_elem%d=%dd;%d;%s;0", idx, daysLeft, opts.certificateWarnDays, critDaysPerfStr))
			pushExpiryCheck(cert, opts, idx, customTimeLayout, resultsPQ)
		} else {
			perfParts = append(perfParts, fmt.Sprintf("days_chain_elem%d=%dd;;;0", idx, daysLeft))
		}

		if shouldCheck {
			// Signature algorithm check.
			pushSignatureCheck(cert, opts, idx, resultsPQ)

			// NotBefore check (certificate not yet valid).
			pushNotBeforeCheck(cert, opts, idx, customTimeLayout, resultsPQ)
		}
	}

	top, ok := heap.Pop(resultsPQ).(*CheckResult)
	if !ok {
		return &CheckResult{
			"HTTP UNKNOWN - Internal error during certificate check: unexpected type in priority queue",
			UNKNOWN,
		}
	}

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

// pushHostnameCheck verifies that the leaf certificate's CN or SAN DNS names
// match the expected hostname (or SNI name). It pushes the result to the PQ.
func pushHostnameCheck(cert *x509.Certificate, hostname string, opts *commandOpts, resultsPQ *CheckResultPQ) {
	err := cert.VerifyHostname(hostname)
	if err != nil {
		heap.Push(resultsPQ, &CheckResult{
			fmt.Sprintf("HTTP CRITICAL - Certificate CN and SAN do not match host name %q for host %q on port %d - (subject: %s)",
				hostname, opts.Hostname, opts.Port, cert.Subject.CommonName),
			CRITICAL,
		})

		return
	}

	heap.Push(resultsPQ, &CheckResult{
		fmt.Sprintf("HTTP OK - Certificate CN or SAN match host name %q for host %q on port %d - (subject: %s)",
			hostname, opts.Hostname, opts.Port, cert.Subject.CommonName),
		OK,
	})
}

// pushExpiryCheck checks the certificate's NotAfter expiry against warning/critical thresholds.
func pushExpiryCheck(cert *x509.Certificate, opts *commandOpts, idx int, timeLayout string, resultsPQ *CheckResultPQ) {
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
			fmt.Sprintf("HTTP CRITICAL - Certificate %q for host %q:%d at chain position %d is not yet valid (valid from %s)",
				formatCertSubject(cert), opts.Hostname, opts.Port, idx, notBefore.Format(timeLayout)),
			CRITICAL,
		})

		return
	}

	heap.Push(resultsPQ, &CheckResult{
		fmt.Sprintf("HTTP OK - Certificate %q for host %q:%d at chain position %d is within its validity period",
			formatCertSubject(cert), opts.Hostname, opts.Port, idx),
		OK,
	})
}
