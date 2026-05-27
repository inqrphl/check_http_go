# check_http

Nagios check_http plugin alternative written in golang,

Modularized and ready to be used in another applicaitons.

Exported function of checkhttp

```golang
func Check(ctx context.Context, output io.Writer, osArgs []string)
```

Implements basic functionality from check_http and check_certificate.

## Usage

```text
Usage:
  check_http [OPTIONS]

Application Options:
  -H, --hostname=                                                 Host name using Host headers
  -I, --IP-address=                                               IP address or Host name
  -j, --method=                                                   Set HTTP Method (default: GET)
  -u, --uri=                                                      URI to request (default: /)
  -e, --expect=                                                   Comma-delimited list of expected HTTP response status. By default, 1XX, 2XX are OK, 3XX depends on
                                                                  --onredirect option, 4XX are WARNING, 5XX are CRITICAL
  -s, --string=                                                   String to expect in the content
      --base64-string=                                            Base64 Encoded string to expect the content
  -A, --useragent=                                                UserAgent to be sent (default: check_http)
  -a, --authorization=                                            username:password on sites with basic authentication
  -C, --certificate=                                              check certificates instead of content. Specified in mandatory days left to warn and optional days
                                                                  to crit with a comma: warn_days[,<crit_days>]
      --tls-min=[1.0|1.0+|1.1|1.1+|1.2|1.2+|1.3]                  minimum supported TLS version. Values with plus set the max tls version as well to latest version:
                                                                  1.3
      --tls-max=[1.0|1.1|1.2|1.3]                                 maximum supported TLS version
      --proxy=                                                    Proxy that should be used
  -r, --regex=                                                    Search page for case-sensitive regex string
  -R, --regexi=                                                   Search page for case-insensitive regex string
  -f, --onredirect=[ok|warning|critical|follow|sticky|stickyport] What strategy to use when encountering a redirect. ok/warning/critical returns immediately. follow
                                                                  uses the new URL returned by golang HTTP client. Sticky keeps the hostname to be same after
                                                                  redirect, and stickyport persists the port as well.
      --max-buffer-size=                                          Max buffer size to read response body (default: 1MB)
  -t, --timeout=                                                  Timeout to wait for connection. If no time unit is given at the end, default of seconds is assumed
                                                                  (default: 10)
  -w, --warning=                                                  If the request+response takes longer specified warning threshold, raises a warning. If no time
                                                                  unit is given at the end, default of seconds is assumed. Value is truncated to milliseconds.
                                                                  (default: 30)
  -c, --critical=                                                 If the request+response takes longer specified critical threshold, raises a critical. If no time
                                                                  unit is given at the end, default of seconds is assumed. Value is truncated to milliseconds.
                                                                  (default: 60)
      --wait-for-interval=                                        retry interval (default: 2s)
      --wait-for-max=                                             time to wait for success
      --interim=                                                  interval time after successful request for consecutive mode (default: 1s)
      --consecutive=                                              number of consecutive successful requests required (default: 1)
  -p, --port=                                                     Port number
      --max-redirs=                                               Maximum redirects before giving up on following
      --no-discard                                                raise error when the response body is larger then max-buffer-size
      --wait-for                                                  retry until successful when enabled
  -S, --ssl                                                       use https
      --sni                                                       enable SNI
  -4                                                              use tcp4 only
  -6                                                              use tcp6 only
  -V, --version                                                   Show version
  -v, --verbose                                                   Show verbose output
      --show-body                                                 Print body content below status line
      --ignore-certificate-chain                                  by default all certificates are checked in many aspects. Toggle this option to only check the leaf
                                                                  (final) certificate.
      --check-cn                                                  Subject Common Name of leaf certificate can be checked to match hostname exactly. Common Name
                                                                  field is now largely unused in modern web, with Subject Alternative Name fields being more
                                                                  prelavent and used instead of Common Name when present. It is not checked by default, use this
                                                                  flag to enable it.
      --check-san                                                 Subject Alternative Names can be checked against the hostname. SANs contain the hostnames and IP
                                                                  addresses this certificate is valid for. They are ignored if the certificate is a Certificate
                                                                  Authority type, meaning they are used to sign other certificates and not for proving secuirty for
                                                                  a hostname. It is not checked by default, use this flag to enable it.
      --ignore-not-after                                          Certificates are invalid after the timestamp in their NotAfter has passed. This field can be
                                                                  ignored with this flag.
      --ignore-not-before                                         Certificates are invalid before the timestamp in their NotBefore is reached. This field can be
                                                                  ignored with this flag.
      --ignore-signature-algorithm                                Some signature algorithms are deemed insecure, and are deprecated. The algorithm used can be
                                                                  ignored with this flag.

Help Options:
  -h, --help                                                      Show this help message
```

## Examples

Check with HEAD request

```bash
% ./check_http -S  -I blog.nomadscafe.jp -H blog.nomadscafe.jp -u /2016/03/retty-tech-cafe-5.html -e 'HTTP/1.0 200,HTTP/1.1 200,HTTP/2.0 200' -j HEAD --sni
HTTP OK - Status line output "HTTP/2.0 200 OK" matched "HTTP/2.0 200"  - 482 bytes in 0.349 second response time | time=0.349428s;;;0.000000 size=482B;;;0
```

Wait for success

```bash
% ./check_http -S -H blog.nomadscafe.jp -s kazeburo-wait-for --wait-for --wait-for-max 10s
2021/03/24 15:44:20 HTTP CRITICAL - HTTP response body Not matched "kazeburo-wait-for" from host on port 443
2021/03/24 15:44:22 HTTP CRITICAL - HTTP response body Not matched "kazeburo-wait-for" from host on port 443
2021/03/24 15:44:24 HTTP CRITICAL - HTTP response body Not matched "kazeburo-wait-for" from host on port 443
2021/03/24 15:44:27 HTTP CRITICAL - HTTP response body Not matched "kazeburo-wait-for" from host on port 443
2021/03/24 15:44:29 HTTP CRITICAL - HTTP response body Not matched "kazeburo-wait-for" from host on port 443
Give up waiting for success
```

Standard Check

```bash
% ./check_http --hostname example.com
HTTP OK - HTTP/1.1 200 OK -  780 bytes in 0.074s response time | time=0.074s;30.000;60.000;0; size=780B;;;0;
```

Check with follow, use -v to see redirects if necessary

```bash
% ./check_http --hostname mail.google.com --onredirect follow --ssl --timeout 1000000s
HTTP OK - HTTP/1.1 200 OK -  926406 bytes in 0.539s response time | time=0.539s;30.000;60.000;0; size=926406B;;;0;
```

Return with a state upon encountering a redirect

```bash
%. ./check_http -v --hostname mail.google.com --onredirect critical --ssl
2026/05/21 16:21:48 request:
GET / HTTP/1.1
Host: mail.google.com
User-Agent: check_http

2026/05/21 16:21:48 response:
HTTP CRITICAL - HTTP/1.1 301 Moved Permanently - -1 bytes in 0.070 second response time | time=0.070s;30.000;60.000;0; size=0B;;;0;
```

SSL certificate check

```bash
%. ./check_http --hostname google.com -v --certificate 10,5 --ssl
subcheck 0
code: 0 | importance: 151 | msg: HTTP OK - x509 certificate '*.google.com' from 'WR2' is valid until Thu 30 Jul 2026 03:51:25 PM UTC +0000 (expires in 70 days)
subcheck 1
code: 0 | importance: 152 | msg: HTTP OK - x509 certificate '*.google.com' from 'WR2' has its validity start time in the past (valid from Thu 07 May 2026 03:51:26 PM UTC +0000)
subcheck 2
code: 0 | importance: 153 | msg: HTTP OK - x509 certificate '*.google.com' from 'WR2' uses strong signature algorithm SHA256-RSA
subcheck 3
code: 0 | importance: 154 | msg: HTTP OK - x509 certificate '*.google.com' from 'WR2' has IP/DNS SANs that match hostname "google.com" - (IP SANs: [], DNS SANs: [*.google.com *.appengine.google.com *.bdn.dev *.origin-test.bdn.dev *.cloud.google.com *.crowdsource.google.com *.datacompute.google.com *.google.ca *.google.cl *.google.co.in *.google.co.jp *.google.co.uk *.google.com.ar *.google.com.au *.google.com.br *.google.com.co *.google.com.mx *.google.com.tr *.google.com.vn *.google.de *.google.es *.google.fr *.google.hu *.google.it *.google.nl *.google.pl *.google.pt *.gemini.cloud.google.com *.gstatic.com *.metric.gstatic.com *.gvt1.com *.gcpcdn.gvt1.com *.gvt2.com *.gcp.gvt2.com *.url.google.com *.youtube-nocookie.com *.ytimg.com ai.android android.com *.android.com *.flash.android.com g.co *.g.co goo.gl www.goo.gl google-analytics.com *.google-analytics.com google.com googlecommerce.com *.googlecommerce.com urchin.com *.urchin.com youtu.be youtube.com *.youtube.com music.youtube.com *.music.youtube.com youtubeeducation.com *.youtubeeducation.com youtubekids.com *.youtubekids.com yt.be *.yt.be android.clients.google.com *.aistudio.google.com])
subcheck 4
code: 0 | importance: 251 | msg: HTTP OK - x509 certificate 'WR2' from 'GTS Root R1' is valid until Tue 20 Feb 2029 02:00:00 PM UTC +0000 (expires in 1005 days)
subcheck 5
code: 0 | importance: 252 | msg: HTTP OK - x509 certificate 'WR2' from 'GTS Root R1' has its validity start time in the past (valid from Wed 13 Dec 2023 09:00:00 AM UTC +0000)
subcheck 6
code: 0 | importance: 253 | msg: HTTP OK - x509 certificate 'WR2' from 'GTS Root R1' uses strong signature algorithm SHA256-RSA
subcheck 7
code: 0 | importance: 254 | msg: HTTP OK - x509 certificate 'WR2' from 'GTS Root R1' is a CA certificate, skipping SAN check for hostname "google.com" - (IP SANs: [], DNS SANs: [])
subcheck 8
code: 0 | importance: 351 | msg: HTTP OK - x509 certificate 'GTS Root R1' from 'GlobalSign Root CA' is valid until Fri 28 Jan 2028 12:00:42 AM UTC +0000 (expires in 616 days)
subcheck 9
code: 0 | importance: 352 | msg: HTTP OK - x509 certificate 'GTS Root R1' from 'GlobalSign Root CA' has its validity start time in the past (valid from Fri 19 Jun 2020 12:00:42 AM UTC +0000)
subcheck 10
code: 0 | importance: 353 | msg: HTTP OK - x509 certificate 'GTS Root R1' from 'GlobalSign Root CA' uses strong signature algorithm SHA256-RSA
subcheck 11
code: 0 | importance: 354 | msg: HTTP OK - x509 certificate 'GTS Root R1' from 'GlobalSign Root CA' is a CA certificate, skipping SAN check for hostname "google.com" - (IP SANs: [], DNS SANs: [])
HTTP OK - x509 certificate '*.google.com' from 'WR2' is valid until Thu 30 Jul 2026 03:51:25 PM UTC +0000 (expires in 70 days) | days_chain_elem1=70d;10;5;0 days_chain_elem2=1005d;10;5;0 days_chain_elem3=616d;10;5;0
```

SSL certificate check, perform certificate Common Name check.

```bash
% ./check_http --hostname google.com --certificate 10,5 --ssl --dont-ignore-host-cn
HTTP CRITICAL - x509 certificate '*.google.com' from 'WR2' has common name "*.google.com", which does not match hostname "google.com" | days_chain_elem1=70d;10;5;0 days_chain_elem2=1005d;10;5;0 days_chain_elem3=616d;10;5;0
```

More examples can be found within tests.
