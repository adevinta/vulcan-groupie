# Vulcan Groupie

A service to group Vulcan vulnerabilities making them easier to process for the end users. It can be used as a package or as a CLI.

It gets the vulnerabilities detected by Vulcan Core and given a set of static rules, it groups them. The grouping is performed at two levels:
1. If a vulnerability affects more than one target, it's reported only once. For every vulnerability there is an `AffectedTargets` field.
2. Vulnerabilities of the same kind are grouped inside the same group. For example, there is a group for the different HTTP Headers configuration issues.

### Installation

```bash
go get -v github.com/adevinta/vulcan-groupie/...
```

### Running

```bash
$ vulcan-groupie group
Error: accepts 1 arg(s), received 0
Usage:
  vulcan-groupie group <scan_id> [flags]

Flags:
  -h, --help            help for group
  -m, --min-print int   minimum Severity Rank of the vulnerabilities to be printed (default 1)
  -s, --save            save the updated model

$ vulcan-groupie group a05ee450-e09b-40cf-a648-b477cafc3cf1
2018/03/21 14:33:05 Getting checks from persistence api...
2018/03/21 14:33:05 Getting reports from results api...
2018/03/21 14:33:05 Sending 101 checks to channel...
2018/03/21 14:33:08 100
#####################
Javascript Libraries Vulnerabilities
Upgrade to the latest version of the reported Javascript libraries
	2 || parseHTML() executes scripts in event handlers in jquery 2.2.4.min || vulcan-retirejs || [site.example.com]
	2 || 3rd party CORS request may execute in jquery 2.2.4.min || vulcan-retirejs || [site.example.com]
#####################
Misconfigured HTTP Headers
Fine tune your HTTP Headers to get stronger security
	1 || HTTP X-XSS-Protection Not Implemented || vulcan-http-headers || [site2.example.com site.example.com]
	1 || HTTP Redirect Misconfiguration || vulcan-http-headers || [site2.example.com site3.example.com site5.example.com site.example.com]
	1 || HTTP X-Content-Type-Options Not Implemented || vulcan-http-headers || [site2.example.com site.example.com]
	1 || HTTP Cookies Misconfiguration || vulcan-http-headers || [site4.example.com site5.example.com site.example.com]
	1 || HTTP Content Security Policy Not Implemented || vulcan-http-headers || [site2.example.com site3.example.com site.example.com]
	1 || HTTP Subresource Integrity Misconfiguration || vulcan-http-headers || [site.example.com]
	1 || HTTP X-Frame-Options Not Implemented || vulcan-http-headers || [site4.example.com site2.example.com site3.example.com site5.example.com site.example.com]
	1 || HTTP Strict Transport Security Not Implemented || vulcan-http-headers || [site4.example.com site2.example.com site3.example.com site5.example.com site.example.com]
	2 || Cross-Origin Resource Sharing Implemented with Universal Access || vulcan-http-headers || [site.example.com]
#####################
Default group
Check the vulnerabilities
#####################
Misconfigured SSL
Check your SSL configuration to avoid potential security issues
	2 || Weak SSL/TLS Protocol Versions || vulcan-tls || [site2.example.com site.example.com site4.example.com site5.example.com site3.example.com]
	2 || Weak SSL/TLS Ciphersuites || vulcan-tls || [site2.example.com site.example.com site4.example.com site5.example.com site3.example.com]
#####################
Configuration May Allow Email Spoofing Attacks
Configure the mitigations available to minimise the risk for email spoofing attacks
	1 || DMARC Tag 'p' Set To 'quarantine' || vulcan-dmarc || [site.example.com site2.example.com]
	1 || SPF 'all' Mechanism Configured As 'SOFTFAIL' || vulcan-spf || [site.example.com site2.example.com]
	2 || DKIM Record Not Found For Selector default || vulcan-dkim || [site.example.com site2.example.com]
```

The current output are the different groups for the scan given, separated by `#####################`.

For every group the information printed is:
- The `Summary` of the Group
- The `Recommendation` of the Group
- The list of `Vulnerabilities` of the group. For each of them:
  - The `Severity` of the Vulnerability
  - The `Summary` of the Vulnerability
  - The `Checktype` that found the Vulnerability
  - The `Assets` affected by the Vulnerability
