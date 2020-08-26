package groupie

import (
	"fmt"
	"sort"

	"github.com/adevinta/vulcan-groupie/pkg/models"
)

var (
	// groups are definied using the map from below, where the key is the name
	// of the group, and the value are groups.
	groups = map[string]models.Group{
		"php": models.Group{
			Summary:         "Vulnerabilities in PHP",
			Recommendations: []string{"Update PHP to the latest version"},
		},
		"wordpress": models.Group{
			Summary:         "Vulnerabilities in WordPress",
			Recommendations: []string{"Update WordPress to the lastest version"},
		},
		"javascript": models.Group{
			Summary:         "Vulnerabilities in JavaScript Dependencies",
			Recommendations: []string{"Update the affected JavaScript dependencies to the lastest version"},
		},
		"exposed": models.Group{
			Summary: "Exposed Services",
			Recommendations: []string{
				"If meant to be used by internal services, use a firewall or Security Group to prevent access from the Intenet",
			},
		},
		"drupal": models.Group{
			Summary:         "Vulnerabilities in Drupal",
			Recommendations: []string{"Update Drupal to the lastest version"},
		},
		"certificates": models.Group{
			Summary: "Security Best Practices for SSL Certificates",
		},
		"ssl": models.Group{
			Summary: "Security Best Practices for SSL",
		},
		"http-headers": models.Group{
			Summary: "Security Best Practices for HTTP Headers",
		},
		"webserver": models.Group{
			Summary: "Security Best Practices for Webservers",
		},
		"ssh": models.Group{
			Summary: "Security Best Practices for SSH",
		},
		"email": models.Group{
			Summary: "Security Best Practices for Email Servers",
		},
		"email-spoofing": models.Group{
			Summary: "Email Spoofing Prevention",
		},
		"apache": models.Group{
			Summary:         "Vulnerabilities in Apache",
			Recommendations: []string{"Update Apache to the latest version"},
		},
		"nginx": models.Group{
			Summary:         "Vulnerabilities in Nginx",
			Recommendations: []string{"Update Nginx to the latest version"},
		},
		"openssl": models.Group{
			Summary:         "Vulnerabilities in OpenSSL",
			Recommendations: []string{"Update OpenSSL to the latest version"},
		},
		"openssh": models.Group{
			Summary:         "Vulnerabilities in OpenSSH",
			Recommendations: []string{"Update OpenSSH to the latest version"},
		},
		"jenkins": models.Group{
			Summary:         "Vulnerabilities in Jenkins",
			Recommendations: []string{"Update Jenkins to the latest version"},
		},
		"unsupported": models.Group{
			Summary:         "Unsupported Software",
			Recommendations: []string{"Update to a supported version"},
		},
		"aws": models.Group{
			Summary: "Security Issues in AWS Accounts",
		},
		"rdp": models.Group{
			Summary: "Security Best Practices for RDP",
		},
		"docker": models.Group{
			Summary: "Docker Vulnerabilities",
		},
		"cis": models.Group{
			Summary: "CIS Compliance (BETA)",
		},
		"other-vulnerabilities": models.Group{
			Summary: "Other Vulnerabilities",
		},
		"default": models.Group{
			Summary: "Unclassified Issues",
		},
	}

	// vuln2Group is where Vulcan Core defined vulnerabilities are mapped to
	// groups.
	// The static rules are defined using a map, where the key is the summary
	// of the vulnerability, and the value is the name of the group.
	vuln2Group = map[string]string{
		// HTTP-Headers group
		"Cross-Origin Resource Sharing Implemented with Universal Access": "http-headers",
		"HTTP Strict Transport Security Not Implemented":                  "http-headers",
		"HTTP Content Security Policy Not Implemented":                    "http-headers",
		"HTTP Redirect Misconfiguration":                                  "http-headers",
		"HTTP Subresource Integrity Misconfiguration":                     "http-headers",
		"HTTP X-Content-Type-Options Not Implemented":                     "http-headers",
		"HTTP X-Frame-Options Not Implemented":                            "http-headers",
		"HTTP Cookies Misconfiguration":                                   "http-headers",
		"HTTP X-XSS-Protection Not Implemented":                           "http-headers",
		"HTTP Strict Transport Security Misconfiguration":                 "http-headers",
		"HTTP Referrer Policy Misconfiguration":                           "http-headers",
		"HTTP X-Content-Type-Options Misconfiguration":                    "http-headers",
		"HTTP X-XSS-Protection Misconfiguration":                          "http-headers",
		"HTTP X-Frame-Options Misconfiguration":                           "http-headers",
		"HTTP Content Security Policy Is Malformed":                       "http-headers",

		// SSL Configuration group
		"Weak SSL/TLS Ciphersuites":                                                             "ssl",
		"Weak SSL/TLS Protocol Versions":                                                        "ssl",
		"OCSP Stapling Not Enabled":                                                             "ssl",
		"SSL RC4 Cipher Suites Supported (Bar Mitzvah)":                                         "ssl",
		"Missing Strong SSL/TLS Protocol Versions":                                              "ssl",
		"SSL Version 2 and 3 Protocol Detection":                                                "ssl",
		"SSL Anonymous Cipher Suites Supported":                                                 "ssl",
		"Cipher Suite Ordering Not Enforced":                                                    "ssl",
		"Perfect Forward Secrecy Not Supported":                                                 "ssl",
		"SSL/TLS EXPORT_DHE <= 512-bit Export Cipher Suites Supported (Logjam)":                 "ssl",
		"SSL Weak Cipher Suites Supported":                                                      "ssl",
		"SSL/TLS EXPORT_RSA <= 512-bit Cipher Suites Supported (FREAK)":                         "ssl",
		"SSL/TLS Diffie-Hellman Modulus <= 1024 Bits (Logjam)":                                  "ssl",
		"SSL Null Cipher Suites Supported":                                                      "ssl",
		"Small Public Key":                                                                      "ssl",
		"SSLv3 Padding Oracle On Downgraded Legacy Encryption Vulnerability (POODLE)":           "ssl",
		"Small Diffie-Hellman Key":                                                              "ssl",
		"Site Without HTTPS":                                                                    "ssl",
		"SSL Medium Strength Cipher Suites Supported":                                           "ssl",
		"Transport Layer Security (TLS) Protocol CRIME Vulnerability":                           "ssl",
		"SSL DROWN Attack Vulnerability (Decrypting RSA with Obsolete and Weakened eNcryption)": "ssl",
		"TLS Padding Oracle Information Disclosure Vulnerability (TLS POODLE)":                  "ssl",
		"Cipher Suite Order Not Compliant":                                                      "ssl",
		"SSL Medium Strength Cipher Suites Supported (SWEET32)":                                 "ssl",
		"TLS Version 1.0 Protocol Detection":                                                    "ssl",
		"TLS Version 1.1 Protocol Detection":                                                    "ssl",
		"SSL Certificate Signed Using Weak Hashing Algorithm (Known CA)":                        "ssl",

		// Email Spoofing group
		//DKIM
		"DKIM DNS Record Not Found":       "email-spoofing",
		"Misconfiguration Of DKIM Record": "email-spoofing",
		"Multiple DKIM Records Found":     "email-spoofing",
		"DKIM Missing Version Tag":        "email-spoofing",
		"DKIM Record In Test Mode":        "email-spoofing",
		"DKIM Record In Strict Mode":      "email-spoofing",
		"DKIM Record Allows Use Of SHA1":  "email-spoofing",
		"DKIM Key Revocation":             "email-spoofing",
		"DKIM Public Key Is Too Short":    "email-spoofing",
		"DKIM Unable To Parse Tags":       "email-spoofing",
		//SPF
		"SPF Multiple Records Found":                   "email-spoofing",
		"SPF 'all' Mechanism Configured As 'SOFTFAIL'": "email-spoofing",
		"SPF 'all' Configured As 'NEUTRAL'":            "email-spoofing",
		"SPF 'all' Is Not The Rightmost Mechanism":     "email-spoofing",
		"SPF DNS Record Not Found":                     "email-spoofing",
		"SPF Policy Not Found":                         "email-spoofing",
		//DMARC
		"DMARC DNS Record Not Found":          "email-spoofing",
		"DMARC Multiple Records Found":        "email-spoofing",
		"DMARC Unable To Parse Tags":          "email-spoofing",
		"DMARC 'v' And 'p' Are Invalid":       "email-spoofing",
		"DMARC Tag 'v' Has Wrong Value":       "email-spoofing",
		"DMARC Tag 'p' Has Wrong Value":       "email-spoofing",
		"DMARC Tag 'p' Set To 'none'":         "email-spoofing",
		"DMARC Tag 'p' Set To 'quarantine'":   "email-spoofing",
		"DMARC Tag 'rua' Missing":             "email-spoofing",
		"DMARC Tag 'ruf' Missing":             "email-spoofing",
		"DMARC Tag 'pct' Is Not Set To '100'": "email-spoofing",
		"DMARC Tag 'rua' Is Invalid":          "email-spoofing",
		"DMARC Tag 'ruf' Is Invalid":          "email-spoofing",
		"DMARC Tag 'adkim' Is Invalid":        "email-spoofing",
		"DMARC Tag 'aspf' Is Invalid":         "email-spoofing",
		"DMARC Tag 'sp' Is Invalid":           "email-spoofing",
		"DMARC Tag 'fo' Is Invalid":           "email-spoofing",
		"DMARC Tag 'rf' Is Invalid":           "email-spoofing",
		"DMARC Tag 'ri' Is Invalid":           "email-spoofing",

		// JavaScript Libraries group
		"parseHTML() executes scripts in event handlers":         "javascript",
		"3rd party CORS request may execute":                     "javascript",
		"Selector interpreted as HTML":                           "javascript",
		"XSS Vulnerability on closeText option":                  "javascript",
		"Title cross-site scripting vulnerability":               "javascript",
		"cross-site-scripting":                                   "javascript",
		"XSS in data-target attribute":                           "javascript",
		"reDOS - regular expression denial of service":           "javascript",
		"open redirect leads to cross site scripting":            "javascript",
		"XSS through SVG if enableSvg is set":                    "javascript",
		"DOS in $sanitize":                                       "javascript",
		"Universal CSP bypass via add-on in Firefox":             "javascript",
		"The attribute usemap can be used as a security exploit": "javascript",
		"safari UXSS":                                       "javascript",
		"DOM-based XSS":                                     "javascript",
		"execution of arbitrary javascript":                 "javascript",
		"weakness in HTML escaping":                         "javascript",
		"XSS with location.hash":                            "javascript",
		"Quoteless attributes in templates can lead to XSS": "javascript",
		"poorly sanitized input passed to eval()":           "javascript",
		"XSS in $sanitize in Safari/Firefox":                "javascript",
		" including untrusted objects as React children can result in an XSS security vulnerability": "javascript",
		"XSS in data-template, data-content and data-title properties of tooltip/popover":            "javascript",
		"XSS in data-target property of scrollspy":                                                   "javascript",
		"XSS in collapse data-parent attribute":                                                      "javascript",
		"XSS in data-container property of tooltip":                                                  "javascript",
		"XSS vulnerability in the HTML parser":                                                       "javascript",
		"jQuery before 3.4.0, as used in Drupal, Backdrop CMS, and other products, mishandles jQuery.extend(true, {}, ...) because of Object.prototype pollution": "javascript",
		"A prototype pollution vulnerability in handlebars is exploitable if an attacker can control the template":                                                "javascript",
		"XSS":                             "javascript",
		"Prototype pollution":             "javascript",
		"JQuery 1.2 < 3.5.0 Multiple XSS": "javascript",
		"Regex in its jQuery.htmlPrefilter sometimes may introduce XSS":                                                                               "javascript",
		"angular.js prior to 1.8.0 allows cross site scripting. The regex-based input HTML replacement may turn sanitized code into unsanitized one.": "javascript",

		// SSL Certificates group
		"Expired Certificate":                                         "certificates",
		"Certificate About To Expire":                                 "certificates",
		"Certificate Host Mismatch":                                   "certificates",
		"Untrusted Certificate Authority":                             "certificates",
		"SSL Certificate Cannot Be Trusted":                           "certificates",
		"SSL Self-Signed Certificate":                                 "certificates",
		"SSL Certificate Expiry":                                      "certificates",
		"SSL Certificate Signed Using Weak Hashing Algorithm":         "certificates",
		"Certificate Signed With Weak Algorithm":                      "certificates",
		"SSL Certificate with Wrong Hostname":                         "certificates",
		"SSL Certificate Chain Contains RSA Keys Less Than 2048 bits": "certificates",

		// PHP Vulnerabilities group
		"PHP 5.6.x < 5.6.33 Multiple Vulnerabilities":                                         "php",
		"PHP 7.0.x < 7.0.25 Multiple Vulnerabilities":                                         "php",
		"PHP 7.2.x < 7.2.3 Stack Buffer Overflow":                                             "php",
		"PHP 7.0.x < 7.0.19 Multiple Vulnerabilities":                                         "php",
		"PHP 7.0.x < 7.0.28 Stack Buffer Overflow":                                            "php",
		"PHP 7.0.x < 7.0.21 Multiple Vulnerabilities":                                         "php",
		"PHP 7.0.x < 7.0.27 Multiple Vulnerabilities":                                         "php",
		"PHP 7.0.x < 7.0.20 Multiple Vulnerabilities":                                         "php",
		"PHP 5.6.x < 5.6.34 Stack Buffer Overflow":                                            "php",
		"PHP 5.2 < 5.2.14 Multiple Vulnerabilities":                                           "php",
		"PHP 5.2 < 5.2.15 Multiple Vulnerabilities":                                           "php",
		"PHP 5.2 < 5.2.17 / 5.3 < 5.3.5 String To Double Conversion DoS":                      "php",
		"PHP 7.1.x < 7.1.17 Multiple Vulnerabilities":                                         "php",
		"PHP 7.2.x < 7.2.5 Stack Buffer Overflow":                                             "php",
		"PHP < 5.2.10 Multiple Vulnerabilities":                                               "php",
		"PHP < 5.2.11 Multiple Vulnerabilities":                                               "php",
		"PHP < 5.2.12 Multiple Vulnerabilities":                                               "php",
		"PHP < 5.3.11 Multiple Vulnerabilities":                                               "php",
		"PHP < 5.3.12 / 5.4.2 CGI Query String Code Execution":                                "php",
		"PHP < 5.3.2 / 5.2.13 Multiple Vulnerabilities":                                       "php",
		"PHP < 5.3.9 Multiple Vulnerabilities":                                                "php",
		"PHP PHP_RSHUTDOWN_FUNCTION Security Bypass":                                          "php",
		"PHP Unsupported Version Detection":                                                   "php",
		"PHP 7.0.x < 7.0.30 Multiple Vulnerabilities":                                         "php",
		"PHP 5.6.x < 5.6.37 exif_thumbnail_extract() DoS":                                     "php",
		"PHP 7.2.x < 7.2.8 Use After Free Arbitrary Code Execution in EXIF":                   "php",
		"PHP 5.4.x < 5.4.31 CLI Server 'header' DoS":                                          "php",
		"PHP 5.4.x < 5.4.30 Multiple Vulnerabilities":                                         "php",
		"PHP 5.4.x < 5.4.40 Multiple Vulnerabilities":                                         "php",
		"PHP 5.4.x < 5.4.45 Multiple Vulnerabilities":                                         "php",
		"PHP 5.4.x < 5.4.17 Buffer Overflow":                                                  "php",
		"PHP 5.4.x < 5.4.18 Multiple Vulnerabilities":                                         "php",
		"PHP 5.4.x < 5.4.26 Multiple Vulnerabilities":                                         "php",
		"PHP 5.4.x < 5.4.34 Multiple Vulnerabilities":                                         "php",
		"PHP 5.4.x < 5.4.42 Multiple Vulnerabilities":                                         "php",
		"PHP 5.4.x < 5.4.44 Multiple Vulnerabilities":                                         "php",
		"PHP 5.4.x < 5.4.35 'donote' DoS":                                                     "php",
		"PHP 5.4.x < 5.4.41 Multiple Vulnerabilities":                                         "php",
		"PHP 5.4.x < 5.4.38 Multiple Vulnerabilities (GHOST)":                                 "php",
		"PHP 5.4.x < 5.4.32 Multiple Vulnerabilities":                                         "php",
		"PHP 5.4.x < 5.4.36 'process_nested_data' RCE":                                        "php",
		"PHP 5.4.x < 5.4.37 Multiple Vulnerabilities":                                         "php",
		"PHP 5.4.x < 5.4.39 Multiple Vulnerabilities":                                         "php",
		"PHP 5.4.x < 5.4.23 OpenSSL openssl_x509_parse() Memory Corruption":                   "php",
		"PHP 5.4.x < 5.4.43 Multiple Vulnerabilities (BACKRONYM)":                             "php",
		"PHP 5.4.x < 5.4.24 Multiple Vulnerabilities":                                         "php",
		"PHP 5.4.x < 5.4.29 'src/cdf.c' Multiple Vulnerabilities":                             "php",
		"PHP 5.4.x < 5.4.28 FPM Unix Socket Insecure Permission Escalation":                   "php",
		"PHP 5.4.x < 5.4.27 awk Magic Parsing BEGIN DoS":                                      "php",
		"PHP 7.2.x < 7.2.10 Transfer-Encoding Parameter XSS Vulnerability":                    "php",
		"PHP 7.2.x < 7.2.13 Arbitrary Command Injection Vulnerability":                        "php",
		"PHP 5.6.x < 5.6.39 Arbitrary Command Injection Vulnerability":                        "php",
		"PHP 7.1.x < 7.1.25 Arbitrary Command Injection Vulnerability":                        "php",
		"PHP 5.6.x < 5.6.31 Multiple Vulnerabilities":                                         "php",
		"PHP 5.6.x < 5.6.32 Multiple Vulnerabilities":                                         "php",
		"PHP 5.6.x < 5.6.36 Multiple Vulnerabilities":                                         "php",
		"PHP 5.6.x < 5.6.38 Transfer-Encoding Parameter XSS Vulnerability":                    "php",
		"PHP 5.6.x < 5.6.39 Multiple vulnerabilities":                                         "php",
		"PHP 5.6.x < 5.6.40 Multiple vulnerabilities.":                                        "php",
		"PHP 5.6.x < 5.6.35 Security Bypass Vulnerability":                                    "php",
		"PHP 7.2.x < 7.2.21 Multiple Vulnerabilities.":                                        "php",
		"PHP 7.3.x < 7.3.7 Multiple Vulnerabilities.":                                         "php",
		"PHP 7.3.x < 7.3.8 Multiple Vulnerabilities.":                                         "php",
		"PHP 7.3.x < 7.3.9 Multiple Vulnerabilities.":                                         "php",
		"PHP 7.3.x < 7.3.10 Heap-Based Buffer Overflow Vulnerability.":                        "php",
		"PHP < 7.1.33 / 7.2.x < 7.2.24 / 7.3.x < 7.3.11 Remote Code Execution Vulnerability.": "php",
		"PHP 7.0.x < 7.0.31 Use After Free Arbitrary Code Execution in EXIF":                  "php",
		"PHP 7.0.x < 7.0.32 Transfer-Encoding Parameter XSS Vulnerability":                    "php",
		"PHP 7.0.x < 7.0.33 Multiple vulnerabilities":                                         "php",
		"PHP 7.2.x < 7.2.13 Multiple vulnerabilities":                                         "php",
		"PHP 7.2.x < 7.2.14 Multiple vulnerabilities.":                                        "php",
		"PHP 7.2.x < 7.2.17 Multiple vulnerabilities.":                                        "php",
		"PHP 7.2.x < 7.2.16 Multiple vulnerabilities.":                                        "php",
		"PHP 7.2.x < 7.2.18 Heap-based Buffer Overflow Vulnerability.":                        "php",
		"PHP 7.2.x < 7.2.19 Multiple Vulnerabilities.":                                        "php",
		"PHP 7.2.x < 7.2.30 Multiple Vulnerabilities":                                         "php",
		"PHP 7.2.x < 7.2.31 / 7.3.x < 7.3.18, 7.4.x < 7.4.6 Denial of Service (DoS)":          "php",
		"PHP 5.5.x < 5.5.30 Multiple Vulnerabilities":                                         "php",
		"PHP prior to 5.5.x < 5.5.31 / 5.6.x < 5.6.17 Multiple Vulnerabilities":               "php",
		"PHP 5.5.x < 5.5.32 Multiple Vulnerabilities":                                         "php",
		"PHP 5.5.x < 5.5.33 Multiple Vulnerabilities":                                         "php",
		"PHP 5.5.x < 5.5.34 Multiple Vulnerabilities":                                         "php",
		"PHP 7.2.x < 7.2.28 / PHP 7.3.x < 7.3.15 / 7.4.x < 7.4.3 Multiple Vulnerabilities":    "php",
		"PHP 7.3.x < 7.3.16 Multiple Vulnerabilities":                                         "php",
		"PHP 7.3.x < 7.3.17 Out of Bounds Read Vulnerability":                                 "php",

		// Webserver Configuration group
		"HTTP TRACE / TRACK Methods Allowed":                  "webserver",
		"Web Server PROPFIND Method Internal IP Disclosure":   "webserver",
		"Web Server HTTP Header Internal IP Disclosure":       "webserver",
		"Nonexistent Page (404) Physical Path Disclosure":     "webserver",
		"Apache Tomcat Default Files":                         "webserver",
		"Apache .htaccess and .htpasswd Disclosure":           "webserver",
		"Apache Server ETag Header Information Disclosure":    "webserver",
		"Sensitive file exposed on web server":                "webserver",
		"HTTP Proxy Arbitrary Site/Port Relaying":             "webserver",
		"HTTP Proxy POST Request Relaying":                    "webserver",
		"Web Server Load Balancer Detection":                  "webserver",
		"Apache mod_info /server-info Information Disclosure": "webserver",
		"HTTP Reverse Proxy Detection":                        "webserver",
		"web.config File Information Disclosure":              "webserver",
		"Exposed HTTP Resources":                              "webserver",
		"Web Server Uses Non Random Session IDs":              "webserver",

		// SSH Configuration group
		"SSH Weak Algorithms Supported":                  "ssh",
		"SSH Server CBC Mode Ciphers Enabled":            "ssh",
		"SSH Weak MAC Algorithms Enabled":                "ssh",
		"SSH Allows Authentication Using Passwords":      "ssh",
		"Service Uses Weak Ciphers":                      "ssh",
		"Service Uses Weak Key Exchange Algorithms":      "ssh",
		"Service Uses Weak Message Authentication Codes": "ssh",

		// Email Configuration group
		"SMTP Service Cleartext Login Permitted":  "email",
		"POP3 Cleartext Logins Permitted":         "email",
		"MTA Open Mail Relaying Allowed":          "email",
		"SMTP Server Non-standard Port Detection": "email",

		// Exposed Services group
		"Exposed Database Ports":   "exposed",
		"Exposed FTP Ports":        "exposed",
		"Exposed SSH Ports":        "exposed",
		"Exposed Memcached Server": "exposed",
		"Unknown Hosts":            "exposed",
		"Exposed Services":         "exposed",
		"Exposed URLs":             "exposed",
		"Exposed HDFS Ports":       "exposed",
		"Exposed RDP Port":         "exposed",

		// WordPress Vulnerabilities group
		"WordPress 2.8.6-4.9 - Authenticated JavaScript File Upload":                                   "wordpress",
		"WordPress 3.7-4.9.1 - MediaElement Cross-Site Scripting (XSS)":                                "wordpress",
		"WordPress 3.4-4.7 - Stored Cross-Site Scripting (XSS) via Theme Name fallback":                "wordpress",
		"WordPress 2.5.0-4.7.4 - Filesystem Credentials Dialog CSRF":                                   "wordpress",
		"WordPress 2.9-4.7 - Authenticated Cross-Site scripting (XSS) in update-core.php":              "wordpress",
		"WordPress 3.5-4.7.1 - WP_Query SQL Injection":                                                 "wordpress",
		"WordPress 4.2-4.7.2 - Press This CSRF DoS":                                                    "wordpress",
		"WordPress 2.8.1-4.7.2 - Control Characters in Redirect URL Validation":                        "wordpress",
		"WordPress 4.3-4.7 - Remote Code Execution (RCE) in PHPMailer":                                 "wordpress",
		"WordPress 4.4-4.8.1 - Cross-Site Scripting (XSS) in oEmbed":                                   "wordpress",
		"WordPress 4.2.3-4.8.1 - Authenticated Cross-Site Scripting (XSS) in Visual Editor":            "wordpress",
		"WordPress 2.7.0-4.7.4 - Insufficient Redirect Validation":                                     "wordpress",
		"WordPress 2.3-4.8.3 - Host Header Injection in Password Reset":                                "wordpress",
		"WordPress 4.3.0-4.7.1 - Cross-Site Scripting (XSS) in posts list table":                       "wordpress",
		"WordPress 3.6.0-4.7.2 - Authenticated Cross-Site Scripting (XSS) via Media File Metadata":     "wordpress",
		"WordPress 3.0-4.8.1 - Path Traversal in Unzipping":                                            "wordpress",
		"WordPress 3.0-4.7 - Cryptographically Weak Pseudo-Random Number Generator (PRNG)":             "wordpress",
		"WordPress  4.0-4.7.2 - Authenticated Stored Cross-Site Scripting (XSS) in YouTube URL Embeds": "wordpress",
		"WordPress 2.8-4.7 - Accessibility Mode Cross-Site Request Forgery (CSRF)":                     "wordpress",
		"WordPress 3.4.0-4.7.4 - Customizer XSS & CSRF":                                                "wordpress",
		"WordPress 2.3.0-4.8.1 - $wpdb->prepare() potential SQL Injection":                             "wordpress",
		"WordPress 2.9.2-4.8.1 - Open Redirect":                                                        "wordpress",
		"WordPress 2.3.0-4.7.4 - Authenticated SQL injection":                                          "wordpress",
		"WordPress 3.3-4.7.4 - Large File Upload Error XSS":                                            "wordpress",
		"WordPress 3.7-4.9.4 - Use Safe Redirect for Login":                                            "wordpress",
		"WordPress 4.4-4.8.1 - Path Traversal in Customizer":                                           "wordpress",
		"WordPress <= 4.9.4 - Application Denial of Service (DoS) (unpatched)":                         "wordpress",
		"WordPress <= 4.9.6 - Authenticated Arbitrary File Deletion":                                   "wordpress",
		"WordPress <= 5.0 - Authenticated Cross-Site Scripting (XSS)":                                  "wordpress",
		"WordPress <= 5.0 - Authenticated Post Type Bypass":                                            "wordpress",
		"WordPress <= 5.0 - Cross-Site Scripting (XSS) that could affect plugins":                      "wordpress",
		"WordPress <= 5.0 - File Upload to XSS on Apache Web Servers":                                  "wordpress",
		"WordPress <= 5.0 - PHP Object Injection via Meta Data":                                        "wordpress",
		"WordPress <= 5.0 - Authenticated File Delete":                                                 "wordpress",
		"WordPress 3.7-5.0 (except 4.9.9) - Authenticated Code Execution":                              "wordpress",
		"WordPress <= 5.3 - Stored XSS via Crafted Links":                                              "wordpress",
		"WordPress <= 5.3 - Stored XSS via Block Editor Content":                                       "wordpress",
		"WordPress <= 5.3 - wp_kses_bad_protocol() Colon Bypass":                                       "wordpress",
		"WordPress 3.9-5.1 - Comment Cross-Site Scripting (XSS)":                                       "wordpress",
		"WordPress <= 5.2.2 - Cross-Site Scripting (XSS) in URL Sanitisation":                          "wordpress",
		"WordPress <= 5.2.3 - Stored XSS in Customizer":                                                "wordpress",
		"WordPress <= 5.2.3 - Unauthenticated View Private/Draft Posts":                                "wordpress",
		"WordPress <= 5.2.3 - Stored XSS in Style Tags":                                                "wordpress",
		"WordPress 5.2.2 - Cross-Site Scripting (XSS) in Stored Comments":                              "wordpress",
		"WordPress 5.2.2 - Authenticated Cross-Site Scripting (XSS) in Post Previews":                  "wordpress",
		"WordPress 5.2.2 - Potential Open Redirect":                                                    "wordpress",
		"WordPress 5.0-5.2.2 - Authenticated Stored XSS in Shortcode Previews":                         "wordpress",
		"WordPress 5.2.2 - Cross-Site Scripting (XSS) in Dashboard":                                    "wordpress",

		"WordPress plugin AddToAny Share Buttons <= 1.7.14 - Conditional Host Header Injection":                              "wordpress",
		"WordPress plugin Contextual Related Posts 1.8.10.1 - contextual-related-posts.php Multiple Parameter SQL Injection": "wordpress",
		"WordPress plugin Contextual Related Posts 1.8.6 - Cross-Site Request Forgery":                                       "wordpress",
		"WordPress plugin Contact Form 7 <= 3.5.2 - File Upload Remote Code Execution":                                       "wordpress",
		"WordPress plugin Contact Form 7 <= 3.7.1 - Security Bypass":                                                         "wordpress",
		"WordPress plugin Google Analytics by Monster Insights":                                                              "wordpress",
		"WordPress plugin Yoast SEO <= 5.7.1 - Authenticated Cross-Site Scripting (XSS)":                                     "wordpress",
		"WordPress plugin Gravity Forms <= 1.9.15.11 -  Authenticated Reflected Cross-Site Scripting (XSS)":                  "wordpress",
		"WordPress plugin Gravity Forms <= 1.9.6 - Cross-Site Scripting (XSS)":                                               "wordpress",
		"WordPress plugin Gravity Forms <= 2.0.6.5 - Authenticated Blind Cross-Site Scripting (XSS)":                         "wordpress",
		"WordPress plugin MailPoet Newsletters 2.6.10 - Unspecified CSRF":                                                    "wordpress",
		"WordPress plugin MailPoet Newsletters 2.6.6 - Theme File Upload H&ling Remote Code Execution":                       "wordpress",
		"WordPress plugin MailPoet Newsletters <= 2.6.19 - Unauthenticated Reflected Cross-Site Scripting (XSS)":             "wordpress",
		"WordPress plugin MailPoet Newsletters <= 2.7.2 - Authenticated Reflected Cross-Site Scripting (XSS)":                "wordpress",
		"WordPress plugin MailPoet Newsletters <= 2.7.2 - SQL Injection":                                                     "wordpress",
		"WordPress plugin Simple Download Monitor <= 3.5.3 - Authenticated Cross-Site Scripting (XSS)":                       "wordpress",
		"WordPress plugin WP-Polls <= 2.70 - Stored Cross-Site Scripting (XSS)":                                              "wordpress",
		"WordPress plugin WP-Polls <= 2.73 - Authenticated Reflected Cross-Site Scripting (XSS)":                             "wordpress",
		"WordPress plugin Wysija Newsletters - swfupload Cross-Site Scripting":                                               "wordpress",
		"WordPress plugin Wysija Newsletters 2.2 - SQL Injection":                                                            "wordpress",
		"WordPress plugin Yet Another Related Posts Plugin (YARPP) 4.2.4 - CSRF / XSS / RCE":                                 "wordpress",
		"WordPress plugin YouTube Embed <= 11.8.1 - Cross-Site Request Forgery (CSRF)":                                       "wordpress",
		"WordPress plugin Contact Form 7 <= 5.0.3 - register_post_type() Privilege Escalation":                               "wordpress",
		"WordPress plugin Yoast SEO <= 9.1 - Authenticated Race Condition":                                                   "wordpress",
		"WordPress plugin Yoast SEO 1.2.0-11.5 - Authenticated Stored XSS":                                                   "wordpress",
		"WordPress plugin MailPoet Newsletters  2.6.7 - helpers/back.php page Parameter Unspecified Issue":                   "wordpress",
		"WordPress plugin Simple Download Monitor <= 3.2.8 - Insufficient Authorization":                                     "wordpress",
		"WordPress plugin Google Analytics by Monster Insights <= 7.1.0 - Authenticated Stored Cross-Site Scripting (XSS)":   "wordpress",
		"WordPress plugin Captcha 2.12-3.8.1 - Captcha Bypass":                                                               "wordpress",
		"WordPress plugin Captcha <= 4.0.6 - Captcha Bypass":                                                                 "wordpress",
		"WordPress plugin Multiple BestWebSoft Plugins - Authenticated Reflected GET Cross-Site Scripting (XSS)":             "wordpress",
		"WordPress plugin Ultimate Addons for Visual Composer <= 3.16.11 - Authenticated XSS, CSRF, RCE":                     "wordpress",
		"WordPress plugin Contact Form 7 <= 3.7.1 - CAPTCHA Bypass":                                                          "wordpress",

		"WordPress plugin W3 Total Cache - Remote Code Execution":                                         "wordpress",
		"WordPress plugin W3 Total Cache 0.9.4 - Edge Mode Enabling CSRF":                                 "wordpress",
		"WordPress plugin W3 Total Cache <= 0.9.4 - Cross-Site Request Forgery (CSRF)":                    "wordpress",
		"WordPress plugin W3 Total Cache <= 0.9.4 - Debug Mode XSS":                                       "wordpress",
		"WordPress plugin W3 Total Cache <= 0.9.4.1 - Authenticated Reflected Cross-Site Scripting (XSS)": "wordpress",
		"WordPress plugin W3 Total Cache <= 0.9.4.1 – Unauthenticated Security Token Bypass":              "wordpress",
		"WordPress plugin W3 Total Cache <= 0.9.4.1 – Authenticated Arbitrary File Upload":                "wordpress",
		"WordPress plugin W3 Total Cache <= 0.9.4.1 – Authenticated Arbitrary File Download":              "wordpress",
		"WordPress plugin W3 Total Cache <= 0.9.4.1 – Authenticated Arbitrary PHP Code Execution":         "wordpress",
		"WordPress plugin W3 Total Cache <= 0.9.4 - Unauthenticated Server Side Request Forgery (SSRF)":   "wordpress",
		"WordPress plugin W3 Total Cache 0.9.2.6-0.9.3 - Unauthenticated Arbitrary File Read":             "wordpress",
		"WordPress plugin W3 Total Cache < 0.9.7.3 - Cryptographic Signature Bypass":                      "wordpress",
		"WordPress plugin W3 Total Cache <= 0.9.7.3 - Cross-Site Scripting (XSS)":                         "wordpress",
		"WordPress plugin W3 Total Cache <= 0.9.7.3 - SSRF / RCE via phar":                                "wordpress",

		// Apache Vulnerabilities group
		"Apache 2.0.x < 2.0.64 Multiple Vulnerabilities":                      "apache",
		"Apache 2.0.x < 2.0.65 Multiple Vulnerabilities":                      "apache",
		"Apache 2.2.x < 2.2.33-dev / 2.4.x < 2.4.26 Multiple Vulnerabilities": "apache",
		"Apache 2.4.x < 2.4.27 Multiple Vulnerabilities":                      "apache",
		"Apache 2.4.x < 2.4.28 HTTP Vulnerability (OptionsBleed)":             "apache",
		"Apache 2.4.x < 2.4.30 Multiple Vulnerabilities":                      "apache",
		"Apache 2.4.x < 2.4.33 Multiple Vulnerabilities":                      "apache",
		"Apache < 2.0.63 Multiple XSS Vulnerabilities":                        "apache",
		"Apache HTTP Server 403 Error Page UTF-7 Encoded XSS":                 "apache",
		"Apache HTTP Server httpOnly Cookie Information Disclosure":           "apache",
		"Apache Multiviews Arbitrary Directory Listing":                       "apache",
		"Apache HTTP Server Byte Range DoS":                                   "apache",
		"Apache 2.4.x < 2.4.34 Multiple Vulnerabilities":                      "apache",
		"Apache 2.4.x < 2.4.35 DoS":                                           "apache",
		"Apache mod_wsgi < 4.2.4 Privilege Dropping Privilege Escalation":     "apache",
		"Apache mod_status /server-status Information Disclosure":             "apache",
		"Apache 2.4.x < 2.4.41 Multiple Vulnerabilities":                      "apache",
		"Apache 2.4.x < 2.4.39 Multiple Vulnerabilities":                      "apache",
		"Multiple vulnerabilities in Apache httpd":                            "apache",
		"Apache 2.4.x < 2.4.38 Multiple Vulnerabilities":                      "apache",
		"Apache 2.4.x < 2.4.42 Multiple Vulnerabilities":                      "apache",

		// Nginx Vulnerabilities group
		"nginx 1.9.5 < 1.16.1 / 1.17.x < 1.17.3 Multiple Vulnerabilties": "nginx",
		"Multiple vulnerabilities in nginx":                              "nginx",

		// OpenSSL Vulnerabilities group
		"OpenSSL 0.9.8 < 0.9.8x DTLS CBC Denial of Service":                                          "openssl",
		"OpenSSL 0.9.8 < 0.9.8za Multiple Vulnerabilities":                                           "openssl",
		"OpenSSL 0.9.8 < 0.9.8zb Multiple Vulnerabilities":                                           "openssl",
		"OpenSSL 0.9.8 < 0.9.8zc Multiple Vulnerabilities (POODLE)":                                  "openssl",
		"OpenSSL 0.9.8 < 0.9.8zd Multiple Vulnerabilities (FREAK)":                                   "openssl",
		"OpenSSL 0.9.8 < 0.9.8zf Multiple Vulnerabilities":                                           "openssl",
		"OpenSSL 0.9.8 < 0.9.8zg Multiple Vulnerabilities":                                           "openssl",
		"OpenSSL 0.9.8 < 0.9.8zh X509_ATTRIBUTE Memory Leak DoS":                                     "openssl",
		"OpenSSL < 0.9.8l Multiple Vulnerabilities":                                                  "openssl",
		"OpenSSL < 0.9.8p / 1.0.0b Buffer Overflow":                                                  "openssl",
		"OpenSSL < 0.9.8p / 1.0.0e Double Free Vulnerability":                                        "openssl",
		"OpenSSL < 0.9.8s Multiple Vulnerabilities":                                                  "openssl",
		"OpenSSL < 0.9.8u Multiple Vulnerabilities":                                                  "openssl",
		"OpenSSL < 0.9.8w ASN.1 asn1_d2i_read_bio Memory Corruption":                                 "openssl",
		"OpenSSL < 0.9.8y Multiple Vulnerabilities":                                                  "openssl",
		"OpenSSL AES-NI Padding Oracle MitM Information Disclosure":                                  "openssl",
		"OpenSSL Unsupported":                                                                        "openssl",
		"OpenSSL 1.0.x < 1.0.2m RSA/DSA Unspecified Carry Issue":                                     "openssl",
		"OpenSSL 1.0.x < 1.0.2o Multiple Vulnerabilities":                                            "openssl",
		"OpenSSL 1.0.2 < 1.0.2n Multiple Vulnerabilities":                                            "openssl",
		"OpenSSL < 1.1.0 Default Weak 64-bit Block Cipher (SWEET32)":                                 "openssl",
		"OpenSSL 1.0.x < 1.0.2p Multiple Vulnerabilities":                                            "openssl",
		"OpenSSL 'ChangeCipherSpec' MiTM Vulnerability":                                              "openssl",
		"OpenSSL SSL_OP_NETSCAPE_REUSE_CIPHER_CHANGE_BUG Session Resume Ciphersuite Downgrade Issue": "openssl",

		// OpenSSH vulnerability group.
		"Multiple vulnerabilities in OpenSSH": "openssh",

		// Jenkings Vulnerabilities group
		"Jenkins JDK / Ant Tools Job Configuration Stored XSS Vulnerability (SECURITY-624)":                                                                                                      "jenkins",
		"Jenkins < 1.642.2 / 1.650 and Jenkins Enterprise < 1.609.16.1 / 1.625.16.1 / 1.642.2.1 Multiple Vulnerabilities":                                                                        "jenkins",
		"Jenkins < 2.46.2 / 2.57 and Jenkins Enterprise < 1.625.24.1 / 1.651.24.1 / 2.7.24.0.1 / 2.46.2.1 Multiple Vulnerabilities":                                                              "jenkins",
		"Jenkins < 2.44 / 2.32.x < 2.32.2, Jenkins Operations Center < 1.625.22.1 / 2.7.22.0.1 / 2.32.2.1, and Jenkins Enterprise < 1.651.22.1 / 2.7.22.0.1 / 2.32.2.1 Multiple Vulnerabilities": "jenkins",
		"Jenkins < 2.89.2 / 2.95 Multiple Vulnerabilities":                                                                                                                                       "jenkins",
		"Jenkins < 2.73.3 / 2.89 Multiple Vulnerabilities":                                                                                                                                       "jenkins",
		"Jenkins < 2.107.2 / 2.116 Multiple Vulnerabilities":                                                                                                                                     "jenkins",
		"Jenkins < 2.89.4 / 2.107 Multiple Vulnerabilities":                                                                                                                                      "jenkins",
		"Jenkins < 2.121.2 / 2.133 Multiple Vulnerabilities":                                                                                                                                     "jenkins",
		"Jenkins < 2.121.3 / 2.138 Multiple Vulnerabilities":                                                                                                                                     "jenkins",
		"Jenkins < 2.138.2 / 2.146 Multiple Vulnerabilities":                                                                                                                                     "jenkins",
		"Jenkins < 2.150.1 LTS / 2.154 Multiple Vulnerabilities":                                                                                                                                 "jenkins",

		// Unsupported Software group
		"Unix Operating System Unsupported Version Detection": "unsupported",
		"Unsupported Web Server Detection":                    "unsupported",

		// AWS Trusted Advisor group
		"AWS Amazon S3 Bucket Permissions": "aws",
		"AWS Security Groups":              "aws",
		"AWS IAM Access Key Rotation":      "aws",
		"AWS ELB Listener Security":        "aws",
		"AWS CloudFront Custom SSL Certificates in the IAM Certificate Store":     "aws",
		"AWS CloudFront SSL Certificate on the Origin Server":                     "aws",
		"AWS Security Groups - Specific Ports Unrestricted":                       "aws",
		"AWS AWS CloudTrail Logging":                                              "aws",
		"AWS Security Groups - Unrestricted Access":                               "aws",
		"AWS Amazon RDS Security Group Access Risk":                               "aws",
		"Managed AWS databases using CA about to expire":                          "aws",
		"AWS Amazon Route 53 MX Resource Record Sets and Sender Policy Framework": "aws",

		// Other Software Vulnerabilities group
		"Return Of Bleichenbacher's Oracle Threat (ROBOT) Information Disclosure":               "other-vulnerabilities",
		"OTRS Authenticated Remote Code Execution (OSA-2017-07)":                                "other-vulnerabilities",
		"OTRS Unspecified Remote Code Execution (OSA-2017-04)":                                  "other-vulnerabilities",
		"F5 BIG-IP Cookie Remote Information Disclosure":                                        "other-vulnerabilities",
		"LDAP NULL BASE Search Access":                                                          "other-vulnerabilities",
		"XMPP Cleartext Authentication":                                                         "other-vulnerabilities",
		"S3 Subdomain Takeover":                                                                 "other-vulnerabilities",
		"Web Server Generic Cookie Injection":                                                   "other-vulnerabilities",
		"SNMP 'GETBULK' Reflection DDoS":                                                        "other-vulnerabilities",
		"SNMP Agent Default Community Name (public)":                                            "other-vulnerabilities",
		"Elasticsearch Unrestricted Access Information Disclosure":                              "other-vulnerabilities",
		"Kibana ESA-2018-18":                                                                    "other-vulnerabilities",
		"Kibana ESA-2018-14":                                                                    "other-vulnerabilities",
		"Kibana ESA-2018-17":                                                                    "other-vulnerabilities",
		"Apache Struts 2 s:a / s:url Tag href Element XSS":                                      "other-vulnerabilities",
		"Apache Struts 2.3.5 - 2.3.31 / 2.5.x < 2.5.10.1 Jakarta Multipart Parser RCE (remote)": "other-vulnerabilities",
		"MS15-034: Vulnerability in HTTP.sys Could Allow Remote Code Execution (3042553) (uncredentialed check)": "other-vulnerabilities",
		"Network Time Protocol (NTP) Mode 6 Scanner":                                                             "other-vulnerabilities",
		"Multiple vulnerabilities in ISC BIND":                                                                   "other-vulnerabilities",
		"Secrets Leaked in Git Repository":                                                                       "other-vulnerabilities",
		"ISC BIND Service Downgrade / Reflected DoS ISC BIND Denial of Service":                                  "other-vulnerabilities",
		"SMB Signing not required":                                                                               "other-vulnerabilities",

		// Drupal Vulnerabilities group
		"Drupal - SA-CORE-2018-004 - Remote Code Execution":    "drupal",
		"Drupal - SA-CORE-2018-003 - Cross-Site Scripting":     "drupal",
		"Drupal - SA-CORE-2018-002 - Remote Code Execution":    "drupal",
		"Drupal - SA-CORE-2018-001 - Multiple Vulnerabilities": "drupal",
		"Drupal - SA-CORE-2018-006 - Multiple Vulnerabilities": "drupal",

		// RDP Vulnerabilities group
		"Microsoft Windows Remote Desktop Protocol Server Man-in-the-Middle Weakness": "rdp",
		"Terminal Services Doesn't Use Network Level Authentication (NLA) Only":       "rdp",
		"Terminal Services Encryption Level is Medium or Low":                         "rdp",
		"Terminal Services Encryption Level is not FIPS-140 Compliant":                "rdp",

		// Docker Vulnerabilities group
		"Outdated Packages in Docker Image":        "docker",
		"Outdated Packages in Docker Image (BETA)": "docker",

		// CIS Compliance group
		"Compliance With CIS AWS Foundations Benchmark (BETA)": "cis",
	}
)

func group(vulns []models.Vulnerability) ([]models.Group, error) {
	// To make the grouping, first we iterate by all the Vulcan Core vulnerabilties
	// storing them in a map where its key is the group name, and the value an
	// array of the vulnerabilities present for that group.
	m := make(map[string][]models.Vulnerability)
	for _, vuln := range vulns {
		// Sort affected targets by alphabetical order.
		sort.Strings(vuln.AffectedTargets)
		vuln.AffectedTargets = removeDuplicates(vuln.AffectedTargets)
		// Get the group name for the vuln.
		gr := v2g(vuln.Summary)
		// Append the vuln in the map.
		m[gr] = append(m[gr], vuln)
	}

	// Once we have all the vulnerabilities classified in groups in the map,
	// we create one models.Group for every group in the map, with its Summary,
	// Recommendations and Vulnerabilities.
	var res []models.Group
	for k, v := range m {
		gr, ok := groups[k]
		if !ok {
			return nil, fmt.Errorf("group %v not found", k)
		}
		// Sort vulnerabilities by score, num of affected targets and alphabetical order of the Summary.
		sort.Slice(v, func(i, j int) bool {
			switch {
			case v[i].Score != v[j].Score:
				return v[i].Score > v[j].Score
			case len(v[i].AffectedTargets) != len(v[j].AffectedTargets):
				return len(v[i].AffectedTargets) > len(v[j].AffectedTargets)
			default:
				return v[i].Summary < v[j].Summary
			}
		})

		gr.Vulnerabilities = v
		res = append(res, gr)
	}
	// Sort groups by score, num of issues and alphabetical order of the Summary.
	sort.Slice(res, func(i, j int) bool {
		switch {
		case len(res[i].Vulnerabilities) > 0 && len(res[j].Vulnerabilities) > 0 && res[i].Vulnerabilities[0].Score != res[j].Vulnerabilities[0].Score:
			return res[i].Vulnerabilities[0].Score > res[j].Vulnerabilities[0].Score
		case len(res[i].Vulnerabilities) != len(res[j].Vulnerabilities):
			return len(res[i].Vulnerabilities) > len(res[j].Vulnerabilities)
		default:
			return res[i].Summary < res[j].Summary
		}
	})

	return res, nil
}

// v2g covers the case when two Vulnerabilities can be the same even having
// a different summary. It is handled using regular expressions for the summary.
// For example the vulcan-retirejs check embeds the detected version of the
// vulnerable JavaScript library in the summary. So the same vulnerability
// can have as many different summaries as versions affected:
//	XSS in angularjs 1.5
//	XSS in angularjs 1.6
func v2g(summary string) string {
	// gr, ok := vuln2Group[vuln.ID]
	gr, ok := vuln2Group[summary]
	if !ok {
		gr = "default"
	}

	return gr
}

func removeDuplicates(ss []string) []string {
	var out []string
	m := make(map[string]bool)
	for _, s := range ss {
		if b := m[s]; !b {
			out = append(out, s)
			m[s] = true
		}
	}
	return out
}
