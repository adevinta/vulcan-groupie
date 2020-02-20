package models

import report "github.com/adevinta/vulcan-report"

// Vulnerability is a Vulcan Core vulnerability with more information, more
// concretely the AffectedTargets and the Checktype that detected it.
type Vulnerability struct {
	report.Vulnerability
	AffectedTargets []string
	Checktype       string
}

// Group consists of a Summary and fixing Recommedation for it, and the list
// of Vulnerabilities present.
type Group struct {
	Summary         string
	Recommendations []string
	Vulnerabilities []Vulnerability
}
