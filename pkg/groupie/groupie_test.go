package groupie

import (
	"encoding/json"
	"io/ioutil"
	"reflect"
	"testing"

	report "github.com/adevinta/vulcan-report"

	"github.com/adevinta/vulcan-groupie/db"
	"github.com/adevinta/vulcan-groupie/pkg/models"
)

var tcClassified = []struct {
	// Test metadata.
	name       string
	skip       bool
	skipAlways bool

	summary string
	want    bool
}{
	{
		name:    "Classified",
		summary: "Weak SSL/TLS Ciphersuites",
		want:    true,
	},
	{
		name:    "Unclassified",
		summary: "fefwfefwfwefw",
		want:    false,
	},
}

func TestClassified(t *testing.T) {
	for _, tc := range tcClassified {
		tc := tc

		t.Run(tc.name, func(t *testing.T) {
			if testing.Short() && tc.skip || tc.skipAlways {
				t.SkipNow()
			}

			have := Classified(tc.summary)

			if tc.want != have {
				t.Errorf("want %+v, have %+v", tc.want, have)
			}
		})
	}
}

type outGroup struct {
	groups []models.Group
	err    error
}

func equalOutGroup(want, have outGroup) bool {
	if !reflect.DeepEqual(want.err, have.err) {
		return false
	}

	if len(want.groups) != len(have.groups) {
		return false
	}

	for i, _ := range want.groups {
		switch {
		case want.groups[i].Summary != have.groups[i].Summary:
			return false
		case !reflect.DeepEqual(want.groups[i].Recommendations, have.groups[i].Recommendations):
			return false
		case len(want.groups[i].Vulnerabilities) != len(have.groups[i].Vulnerabilities):
			return false
		}

		for j, _ := range want.groups[i].Vulnerabilities {
			// NOTE: in order to compare we need to ensure that vulnerabilities and groups are sorted.
			switch {
			case want.groups[i].Vulnerabilities[j].ID != have.groups[i].Vulnerabilities[j].ID:
				return false
			case want.groups[i].Vulnerabilities[j].Summary != have.groups[i].Vulnerabilities[j].Summary:
				return false
			case want.groups[i].Vulnerabilities[j].Checktype != have.groups[i].Vulnerabilities[j].Checktype:
				return false
			case !reflect.DeepEqual(want.groups[i].Vulnerabilities[j].AffectedTargets, have.groups[i].Vulnerabilities[j].AffectedTargets):
				return false
			}
		}
	}

	return true
}

var tcGroupByScan = []struct {
	// Test metadata.
	name       string
	skip       bool
	skipAlways bool

	init []string // Initialisation fixtures for the db, run by order.

	// Input.
	scanID string

	// Output.
	want outGroup
}{
	{
		name: "Single Vuln",
		init: []string{
			"testdata/single-vuln.json",
			"testdata/no-vuln.json",
		},
		scanID: "3",
		want: outGroup{
			err: nil,
			groups: []models.Group{
				{
					Summary: "Security Best Practices for HTTP Headers",
					Vulnerabilities: []models.Vulnerability{
						{
							Vulnerability: report.Vulnerability{
								ID:      "",
								Summary: "HTTP Content Security Policy Not Implemented",
								Score:   3.9,
							},
							AffectedTargets: []string{"www.example.com"},
							Checktype:       "vulcan-http-headers",
						},
					},
				},
			},
		},
	},
	{
		name: "Single Vuln More Than One Host",
		init: []string{
			"testdata/no-vuln.json",
			"testdata/single-vuln-two-targets.json",
		},
		scanID: "4",
		want: outGroup{
			err: nil,
			groups: []models.Group{
				{
					Summary: "Security Best Practices for HTTP Headers",
					Vulnerabilities: []models.Vulnerability{
						{
							Vulnerability: report.Vulnerability{
								ID:      "",
								Summary: "HTTP Content Security Policy Not Implemented",
								Score:   3.9,
							},
							AffectedTargets: []string{
								"www.example.com",
								"www.example2.com",
							},
							Checktype: "vulcan-http-headers",
						},
					},
				},
			},
		},
	},
	{
		name: "No Vuln",
		init: []string{
			"testdata/single-vuln.json",
			"testdata/no-vuln.json",
		},
		scanID: "1",
		want: outGroup{
			err:    nil,
			groups: []models.Group{},
		},
	},
}

func TestGroupByScan(t *testing.T) {
	for _, tc := range tcGroupByScan {
		tc := tc

		t.Run(tc.name, func(t *testing.T) {
			if testing.Short() && tc.skip || tc.skipAlways {
				t.SkipNow()
			}

			// Init db.
			m := db.NewMemDB()
			if err := initFixtures(m, tc.init); err != nil {
				t.Fatalf("can not initialize fixtures: %v", err)
			}

			g := New(m)

			groups, err := g.GroupByScan(tc.scanID)
			have := outGroup{groups, err}

			if !equalOutGroup(tc.want, have) {
				t.Errorf("want %+v, have %+v", tc.want, have)
			}
		})
	}
}

var tcGroupByTarget = []struct {
	// Test metadata.
	name       string
	skip       bool
	skipAlways bool

	init []string // Initialisation fixtures for the db, run by order.

	// Input.
	targets []string

	// Output.
	want outGroup
}{
	{
		name: "Single Vuln",
		init: []string{
			"testdata/no-vuln.json",
			"testdata/single-vuln.json",
		},
		targets: []string{"www.example.com"},
		want: outGroup{
			err: nil,
			groups: []models.Group{
				{
					Summary: "Security Best Practices for HTTP Headers",
					Vulnerabilities: []models.Vulnerability{
						{
							Vulnerability: report.Vulnerability{
								ID:      "",
								Summary: "HTTP Content Security Policy Not Implemented",
								Score:   3.9,
							},
							AffectedTargets: []string{"www.example.com"},
							Checktype:       "vulcan-http-headers",
						},
					},
				},
			},
		},
	},
	{
		name: "Single Vuln More Than One Host",
		init: []string{
			"testdata/no-vuln.json",
			"testdata/single-vuln-two-targets.json",
		},
		targets: []string{
			"www.example.com",
			"www.example2.com",
		},
		want: outGroup{
			err: nil,
			groups: []models.Group{
				{
					Summary: "Security Best Practices for HTTP Headers",
					Vulnerabilities: []models.Vulnerability{
						{
							Vulnerability: report.Vulnerability{
								ID:      "",
								Summary: "HTTP Content Security Policy Not Implemented",
								Score:   3.9,
							},
							AffectedTargets: []string{
								"www.example.com",
								"www.example2.com",
							},
							Checktype: "vulcan-http-headers",
						},
					},
				},
			},
		},
	},
	{
		name: "No Vuln",
		init: []string{
			"testdata/single-vuln.json",
			"testdata/no-vuln.json",
		},
		targets: []string{"www.example.com"},
		want: outGroup{
			err:    nil,
			groups: []models.Group{},
		},
	},
}

func TestGroupByTarget(t *testing.T) {
	for _, tc := range tcGroupByTarget {
		tc := tc

		t.Run(tc.name, func(t *testing.T) {
			if testing.Short() && tc.skip || tc.skipAlways {
				t.SkipNow()
			}

			// Init db.
			m := db.NewMemDB()
			if err := initFixtures(m, tc.init); err != nil {
				t.Fatalf("can not initialize fixtures: %v", err)
			}

			g := New(m)

			groups, err := g.GroupByTarget(tc.targets...)
			have := outGroup{groups, err}

			if !equalOutGroup(tc.want, have) {
				t.Errorf("want %+v, have %+v", tc.want, have)
			}
		})
	}
}

type reportData struct {
	ScanID  string `json:"scan_id"`
	Date    string
	Reports []report.Report
}

func initFixtures(d db.DB, fixtures []string) error {
	for _, fixture := range fixtures {
		b, err := ioutil.ReadFile(fixture)
		if err != nil {
			return err
		}
		var scanReport reportData
		if err := json.Unmarshal(b, &scanReport); err != nil {
			return err
		}
		if err := d.SaveScanVulnerabilities(scanReport.ScanID, scanReport.Date, scanReport.Reports); err != nil {
			return err
		}
	}
	return nil
}

func TestNoUndeclaredGroups(t *testing.T) {
	for summary, group := range vuln2Group {
		if _, ok := groups[group]; !ok {
			t.Fatalf("the group \"%s\" defined for the vuln \"%s\" is not declared", group, summary)
		}
	}
}
