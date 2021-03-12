/*
Copyright 2021 Adevinta
*/

// Package groupie allows getting, saving and grouping vulnerabilities detected
// by Vulcan, making them easier to process by the end users.
package groupie

import (
	"context"
	"github.com/adevinta/vulcan-groupie/db"
	"github.com/adevinta/vulcan-groupie/pkg/models"
	report "github.com/adevinta/vulcan-report"
)

// Results defines the methods required by the Groupie from a results client.
type Results interface {
	ScanReports(ctx context.Context, ID string, workers int) ([]report.Report, error)
}

// Groupie allows calling the package functions using an injected configuration
// and persistence layer.
type Groupie struct {
	db db.DB
}

// New creates a Groupie instance given the injected config and db,
// and returns its address.
func New(db db.DB) *Groupie {
	return &Groupie{db: db}
}

// UpdateFromScan gets the vulnerabilities for the given scanID from Vulcan
// Core and stores them in the db.
func (g *Groupie) UpdateFromScan(scanID string, date string, reports []report.Report) error {
	return g.db.SaveScanVulnerabilities(scanID, date, reports)
}

// GroupByScan returns the current vulnerabilities stored in the db for a given
// scan.
func (g *Groupie) GroupByScan(scanID ...string) ([]models.Group, error) {
	// First we get the vulnerabilities stored in the DB.
	// They have been grouped in a way the they are unique,
	// so they have list of AffectedTargets.
	vulns, err := g.db.GetScanVulnerabilities(scanID...)
	if err != nil {
		return nil, err
	}

	// And finally we create the groups given the kind of vulnerabilities
	// present.
	return group(vulns)
}

// GroupByTarget returns the current vulnerabilities stored in the db for the given
// targets.
func (g *Groupie) GroupByTarget(target ...string) ([]models.Group, error) {
	// First we get the vulnerabilities stored in the DB.
	// They have been grouped in a way the they are unique,
	// so they have list of AffectedTargets.
	vulns, err := g.db.GetTargetVulnerabilities(target...)
	if err != nil {
		return nil, err
	}

	// And finally we create the groups given the kind of vulnerabilities
	// present.
	return group(vulns)
}

// Classified specifies if a vulnerability is already classified in groupie or not.
func Classified(summary string) bool {
	return v2g(summary) != "default"
}
