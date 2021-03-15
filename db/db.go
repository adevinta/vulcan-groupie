/*
Copyright 2020 Adevinta
*/

package db

import (
	"github.com/adevinta/vulcan-groupie/pkg/models"
	report "github.com/adevinta/vulcan-report"
)

// DB defines the methods for the persistence layer to be implemented.
type DB interface {
	SaveScanVulnerabilities(scanID string, date string, reports []report.Report) error
	GetScanVulnerabilities(scanID ...string) ([]models.Vulnerability, error)
	GetTargetVulnerabilities(target ...string) ([]models.Vulnerability, error)
}
