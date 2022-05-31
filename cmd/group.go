/*
Copyright 2020 Adevinta
*/

package cmd

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"

	goaclient "github.com/goadesign/goa/client"
	"github.com/spf13/cobra"

	"github.com/adevinta/vulcan-core-cli/vulcan-core/client"
	"github.com/adevinta/vulcan-core-cli/vulcan-core/results"
	"github.com/adevinta/vulcan-core-cli/vulcan-core/scans"
	"github.com/adevinta/vulcan-groupie/db"
	"github.com/adevinta/vulcan-groupie/pkg/groupie"
	"github.com/adevinta/vulcan-groupie/pkg/models"
	report "github.com/adevinta/vulcan-report"
)

var (
	stateFile string
	minLevel  int
)

// groupCmd represents the base command when called without any subcommands
var groupCmd = &cobra.Command{
	Use:   "group <scan_id1> [scan_id2 ...]",
	Short: "Gets the vulnerabilities from Vulcan Core and converts them",
	Args:  cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		scanID := args[0:]

		var m *db.MemDB
		if stateFile != "" {
			var err error
			m, err = db.LoadState(stateFile)
			if err != nil {
				if _, ok := err.(*os.PathError); !ok {
					return err
				}
				// If the file doesn't exist we continue anyway to allow saving
				// it the first time.
				// But we return the error if there were another error like
				// for example decoding the state.
				m = db.NewMemDB()
			}
		} else {
			m = db.NewMemDB()
		}

		scansClient, err := buildResultsClient(cfg.Persistence, cfg.Results, cfg.Workers)
		if err != nil {
			return err
		}
		g := groupie.New(m)

		for _, s := range scanID {
			d, err := scansClient.Data(context.Background(), s)
			if err != nil {
				return err
			}

			var reports []report.Report
			// Get the reports of the scan. By now, we are not going to fail if
			// the client was unable to get the report of a check, even if the
			// error happened downloading a check that is FINISHED. In future,
			// when we are sure this should not happen, we must fail in that
			// case.
			for _, c := range d.ChecksData {
				if c.Report.Err != nil {
					fmt.Printf("unable to get the report for the check %s of the scan %s, error: %+v\n", c.ID.String(), scanID, c.Report.Err)
					continue
				}
				reports = append(reports, c.Report.Report)
			}

			if err := g.UpdateFromScan(s, d.CreationDate, reports); err != nil {
				return err
			}
		}

		groups, err := g.GroupByScan(scanID...)
		if err != nil {
			return err
		}

		printGroups(groups)

		if stateFile != "" {
			return m.SaveState(stateFile)
		}

		return nil
	},
}

func init() {
	rootCmd.AddCommand(groupCmd)

	groupCmd.Flags().StringVarP(&stateFile, "save", "s", "", "save and load state from a file (suggested is $HOME/.vulcan-groupie/state.gob)")
	groupCmd.Flags().IntVarP(&minLevel, "min-print", "m", 1, "minimum Severity Rank of the vulnerabilities to be printed")
}

func printGroups(groups []models.Group) {
	for _, g := range groups {
		if len(g.Vulnerabilities) == 0 {
			continue
		}

		fmt.Println("#####################")
		fmt.Println(g.Summary)
		fmt.Println(g.Recommendations)
		for _, v := range g.Vulnerabilities {
			if int(v.Severity()) >= minLevel {
				fmt.Printf("\t%v || %v || %v || %v\n", v.Severity(), v.Summary, v.Checktype, v.AffectedTargets)
			}
		}
	}
}

func buildResultsClient(persistenceURL, resultsURL string, workers int) (*scans.Client, error) {
	u, err := url.Parse(persistenceURL)
	if err != nil {
		return nil, err
	}
	if u.Scheme == "" || u.Host == "" {
		return nil, errors.New("invalid persistence url")
	}
	// Build a vulcan core client.

	c := client.New(goaclient.HTTPClientDoer(http.DefaultClient))
	c.Client.Scheme = u.Scheme
	c.Client.Host = u.Host

	// Build a results client.
	rClient, err := results.NewClient(http.DefaultClient)
	if err != nil {
		return nil, err
	}

	// Build a concurrent results client.

	sclient := scans.NewClient(c, rClient, workers)
	return sclient, nil
}
