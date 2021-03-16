/*
Copyright 2020 Adevinta
*/

package cmd

// Config holds the configuration fields used by the vulcan-groupie cli.
type Config struct {
	Persistence string `toml:"persistence"`
	Results     string `toml:"results"`
	Workers     int    `toml:"workers"`
}
