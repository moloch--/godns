package cmd

/*
	God Name Server (godns)
	Copyright (C) 2023  moloch--

	This program is free software: you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation, either version 3 of the License, or
	(at your option) any later version.

	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

import (
	"fmt"
	"runtime/debug"
	"time"

	"github.com/spf13/cobra"
)

var (
	Version    string
	Revision   string
	LastCommit time.Time
	DirtyBuild bool
)

func init() {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return
	}
	for _, kv := range info.Settings {
		switch kv.Key {
		case "vcs.revision":
			Revision = kv.Value
		case "vcs.time":
			LastCommit, _ = time.Parse(time.RFC3339, kv.Value)
		case "vcs.modified":
			DirtyBuild = kv.Value == "true"
		}
	}
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Show version information",
	Run: func(cmd *cobra.Command, args []string) {
		version := Version
		if version == "" {
			version = "dev"
		}
		ver := fmt.Sprintf("%s - %s", version, Revision)
		if DirtyBuild {
			ver += " (dirty)"
		}
		ver += fmt.Sprintf(" - %s", LastCommit.Local())
		fmt.Printf("%s\n", ver)
	},
}
