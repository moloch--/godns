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

import "github.com/spf13/cobra"

const configLongHelp = `GodNS - The God Name Server

Config files can be JSON or YAML, though YAML is recommended. If the file
name does not end in .json the file is assumed to be YAML.

To use a config file, run godns with the --config flag, any conflicting
command line flags that are specified in addition to the config file will
override the values from the config file:

	godns --config /path/to/config.yml
`

var configCmd = &cobra.Command{
	Use:   "config",
	Short: "Generate configuration file(s) for GodNS",
	Long:  configLongHelp,
	Run: func(cmd *cobra.Command, args []string) {

	},
}
