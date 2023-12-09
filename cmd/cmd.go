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
	"log/slog"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/moloch--/godns/pkg/godns"
	"github.com/spf13/cobra"
)

func init() {
	rootCmd.Flags().StringP("host", "H", "", "Host to listen on")
	rootCmd.Flags().Uint16P("port", "p", 53, "Port to listen on")
	rootCmd.Flags().StringP("net", "n", "udp", "Network to listen on (tcp/udp)")
	rootCmd.Flags().StringP("dial-timeout", "d", "30s", "Dial timeout (duration)")
	rootCmd.Flags().StringP("read-timeout", "r", "30s", "Read timeout (duration)")
	rootCmd.Flags().StringP("write-timeout", "w", "30s", "Write timeout (duration)")
	rootCmd.Flags().StringSliceP("rule", "R", []string{}, "Replacement rule (match:spoof:priority)")
	rootCmd.Flags().StringP("config", "c", "", "Config file path (json/yaml)")

	rootCmd.AddCommand(versionCmd)
}

const rootLongHelp = `GodNS - The God Name Server

A configurable attacker-in-the-middle DNS proxy for Penetration Testers and Malware Analysts.
It allows the selective replacement of specific DNS records for arbitrary domains with custom values,
and can be used to direct traffic to a different host.
`

var rootCmd = &cobra.Command{
	Use:   "godns",
	Short: "The God Name Server",
	Long:  rootLongHelp,
	Run: func(cmd *cobra.Command, args []string) {
		host, _ := cmd.Flags().GetString("host")
		port, _ := cmd.Flags().GetUint16("port")
		dialTimeout, _ := cmd.Flags().GetString("dial-timeout")
		readTimeout, _ := cmd.Flags().GetString("read-timeout")
		writeTimeout, _ := cmd.Flags().GetString("write-timeout")

		rules := parseRulesFlag(cmd)
		if len(rules) == 0 {
			fmt.Println("Error: No rules specified")
			os.Exit(1)
		}

		logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
		logger.Info(fmt.Sprintf("Starting GodNS %s:%d", host, port))

		ns, err := godns.NewGodNS(&godns.GodNSConfig{
			Rules: []*godns.ReplacementRule{},

			Server: &godns.ServerConfig{
				Host:       host,
				ListenPort: port,
			},
			Client: &godns.ClientConfig{
				DialTimeout:  dialTimeout,
				ReadTimeout:  readTimeout,
				WriteTimeout: writeTimeout,
			},
		}, logger)
		if err != nil {
			logger.Error(fmt.Sprintf("Error creating GodNS: %s", err.Error()))
			os.Exit(1)
		}
		if err := ns.Start(); err != nil {
			logger.Error(fmt.Sprintf("Error: %s", err.Error()))
			os.Exit(1)
		}
	},
}

func parseRulesFlag(cmd *cobra.Command) []*godns.ReplacementRule {
	rules, _ := cmd.Flags().GetStringSlice("rule")
	parsedRules := []*godns.ReplacementRule{}
	for _, rawRule := range rules {
		segments := strings.Split(rawRule, ":")
		if len(segments) < 2 {
			fmt.Printf("Error: Invalid rule format '%s'\n", rawRule)
			os.Exit(1)
		}
		if _, err := regexp.Compile(segments[0]); err != nil {
			fmt.Printf("Error: Invalid match regex '%s'\n", segments[0])
			os.Exit(1)
		}
		priority := 0
		if len(segments) == 3 {
			value, err := strconv.ParseInt(segments[2], 10, 32)
			if err != nil {
				fmt.Printf("Error: Invalid priority '%s'\n", segments[2])
				os.Exit(1)
			}
			priority = int(value)
		}
		parsedRules = append(parsedRules, &godns.ReplacementRule{
			Priority: priority,
			Match:    segments[0],
			Spoof:    segments[1],
		})
	}
	return parsedRules
}

// Execute - Execute root command
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
