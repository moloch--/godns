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

	rootCmd.Flags().StringP("config", "c", "", "Config file path (json/yaml)")
}

const rootLongHelp = `GodNS - The God Name Server

A configurable attacker-in-the-middle DNS proxy for Penetration Testers and Malware Analysts.
It allows the selective replacement of specific DNS records for arbitrary domains with custom values,
and can be used to direct traffic to a different host.`

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

		logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
		logger.Info(fmt.Sprintf("Starting GodNS %s:%d", host, port))

		ns, err := godns.NewGodNS(&godns.GodNSConfig{
			Rules: []*godns.ReplacementRule{
				{
					Priority: 1,
					Match:    ".*",
					Spoof:    "1.3.3.7",
				},
			},

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

// Execute - Execute root command
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
