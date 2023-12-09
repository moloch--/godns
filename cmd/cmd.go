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
	"os/signal"
	"strings"

	"github.com/lmittmann/tint"
	"github.com/mattn/go-isatty"
	"github.com/moloch--/godns/pkg/godns"
	"github.com/spf13/cobra"
)

const (
	aRule   = "rule-a"    // A rule
	qRule   = "rule-aaaa" // Quad A rule
	mxRule  = "rule-mx"   // MX rule
	nsRule  = "rule-ns"   // NS rule
	txtRule = "rule-txt"  // TXT rule
)

func init() {
	// Server Flags
	rootCmd.Flags().StringP("host", "H", "", "Host to listen on")
	rootCmd.Flags().Uint16P("port", "P", 53, "Port to listen on")
	rootCmd.Flags().StringP("net", "N", "udp", "Network to listen on (tcp/udp)")
	rootCmd.Flags().StringP("dial-timeout", "D", "30s", "Dial timeout (duration)")
	rootCmd.Flags().StringP("read-timeout", "R", "30s", "Read timeout (duration)")
	rootCmd.Flags().StringP("write-timeout", "W", "30s", "Write timeout (duration)")

	// Logging Flags
	rootCmd.Flags().StringP("log-level", "l", "info", "Log level (debug/info/warn/error)")
	rootCmd.Flags().BoolP("log-pretty", "y", true, "Log using pretty terminal colors")

	// Upstream Flags
	rootCmd.Flags().StringSliceP("upstream", "u", []string{}, "Upstream DNS server (host only)")
	rootCmd.Flags().Uint16P("upstream-port", "p", 53, "Upstream DNS server port (applied to all hosts)")

	// Config Flag
	rootCmd.Flags().StringP("config", "c", "", "Config file path (json/yaml)")

	// Rule Flags
	rootCmd.Flags().StringSliceP(aRule, "a", []string{}, "Replacement rule for A records (match|spoof)")
	rootCmd.Flags().StringSliceP(qRule, "q", []string{}, "Replacement rule for AAAA records (match|spoof)")
	rootCmd.Flags().StringSliceP(mxRule, "m", []string{}, "Replacement rule for MX records (match|spoof)")
	rootCmd.Flags().StringSliceP(nsRule, "n", []string{}, "Replacement rule for NS records (match|spoof)")
	rootCmd.Flags().StringSliceP(txtRule, "t", []string{}, "Replacement rule for TXT records (match|spoof)")

	rootCmd.AddCommand(completionCmd)
	rootCmd.AddCommand(licenseCmd)
	rootCmd.AddCommand(versionCmd)
}

const rootLongHelp = `GodNS - The God Name Server

A configurable attacker-in-the-middle DNS proxy for Penetration Testers and Malware Analysts.
It allows the selective replacement of specific DNS records for arbitrary domains with custom values,
and can be used to direct traffic to a different host.

Basic rules can be passed via the command line, basic rules simply match a domain name and record type
and spoof the response using the provided value. For example, to spoof all A records for various domains:
	
	godns --rule-a "microsoft.com|127.0.0.1" --rule-a "google.com|127.0.0.1"

The command line also allows a global wild card match '*' to match all domains. For example, to spoof
all A records for all domains:

	godns --rule-a "*|127.0.0.1"

For more advanced usage, a config file can be provided. The config file is a JSON or YAML file that
contains a list of rules. Each rule has a match and spoof value, and can optionally specify a record type
and priority. Configuration file also allow for regular expression matching, and can be used to spoof
multiple records for a single domain.
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

		// Parse rule flags, if any
		allRules := map[string][]*godns.ReplacementRule{}
		allRules["A"] = parseARules(cmd)
		allRules["NS"] = parseRulesFlag(cmd, nsRule)
		allRules["MX"] = parseRulesFlag(cmd, mxRule)
		allRules["TXT"] = parseRulesFlag(cmd, txtRule)
		allRules["AAAA"] = parseRulesFlag(cmd, qRule)

		countRules := 0
		for _, rules := range allRules {
			countRules += len(rules)
		}
		if countRules == 0 {
			fmt.Println("Error: No rules specified")
			os.Exit(1)
		}

		// Parse log flags
		logger := parseLogFlags(cmd)

		startServer(&godns.GodNSConfig{
			Rules: allRules,
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
	},
}

func parseARules(cmd *cobra.Command) []*godns.ReplacementRule {
	return parseRulesFlag(cmd, aRule)
}

func parseQRules(cmd *cobra.Command) []*godns.ReplacementRule {
	return parseRulesFlag(cmd, qRule)
}

func parseRulesFlag(cmd *cobra.Command, flag string) []*godns.ReplacementRule {
	rules, _ := cmd.Flags().GetStringSlice(flag)
	parsedRules := []*godns.ReplacementRule{}
	for _, rawRule := range rules {
		segments := strings.Split(rawRule, "|")
		if len(segments) != 2 {
			fmt.Printf("Error: Invalid rule format '%s'\n", rawRule)
			os.Exit(1)
		}
		parsedRules = append(parsedRules, &godns.ReplacementRule{
			Priority: 0,
			IsRegExp: false,
			Match:    segments[0],
			Spoof:    segments[1],
		})
	}
	return parsedRules
}

func parseLogFlags(cmd *cobra.Command) *slog.Logger {
	var logger *slog.Logger

	// parse log level
	logLevel, _ := cmd.Flags().GetString("log-level")
	opts := &slog.HandlerOptions{}
	switch strings.ToLower(logLevel) {
	case "debug":
		opts.Level = slog.LevelDebug
	case "info":
		opts.Level = slog.LevelInfo
	case "warn":
		opts.Level = slog.LevelWarn
	case "error":
		opts.Level = slog.LevelError
	default:
		opts.Level = slog.LevelInfo
	}

	// Initialize root logger
	if logPretty, _ := cmd.Flags().GetBool("log-pretty"); logPretty {
		logger = slog.New(tint.NewHandler(os.Stderr, &tint.Options{
			NoColor: !isatty.IsTerminal(os.Stderr.Fd()),
		}))
	} else {
		logger = slog.New(slog.NewTextHandler(os.Stderr, opts))
	}

	slog.SetDefault(logger)
	return logger
}

func startServer(config *godns.GodNSConfig, logger *slog.Logger) {
	logger.Info(fmt.Sprintf("Starting GodNS %s (%s:%d)", FullVersion, config.Server.Host, config.Server.ListenPort))

	ns, err := godns.NewGodNS(config, logger)
	if err != nil {
		logger.Error(fmt.Sprintf("Error creating GodNS: %s", err.Error()))
		os.Exit(1)
	}

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	go func() {
		<-c
		logger.Info("Shutting down GodNS")
		err := ns.Stop()
		if err != nil {
			logger.Error(fmt.Sprintf("Error shutting down GodNS: %s", err.Error()))
			os.Exit(1)
		}
		os.Exit(0)
	}()

	if err := ns.Start(); err != nil {
		logger.Error(fmt.Sprintf("Error: %s", err.Error()))
		os.Exit(1)
	}
}

// Execute - Execute root command
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
