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
	"io"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/lmittmann/tint"
	"github.com/mattn/go-isatty"
	"github.com/moloch--/godns/pkg/godns"
	"github.com/spf13/cobra"
)

const (
	interfaceFlag    = "interface"
	portFlag         = "port"
	netFlag          = "net"
	dialTimeoutFlag  = "dial-timeout"
	readTimeoutFlag  = "read-timeout"
	writeTimeoutFlag = "write-timeout"

	logFileFlag   = "log-file"
	logLevelFlag  = "log-level"
	logPrettyFlag = "log-pretty"
	logJSONFlag   = "log-json"

	upstreamFlag     = "upstream"
	upstreamPortFlag = "upstream-port"

	configFlag = "config"

	aRuleFlag     = "rule-a"     // A rule
	qRuleFlag     = "rule-aaaa"  // Quad A rule
	mxRuleFlag    = "rule-mx"    // MX rule
	nsRuleFlag    = "rule-ns"    // NS rule
	txtRuleFlag   = "rule-txt"   // TXT rule
	cnameRuleFlag = "rule-cname" // CNAME rule
	ptrRuleFlag   = "rule-ptr"   // PTR rule
)

func init() {
	// Server Flags
	rootCmd.Flags().StringP(interfaceFlag, "I", "", "Interface to listen on")
	rootCmd.Flags().Uint16P(portFlag, "P", 53, "Port to listen on")
	rootCmd.Flags().StringP(netFlag, "N", "udp", "Network to listen on (tcp/udp)")
	rootCmd.Flags().StringP(dialTimeoutFlag, "D", "30s", "Dial timeout (duration)")
	rootCmd.Flags().StringP(readTimeoutFlag, "R", "30s", "Read timeout (duration)")
	rootCmd.Flags().StringP(writeTimeoutFlag, "W", "30s", "Write timeout (duration)")

	// Logging Flags
	rootCmd.Flags().StringP(logFileFlag, "f", "", "Log file path")
	rootCmd.Flags().StringP(logLevelFlag, "l", "info", "Log level (debug/info/warn/error)")
	rootCmd.Flags().BoolP(logPrettyFlag, "z", true, "Log using pretty terminal colors")
	rootCmd.Flags().BoolP(logJSONFlag, "j", false, "Log in json format")

	// Upstream Flags
	rootCmd.Flags().StringSliceP(upstreamFlag, "u", []string{}, "Upstream DNS server hosts")
	rootCmd.Flags().Uint16P(upstreamPortFlag, "p", 53, "Upstream server port, applied to all upstream hosts")

	// Config File Flag
	rootCmd.Flags().StringP(configFlag, "y", "", "Config file path (yaml/json)")

	// Rule Flags
	rootCmd.Flags().StringSliceP(aRuleFlag, "a", []string{}, "Replacement rule for A records (match|spoof)")
	rootCmd.Flags().StringSliceP(qRuleFlag, "q", []string{}, "Replacement rule for AAAA records (match|spoof)")
	rootCmd.Flags().StringSliceP(mxRuleFlag, "m", []string{}, "Replacement rule for MX records (match|spoof)")
	rootCmd.Flags().StringSliceP(nsRuleFlag, "n", []string{}, "Replacement rule for NS records (match|spoof)")
	rootCmd.Flags().StringSliceP(txtRuleFlag, "t", []string{}, "Replacement rule for TXT records (match|spoof)")
	rootCmd.Flags().StringSliceP(cnameRuleFlag, "c", []string{}, "Replacement rule for CNAME records (match|spoof)")

	rootCmd.AddCommand(completionCmd)
	rootCmd.AddCommand(licenseCmd)
	rootCmd.AddCommand(versionCmd)
}

const rootLongHelp = `GodNS - The God Name Server

A configurable attacker-in-the-middle DNS proxy for Penetration Testers and Malware Analysts.
It allows the selective replacement of specific DNS records for arbitrary domains with custom values,
and can be used to direct traffic to a different host.

Basic rules can be passed via the command line and use glob matching for the domain name spoof the 
response using the provided value. For example, to spoof all A records for various domains:
	
	godns --rule-a "microsoft.com|127.0.0.1" --rule-a "google.com|127.0.0.1"

You can leverage the glob matching to replace all A records:

	godns --rule-a "*|127.0.0.1"

Replace a domain and all subdomain records:

	godns --rule-a "example.com|127.0.0.1" --rule-a "*.example.com|127.0.0.1"

For more advanced usage, a config file can be provided. The config file is a JSON or YAML file that
contains a list of rules. Each rule has a match and spoof value, and can optionally specify a record type
and priority. Configuration file entries also support regular expression matching in addition to glob matching.
`

var rootCmd = &cobra.Command{
	Use:   "godns",
	Short: "God Name Server",
	Long:  rootLongHelp,
	Run: func(cmd *cobra.Command, args []string) {
		// Defaults
		config := &godns.GodNSConfig{
			Server: &godns.ServerConfig{
				Net:        "udp",
				Host:       "",
				ListenPort: 53,
			},
			Client: &godns.ClientConfig{
				Net:          "udp",
				DialTimeout:  "30s",
				ReadTimeout:  "30s",
				WriteTimeout: "30s",
			},
			Upstreams: []string{},
			Rules:     map[string][]*godns.ReplacementRule{},
		}

		// Parse Config File
		if cmd.Flags().Changed(configFlag) {
			configFilePath, _ := cmd.Flags().GetString(configFlag)
			if configFilePath != "" {
				var err error
				config, err = godns.ParseConfigFile(configFilePath)
				if err != nil {
					fmt.Printf("Error loading config file '%s': %s\n", configFilePath, err.Error())
					os.Exit(1)
				}
			}
		}

		// Server Flags
		if cmd.Flags().Changed(interfaceFlag) {
			config.Server.Host, _ = cmd.Flags().GetString(interfaceFlag)
		}
		if cmd.Flags().Changed(portFlag) {
			config.Server.ListenPort, _ = cmd.Flags().GetUint16(portFlag)
		}
		if cmd.Flags().Changed(netFlag) {
			config.Server.Net, _ = cmd.Flags().GetString(netFlag)
		}
		// Client Flags
		if cmd.Flags().Changed(dialTimeoutFlag) {
			config.Client.DialTimeout, _ = cmd.Flags().GetString(dialTimeoutFlag)
		}
		if cmd.Flags().Changed(readTimeoutFlag) {
			config.Client.ReadTimeout, _ = cmd.Flags().GetString(readTimeoutFlag)
		}
		if cmd.Flags().Changed(writeTimeoutFlag) {
			config.Client.WriteTimeout, _ = cmd.Flags().GetString(writeTimeoutFlag)
		}

		// Parse rule flags
		if cmd.Flags().Changed(aRuleFlag) {
			config.Rules["A"] = parseARules(cmd)
		}
		if cmd.Flags().Changed(nsRuleFlag) {
			config.Rules["NS"] = parseRulesFlag(cmd, nsRuleFlag)
		}
		if cmd.Flags().Changed(cnameRuleFlag) {
			config.Rules["CNAME"] = parseRulesFlag(cmd, cnameRuleFlag)
		}
		if cmd.Flags().Changed(ptrRuleFlag) {
			config.Rules["PTR"] = parseRulesFlag(cmd, ptrRuleFlag)
		}
		if cmd.Flags().Changed(mxRuleFlag) {
			config.Rules["MX"] = parseRulesFlag(cmd, mxRuleFlag)
		}
		if cmd.Flags().Changed(txtRuleFlag) {
			config.Rules["TXT"] = parseRulesFlag(cmd, txtRuleFlag)
		}
		if cmd.Flags().Changed(qRuleFlag) {
			config.Rules["AAAA"] = parseRulesFlag(cmd, qRuleFlag)
		}

		// Parse log flags
		logger := parseLogFlags(cmd)

		startServer(config, logger)
	},
}

func parseARules(cmd *cobra.Command) []*godns.ReplacementRule {
	return parseRulesFlag(cmd, aRuleFlag)
}

func parseQRules(cmd *cobra.Command) []*godns.ReplacementRule {
	return parseRulesFlag(cmd, qRuleFlag)
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
	var logOutput io.Writer = os.Stderr
	if logFile, _ := cmd.Flags().GetString(logFileFlag); logFile != "" {
		f, err := os.OpenFile(logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
		if err != nil {
			fmt.Printf("Error opening log file '%s': %s\n", logFile, err.Error())
			os.Exit(1)
		}
		logOutput = io.MultiWriter(os.Stderr, f)
	}

	if logJSON, _ := cmd.Flags().GetBool(logJSONFlag); logJSON {
		logger = slog.New(slog.NewJSONHandler(logOutput, opts))
	} else {
		if logPretty, _ := cmd.Flags().GetBool(logPrettyFlag); logPretty {
			logger = slog.New(tint.NewHandler(logOutput, &tint.Options{
				NoColor: !isatty.IsTerminal(os.Stderr.Fd()),
			}))
		} else {
			logger = slog.New(slog.NewTextHandler(logOutput, opts))
		}
	}

	slog.SetDefault(logger)
	return logger
}

func startServer(config *godns.GodNSConfig, logger *slog.Logger) {
	logger.Info(fmt.Sprintf("Starting GodNS %s (%s:%d)", FullVersion, config.Server.Host, config.Server.ListenPort))

	countRules := 0
	for _, rules := range config.Rules {
		countRules += len(rules)
	}
	if countRules == 0 {
		logger.Warn("No rules specified, GodNS will act as a passthrough DNS server only")
	}

	ns, err := godns.NewGodNS(config, logger)
	if err != nil {
		logger.Error(fmt.Sprintf("Error creating GodNS: %s", err.Error()))
		os.Exit(1)
	}

	c := make(chan os.Signal, 1)
	signal.Notify(c, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-c
		logger.Info(fmt.Sprintf("Shutting down GodNS: %s", sig))
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
