package cmd

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

func newCmdWithStringSliceFlag(name string, values []string) *cobra.Command {
	cmd := &cobra.Command{}
	cmd.Flags().StringSlice(name, values, "")
	return cmd
}

func newCmdWithLogFlags(t *testing.T, logFile string) *cobra.Command {
	t.Helper()

	cmd := &cobra.Command{}
	cmd.Flags().String(logLevelFlag, "info", "")
	cmd.Flags().String(logFileFlag, logFile, "")
	cmd.Flags().Bool(logPrettyFlag, false, "")
	cmd.Flags().Bool(logJSONFlag, false, "")
	return cmd
}

func captureStdout(t *testing.T, fn func()) string {
	t.Helper()

	oldStdout := os.Stdout
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatalf("create stdout pipe: %v", err)
	}
	os.Stdout = writer
	defer func() {
		os.Stdout = oldStdout
	}()

	fn()

	if err := writer.Close(); err != nil {
		t.Fatalf("close stdout writer: %v", err)
	}
	out, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("read stdout: %v", err)
	}
	return string(out)
}

func TestParseRulesFlag(t *testing.T) {
	cmd := newCmdWithStringSliceFlag(aRuleFlag, []string{
		"example.com|192.0.2.10",
		"*.example.net|198.51.100.20",
	})

	rules := parseARules(cmd)
	if len(rules) != 2 {
		t.Fatalf("rule count = %d, want 2", len(rules))
	}
	if rules[0].Priority != 0 || rules[0].IsRegExp {
		t.Fatalf("first rule priority/is_regexp = %d/%v, want 0/false", rules[0].Priority, rules[0].IsRegExp)
	}
	if rules[0].Match != "example.com" || rules[0].Spoof != "192.0.2.10" {
		t.Fatalf("first rule = %#v, want example.com -> 192.0.2.10", rules[0])
	}
	if rules[1].Match != "*.example.net" || rules[1].Spoof != "198.51.100.20" {
		t.Fatalf("second rule = %#v, want *.example.net -> 198.51.100.20", rules[1])
	}
}

func TestParseQRules(t *testing.T) {
	cmd := newCmdWithStringSliceFlag(qRuleFlag, []string{"example.com|2001:db8::10"})

	rules := parseQRules(cmd)
	if len(rules) != 1 {
		t.Fatalf("rule count = %d, want 1", len(rules))
	}
	if rules[0].Match != "example.com" || rules[0].Spoof != "2001:db8::10" {
		t.Fatalf("rule = %#v, want example.com -> 2001:db8::10", rules[0])
	}
}

func TestParseBlockRulesFlag(t *testing.T) {
	cmd := newCmdWithStringSliceFlag(blockRuleFlag, []string{"blocked.example", "*.blocked.example"})

	rules := parseBlockRulesFlag(cmd, blockRuleFlag)
	if len(rules) != 2 {
		t.Fatalf("rule count = %d, want 2", len(rules))
	}
	for index, rule := range rules {
		if !rule.Block {
			t.Fatalf("rule %d Block = false, want true", index)
		}
		if rule.Spoof != "" {
			t.Fatalf("rule %d Spoof = %q, want empty", index, rule.Spoof)
		}
	}
	if rules[0].Match != "blocked.example" || rules[1].Match != "*.blocked.example" {
		t.Fatalf("block matches = %q, %q", rules[0].Match, rules[1].Match)
	}
}

func TestParseLogFlagsWritesJSONAtConfiguredLevel(t *testing.T) {
	logFile := filepath.Join(t.TempDir(), "godns.log")
	cmd := newCmdWithLogFlags(t, logFile)
	if err := cmd.Flags().Set(logLevelFlag, "debug"); err != nil {
		t.Fatalf("set log level: %v", err)
	}
	if err := cmd.Flags().Set(logJSONFlag, "true"); err != nil {
		t.Fatalf("set json flag: %v", err)
	}

	logger := parseLogFlags(cmd)
	logger.Debug("debug-message", "key", "value")

	data, err := os.ReadFile(logFile)
	if err != nil {
		t.Fatalf("read log file: %v", err)
	}
	got := string(data)
	if !strings.Contains(got, `"msg":"debug-message"`) || !strings.Contains(got, `"key":"value"`) {
		t.Fatalf("json log output = %s, want debug message with key", got)
	}
	if slog.Default() != logger {
		t.Fatalf("expected parseLogFlags to install logger as slog default")
	}
}

func TestParseLogFlagsDefaultsUnknownLevelToInfo(t *testing.T) {
	logFile := filepath.Join(t.TempDir(), "godns.log")
	cmd := newCmdWithLogFlags(t, logFile)
	if err := cmd.Flags().Set(logLevelFlag, "verbose"); err != nil {
		t.Fatalf("set log level: %v", err)
	}

	logger := parseLogFlags(cmd)
	logger.Debug("hidden-debug-message")
	logger.Info("visible-info-message")

	data, err := os.ReadFile(logFile)
	if err != nil {
		t.Fatalf("read log file: %v", err)
	}
	got := string(data)
	if strings.Contains(got, "hidden-debug-message") {
		t.Fatalf("debug message should have been filtered at default info level: %s", got)
	}
	if !strings.Contains(got, "visible-info-message") {
		t.Fatalf("info message missing from log output: %s", got)
	}
}

func TestParseLogFlagsLevelFiltering(t *testing.T) {
	tests := []struct {
		level       string
		hidden      func(*slog.Logger)
		hiddenMsg   string
		visible     func(*slog.Logger)
		visibleMsg  string
		wantSnippet string
	}{
		{
			level:      "info",
			hidden:     func(logger *slog.Logger) { logger.Debug("info-hidden-debug") },
			hiddenMsg:  "info-hidden-debug",
			visible:    func(logger *slog.Logger) { logger.Info("info-visible") },
			visibleMsg: "info-visible",
		},
		{
			level:      "warn",
			hidden:     func(logger *slog.Logger) { logger.Info("warn-hidden-info") },
			hiddenMsg:  "warn-hidden-info",
			visible:    func(logger *slog.Logger) { logger.Warn("warn-visible") },
			visibleMsg: "warn-visible",
		},
		{
			level:      "error",
			hidden:     func(logger *slog.Logger) { logger.Warn("error-hidden-warn") },
			hiddenMsg:  "error-hidden-warn",
			visible:    func(logger *slog.Logger) { logger.Error("error-visible") },
			visibleMsg: "error-visible",
		},
	}

	for _, tt := range tests {
		t.Run(tt.level, func(t *testing.T) {
			logFile := filepath.Join(t.TempDir(), "godns.log")
			cmd := newCmdWithLogFlags(t, logFile)
			if err := cmd.Flags().Set(logLevelFlag, tt.level); err != nil {
				t.Fatalf("set log level: %v", err)
			}

			logger := parseLogFlags(cmd)
			tt.hidden(logger)
			tt.visible(logger)

			data, err := os.ReadFile(logFile)
			if err != nil {
				t.Fatalf("read log file: %v", err)
			}
			got := string(data)
			if strings.Contains(got, tt.hiddenMsg) {
				t.Fatalf("hidden message %q should have been filtered: %s", tt.hiddenMsg, got)
			}
			if !strings.Contains(got, tt.visibleMsg) {
				t.Fatalf("visible message %q missing from log output: %s", tt.visibleMsg, got)
			}
		})
	}
}

func TestCompletionCommandRequiresShellArgument(t *testing.T) {
	out := captureStdout(t, func() {
		completionCmd.Run(&cobra.Command{}, nil)
	})

	if !strings.Contains(out, "Specify one of: bash, zsh, fish, or powershell") {
		t.Fatalf("completion output = %q, want shell hint", out)
	}
}

func TestCompletionCommandGeneratesSupportedShells(t *testing.T) {
	for _, shell := range []string{"bash", "zsh", "fish", "powershell"} {
		t.Run(shell, func(t *testing.T) {
			out := captureStdout(t, func() {
				completionCmd.Run(completionCmd, []string{shell})
			})
			if len(out) == 0 {
				t.Fatalf("expected %s completion output to be non-empty", shell)
			}
			if !strings.Contains(out, "godns") {
				t.Fatalf("%s completion output missing command name: %q", shell, out)
			}
		})
	}
}

func TestRootCommandRegistersExpectedFlagsAndSubcommands(t *testing.T) {
	flags := []string{
		interfaceFlag,
		portFlag,
		netFlag,
		dialTimeoutFlag,
		readTimeoutFlag,
		writeTimeoutFlag,
		logFileFlag,
		logLevelFlag,
		logPrettyFlag,
		logJSONFlag,
		upstreamFlag,
		upstreamPortFlag,
		configFlag,
		aRuleFlag,
		qRuleFlag,
		mxRuleFlag,
		nsRuleFlag,
		txtRuleFlag,
		cnameRuleFlag,
		ptrRuleFlag,
		blockRuleFlag,
	}
	for _, flag := range flags {
		if rootCmd.Flags().Lookup(flag) == nil {
			t.Fatalf("expected root command to register --%s", flag)
		}
	}

	subcommands := []string{}
	for _, subcmd := range rootCmd.Commands() {
		subcommands = append(subcommands, subcmd.Name())
	}
	for _, want := range []string{"completion", "license", "version"} {
		if !slices.Contains(subcommands, want) {
			t.Fatalf("subcommands = %#v, missing %s", subcommands, want)
		}
	}
}

func TestVersionCommandPrintsFullVersion(t *testing.T) {
	oldFullVersion := FullVersion
	FullVersion = "test-version"
	defer func() {
		FullVersion = oldFullVersion
	}()

	out := captureStdout(t, func() {
		versionCmd.Run(&cobra.Command{}, nil)
	})

	if out != "test-version\n" {
		t.Fatalf("version output = %q, want test-version newline", out)
	}
}

func TestExecuteRunsConfiguredSubcommand(t *testing.T) {
	oldFullVersion := FullVersion
	FullVersion = "execute-version"
	defer func() {
		FullVersion = oldFullVersion
		rootCmd.SetArgs(nil)
	}()

	rootCmd.SetArgs([]string{"version"})
	out := captureStdout(t, Execute)

	if out != "execute-version\n" {
		t.Fatalf("execute output = %q, want execute-version newline", out)
	}
}

func TestLicenseCommandPrintsGPLNotice(t *testing.T) {
	out := captureStdout(t, func() {
		licenseCmd.Run(&cobra.Command{}, nil)
	})

	if !strings.Contains(out, "God Name Server (godns)") || !strings.Contains(out, "GNU General Public License") {
		t.Fatalf("license output missing expected notice: %q", out)
	}
}
