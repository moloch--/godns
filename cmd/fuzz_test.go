package cmd

import (
	"strings"
	"testing"
)

func fuzzCmdField(input string) string {
	input = strings.ReplaceAll(input, "|", "")
	input = strings.ReplaceAll(input, ",", "")
	input = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, input)
	if len(input) > 256 {
		return input[:256]
	}
	return input
}

func FuzzParseRuleHelpers(f *testing.F) {
	f.Add("example.com", "192.0.2.10", false)
	f.Add("*.example.net", "2001:db8::10", true)
	f.Add("", "", false)

	f.Fuzz(func(t *testing.T, match string, spoof string, block bool) {
		match = fuzzCmdField(match)
		spoof = fuzzCmdField(spoof)
		if match == "" {
			t.Skip()
		}
		if block {
			cmd := newCmdWithStringSliceFlag(blockRuleFlag, []string{match})
			rules := parseBlockRulesFlag(cmd, blockRuleFlag)
			if len(rules) != 1 {
				t.Fatalf("block rule count = %d, want 1", len(rules))
			}
			if rules[0].Match != match || !rules[0].Block {
				t.Fatalf("block rule = %#v, want match %q with Block=true", rules[0], match)
			}
			return
		}

		cmd := newCmdWithStringSliceFlag(aRuleFlag, []string{match + "|" + spoof})
		rules := parseARules(cmd)
		if len(rules) != 1 {
			t.Fatalf("rule count = %d, want 1", len(rules))
		}
		if rules[0].Match != match || rules[0].Spoof != spoof {
			t.Fatalf("rule = %#v, want %q -> %q", rules[0], match, spoof)
		}
	})
}
