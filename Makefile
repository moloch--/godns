.PHONY: test coverage coverage-html fuzz

COVERPROFILE ?= coverage.out
FUZZTIME ?= 10s

test:
	go test ./...

coverage:
	go test ./... -coverprofile=$(COVERPROFILE)
	go tool cover -func=$(COVERPROFILE)

coverage-html: coverage
	go tool cover -html=$(COVERPROFILE) -o coverage.html

fuzz:
	go test ./pkg/godns -run=^$$ -fuzz=FuzzParseConfigs -fuzztime=$(FUZZTIME)
	go test ./pkg/godns -run=^$$ -fuzz=FuzzCompileRulesAndMatch -fuzztime=$(FUZZTIME)
	go test ./pkg/godns -run=^$$ -fuzz=FuzzEvalReplacement -fuzztime=$(FUZZTIME)
	go test ./pkg/godns -run=^$$ -fuzz=FuzzHandleDNSRequestEmptyQuestion -fuzztime=$(FUZZTIME)
	go test ./cmd -run=^$$ -fuzz=FuzzParseRuleHelpers -fuzztime=$(FUZZTIME)
