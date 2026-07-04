.PHONY: test lint coverage coverage-html fuzz

COVERPROFILE ?= coverage.out
FUZZTIME ?= 10s
GOLANGCI_LINT ?= golangci-lint

test:
	go test ./...

lint:
	$(GOLANGCI_LINT) run ./...

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
