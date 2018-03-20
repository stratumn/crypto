VERSION=$(shell ./version.sh)
PRERELEASE=$(shell cat PRERELEASE)
GIT_PATH=$(shell git rev-parse --show-toplevel)
GITHUB_REPO=$(shell basename $(GIT_PATH))
GITHUB_USER=$(shell basename $(shell dirname $(GIT_PATH)))
GIT_TAG=v$(VERSION)
RELEASE_NAME=$(GIT_TAG)
RELEASE_NOTES_FILE=RELEASE_NOTES.md
COVERAGE_FILE=coverage.txt
COVERHTML_FILE=coverhtml.txt
CLEAN_PATHS=$(DIST_DIR) $(COVERAGE_FILE) $(COVERHTML_FILE)

GO_CMD=go
GO_LINT_CMD=golint
KEYBASE_CMD=keybase
GITHUB_RELEASE_COMMAND=github-release

GITHUB_RELEASE_FLAGS=--user '$(GITHUB_USER)' --repo '$(GITHUB_REPO)' --tag '$(GIT_TAG)'
GITHUB_RELEASE_RELEASE_FLAGS=$(GITHUB_RELEASE_FLAGS) --name '$(RELEASE_NAME)' --description "$$(cat $(RELEASE_NOTES_FILE))"

GO_LIST=$(GO_CMD) list
GO_TEST=$(GO_CMD) test
GO_LINT=$(GO_LINT_CMD) -set_exit_status
GITHUB_RELEASE_RELEASE=$(GITHUB_RELEASE_COMMAND) release $(GITHUB_RELEASE_RELEASE_FLAGS)
GITHUB_RELEASE_EDIT=$(GITHUB_RELEASE_COMMAND) edit $(GITHUB_RELEASE_RELEASE_FLAGS)

PACKAGES=$(shell $(GO_LIST) ./... | grep -v vendor)
TEST_PACKAGES=$(shell $(GO_LIST) ./... | grep -v vendor)
COVERAGE_SOURCES=$(shell find * -name '*.go')

LICENSED_FILES=$(shell find * -name '*.go' -not -path "vendor/*" | grep -v mock | grep -v '^\./\.')

TEST_LIST=$(foreach package, $(TEST_PACKAGES), test_$(package))
LINT_LIST=$(foreach package, $(PACKAGES), lint_$(package))
CLEAN_LIST=$(foreach path, $(CLEAN_PATHS), clean_$(path))

# == .PHONY ===================================================================
.PHONY: test coverage lint build git_tag github_draft github_publish clean test_headers $(TEST_LIST) $(LINT_LIST) $(CLEAN_LIST)

# == all ======================================================================
all: lint test

# == release ==================================================================
release: test lint clean build git_tag github_draft github_upload github_publish

# == test =====================================================================
test: $(TEST_LIST)

$(TEST_LIST): test_%:
	@$(GO_TEST) -v $* $(GO_TEST_OPTS)

test_wo_cache: GO_TEST_OPTS=-count=1
test_wo_cache: $(TEST_LIST)

# == coverage =================================================================
coverage: $(COVERAGE_FILE)

$(COVERAGE_FILE): $(COVERAGE_SOURCES)
	@for d in $(TEST_PACKAGES); do \
	    $(GO_TEST) -v -coverprofile=profile.out -covermode=atomic $$d || exit 1; \
	    if [ -f profile.out ]; then \
	        cat profile.out >> $(COVERAGE_FILE); \
	        rm profile.out; \
	    fi \
	done

coverhtml:
	echo 'mode: set' > $(COVERHTML_FILE)
	@for d in $(TEST_PACKAGES); do \
	    $(GO_TEST) -coverprofile=profile.out $$d || exit 1; \
	    if [ -f profile.out ]; then \
	        tail -n +2 profile.out >> $(COVERHTML_FILE); \
	        rm profile.out; \
	    fi \
	done
	$(GO_CMD) tool cover -html $(COVERHTML_FILE)


# == list =====================================================================
lint: $(LINT_LIST)

$(LINT_LIST): lint_%:
	@$(GO_LINT) $*

# == git_tag ==================================================================
git_tag:
	git tag $(GIT_TAG)
	git push origin --tags

# == github_draft =============================================================
github_draft:
	@if [[ $prerelease != "false" ]]; then \
		echo $(GITHUB_RELEASE_RELEASE) --draft --pre-release; \
		$(GITHUB_RELEASE_RELEASE) --draft --pre-release; \
	else \
		echo $(GITHUB_RELEASE_RELEASE) --draft; \
		$(GITHUB_RELEASE_RELEASE) --draft; \
	fi

# == github_publish ===========================================================
github_publish:
	@if [[ "$(PRERELEASE)" != "false" ]]; then \
		echo $(GITHUB_RELEASE_EDIT) --pre-release; \
		$(GITHUB_RELEASE_EDIT) --pre-release; \
	else \
		echo $(GITHUB_RELEASE_EDIT); \
		$(GITHUB_RELEASE_EDIT); \
	fi

# == license_headers ==========================================================
license_headers: $(LICENSED_FILES)

$(LICENSED_FILES): LICENSE_HEADER
	perl -i -0pe 's/\/\/ Copyright \d* Stratumn.*\n(\/\/.*\n)*/`cat LICENSE_HEADER`/ge' $@

# == clean ====================================================================
clean: $(CLEAN_LIST)

$(CLEAN_LIST): clean_%:
	rm -rf $*
 
test_headers:
	@ ./test_headers.sh $(LICENSED_FILES)