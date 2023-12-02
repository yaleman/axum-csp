.PHONY: help build test book clean_book docs

IMAGE_VERSION ?= latest
IMAGE_ARCH ?= "linux/amd64,linux/arm64"
CONTAINER_BUILD_ARGS ?=
CONTAINER_TOOL ?= docker
CONTAINER_TOOL_ARGS ?=
MARKDOWN_FORMAT_ARGS ?= --options-line-width=100

.DEFAULT: help
help:
	@fgrep -h "##" $(MAKEFILE_LIST) | fgrep -v fgrep | sed -e 's/\\$$//' | sed -e 's/##/\n\t/'

.PHONY: build
build: ## Build release
build:
	cargo build
	cargo build --release

.PHONY: test
test: ## run cargo test
test:
	cargo test
	cargo test --release

.PHONY: codespell
codespell: ## Spellchecking, or shaming. Whatever
codespell:
	codespell -c \
	-L crate,unexpect,Pres,pres,ACI,aci,te,ue,mut \
	--skip='./target,./axum-csp-examples/target,./.git,./static_files,./docs/book/*.js,./docs/*.js,./docs/book/FontAwesome/fonts/fontawesome-webfont.svg'

doc: ## Build the rust documentation locally
doc:
	cargo doc --document-private-items --no-deps

.PHONY: semgrep
semgrep: ## Run semgrep
semgrep:
	./semgrep.sh

.PHONY: prep
prep: ## run things before push/release/etc
prep: docs codespell test build semgrep
	cargo outdated -R
	cargo audit