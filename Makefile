.PHONY: all build clean docs fmt run setup test tools syscall_test syscall_bin

all: build

setup:
	@rustup component add rust-src
	@rustup component add rustc-dev
	@rustup component add llvm-tools-preview
	@cargo install mdbook

build:
	@make --no-print-directory -C regression
	@cargo kbuild

tools:
	@cd services/libs/comp-sys && cargo install --path cargo-component

# FIXME: Exit code manipulation is not needed using non-x86 QEMU
run: build
ifneq ($(ENABLE_KVM), false)
	cargo krun --enable-kvm || exit $$(($$? >> 1))
else
	cargo krun || exit $$(($$? >> 1))
endif

syscall_bin:
	@make --no-print-directory -C regression/syscall_test

# Test Jinux in a QEMU guest VM and run a series of evaluations.
syscall_test: syscall_bin build
ifneq ($(ENABLE_KVM), false)
	@cargo ksctest --enable-kvm || exit $$(($$? >> 1))
else
	@cargo ksctest || exit $$(($$? >> 1))
endif

# The usermode cargo test of Jinux frame and Jinux standard library.
test: build
	@cargo ktest

docs:
	@cargo doc 								# Build Rust docs
	@echo "" 								# Add a blank line
	@cd docs && mdbook build 				# Build mdBook

check:
	@cargo fmt --check 				# Check Rust format issues
	@cargo kclippy					# Check common programming mistakes

clean:
	@cargo clean
	@cd docs && mdbook clean
	@make --no-print-directory -C regression clean
