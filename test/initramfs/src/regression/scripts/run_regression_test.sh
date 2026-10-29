#!/bin/sh

# SPDX-License-Identifier: MPL-2.0

set -e

SCRIPT_DIR=/test

# An optional comma-separated list of test directories to run, taken from the
# kernel command line so that a focused run needs no rebuild:
#
#     make run_kernel AUTO_TEST=regression CMDLINE="REGRESSION_TEST_DIRS=rsm"
#
# Without it every test directory runs, as before. A missing `/proc` simply
# leaves the list empty.
SELECTED_DIRS=
if [ -r /proc/cmdline ]; then
    for argument in $(cat /proc/cmdline); do
        case "${argument}" in
            REGRESSION_TEST_DIRS=*) SELECTED_DIRS="${argument#REGRESSION_TEST_DIRS=}" ;;
        esac
    done
fi

for dir in $(find -L "${SCRIPT_DIR}" -mindepth 1 -maxdepth 1 -type d); do
    if [ -n "${SELECTED_DIRS}" ]; then
        case ",${SELECTED_DIRS}," in
            *",$(basename "${dir}"),"*) ;;
            *) continue ;;
        esac
    fi

    if [ -x "${dir}/run_test.sh" ]; then
        echo "Running test in $dir"
        (cd "$dir" && ./run_test.sh)
        echo "All test in $dir passed."
    else
        echo "Skipping $dir (no executable TEST_SCRIPT)"
    fi
done

echo "All regression tests passed."
