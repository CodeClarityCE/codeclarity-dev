# shellcheck shell=sh
. ./compose.sh

compose down ${1:+"$1"}
