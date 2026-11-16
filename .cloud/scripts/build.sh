# shellcheck shell=sh
. ./compose.sh

compose build ${1:+"$1"}
