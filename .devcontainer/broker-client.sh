#!/bin/sh
# Sends one command to the broker and exits with the command's status.
# Usage: broker-client.sh <command> [service]
# Env: WAIVE and REASON, a gate waiver that only dump-knowledge accepts;
# CONFIRM, the confirmation only reset accepts (CONFIRM=reset).
# On a terminal, the broker runs the command on a terminal of the same size.
socket=/run/codeclarity-broker/broker.sock
command=$1
service=$2

size=
if [ -t 1 ]; then
  size=$(stty size </dev/tty 2>/dev/null)
fi
rows=${size% *}
cols=${size#* }

# Each value is URL-encoded by curl and stays one quoted argument.
set --
[ -n "$service" ] && set -- "$@" --url-query "service=$service"
[ -n "$WAIVE" ] && set -- "$@" --url-query "waive=$WAIVE"
[ -n "$REASON" ] && set -- "$@" --url-query "reason=$REASON"
[ "$command" = reset ] && [ -n "$CONFIRM" ] && set -- "$@" --url-query "confirm=$CONFIRM"
case "$rows$cols" in
  '' | *[!0-9]*) ;;
  *) set -- "$@" --url-query tty=1 --url-query "rows=$rows" --url-query "cols=$cols" ;;
esac

# Passes output through as it arrives, except the broker's final exit line.
curl -sS --no-buffer --unix-socket "$socket" -X POST "$@" "http://broker/$command" | perl -e '
  $| = 1;
  binmode STDIN;
  binmode STDOUT;
  my $marker = "__BROKER_EXIT__ ";
  my $buf = "";
  while (sysread(STDIN, my $chunk, 65536)) {
    $buf .= $chunk;
    # Hold back the last line only while it could be the exit line.
    my $end = length($buf) - ($buf =~ /\n\z/ ? 1 : 0);
    my $start = rindex($buf, "\n", $end - 1) + 1;
    my $line = substr($buf, $start, $end - $start);
    my $hold = $buf =~ /\n\z/
      ? $line =~ /\A\Q$marker\E\d+\z/
      : (index($marker, $line) == 0 || $line =~ /\A\Q$marker\E\d*\z/);
    $start = length($buf) unless $hold;
    print substr($buf, 0, $start);
    $buf = substr($buf, $start);
  }
  exit $1 if $buf =~ /\A\Q$marker\E(\d+)\n\z/;
  print $buf;
  exit 1;
'
