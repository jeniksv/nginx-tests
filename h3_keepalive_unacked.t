#!/usr/bin/perl

# (C) Jan Svojanovsky

# Tests for HTTP/3, keepalive timeout with unacknowledged response.

###############################################################################

use warnings;
use strict;

use Test::More;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx;
use Test::Nginx::HTTP3;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $t = Test::Nginx->new()->has(qw/http http_v3 cryptx/)
	->has_daemon('openssl')->plan(2)
	->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    ssl_certificate_key localhost.key;
    ssl_certificate localhost.crt;

    server {
        listen       127.0.0.1:%%PORT_8980_UDP%% quic;
        server_name  localhost;

        keepalive_timeout 1s;
    }
}

EOF

$t->write_file('openssl.conf', <<EOF);
[ req ]
default_bits = 2048
encrypt_key = no
distinguished_name = req_distinguished_name
[ req_distinguished_name ]
EOF

my $d = $t->testdir();

foreach my $name ('localhost') {
	system('openssl req -x509 -new '
		. "-config $d/openssl.conf -subj /CN=$name/ "
		. "-out $d/$name.crt -keyout $d/$name.key "
		. ">>$d/openssl.out 2>&1") == 0
		or die "Can't create certificate for $name: $!\n";
}

# exceeds the initial congestion window,
# yet fits into the client stream flow control window

$t->write_file('index.html', 'x' x 200000);

$t->run();

###############################################################################

my ($s, $sid, $frames, $frame);

$s = Test::Nginx::HTTP3->new();
$sid = $s->new_stream();

# do not read, and thus acknowledge, the response past keepalive_timeout,
# PING keeps the connection from the idle timeout, which is set to
# keepalive_timeout as well

for (1 .. 10) {
	$s->ping();
	select undef, undef, undef, 0.2;
}

$frames = $s->read(all => [{ sid => $sid, fin => 1 }]);

($frame) = grep { $_->{type} eq "HEADERS" } @$frames;
is($frame->{headers}->{':status'}, 200, 'request');

my $length = 0;
$length += $_->{length}
	for grep { $_->{type} eq "DATA" && $_->{sid} == $sid } @$frames;
is($length, 200000, 'response body');

###############################################################################
