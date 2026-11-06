#!/usr/bin/perl

# (C) Jan Svojanovsky

# Tests for HTTP/3, server unidirectional streams
# with a full congestion window or exhausted connection flow control.

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
	->has_daemon('openssl')->plan(10)
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

        location / { }
    }

    server {
        listen       127.0.0.1:%%PORT_8981_UDP%% quic;
        server_name  localhost;

        keepalive_requests 2;

        location / { }
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

# exceeds the initial congestion window and the limited client connection
# flow control window, yet fits into the client stream flow control window

$t->write_file('big.html', 'x' x 200000);
$t->write_file('index.html', '');

$t->run();

###############################################################################

# the 1st response, not acknowledged until read, fills the congestion window,
# or exhausts the limited connection flow control window, and the 2nd request
# then makes the server write to a unidirectional stream

# GOAWAY on the control stream, as the 2nd request reaches keepalive_requests

goaway('congestion window');
goaway('flow control', 65536);

# instruction on the decoder stream,
# as the 2nd request references the dynamic table

decoder('congestion window');
decoder('flow control', 65536);

###############################################################################

sub goaway {
	my ($name, $max_data) = @_;

	my $s = Test::Nginx::HTTP3->new(8981,
		$max_data ? (opts => { 4 => $max_data }) : ());
	my $sid = $s->new_stream({ path => '/big.html' });
	select undef, undef, undef, 0.2;

	my $sid2 = $s->new_stream();
	select undef, undef, undef, 0.2;

	$s->h3_max_data(1024 * 1024) if $max_data;
	my $frames = $s->read(all => [{ sid => $sid, fin => 1 },
		{ sid => $sid2, fin => 1 }, { type => 'GOAWAY' }]);

	is(body_length($frames, $sid), 200000, "goaway $name - response body");

	my ($frame) = grep { $_->{type} eq "HEADERS" && $_->{sid} == $sid2 }
		@$frames;
	is($frame->{headers}->{':status'}, 200, "goaway $name - request");

	($frame) = grep { $_->{type} eq "GOAWAY" } @$frames;
	is($frame->{last_sid}, 8, "goaway $name - last stream");
}

sub decoder {
	my ($name, $max_data) = @_;

	my $s = Test::Nginx::HTTP3->new(8980,
		$max_data ? (opts => { 4 => $max_data }) : ());
	my $sid = $s->new_stream({ path => '/big.html' });
	select undef, undef, undef, 0.2;

	$s->insert_literal(':path', '/');
	my $sid2 = $s->new_stream({ headers => [
		{ name => ':method', value => 'GET', mode => 0 },
		{ name => ':scheme', value => 'http', mode => 0 },
		{ name => ':path', value => '/', mode => 0, dyn => 1 },
		{ name => ':authority', value => 'localhost', mode => 4 }]});
	select undef, undef, undef, 0.2;

	$s->h3_max_data(1024 * 1024) if $max_data;
	my $frames = $s->read(all => [{ sid => $sid, fin => 1 },
		{ sid => $sid2, fin => 1 }]);

	is(body_length($frames, $sid), 200000,
		"decoder stream $name - response body");

	my ($frame) = grep { $_->{type} eq "HEADERS" && $_->{sid} == $sid2 }
		@$frames;
	is($frame->{headers}->{':status'}, 200,
		"decoder stream $name - request");
}

sub body_length {
	my ($frames, $sid) = @_;
	my $length = 0;

	$length += $_->{length}
		for grep { $_->{type} eq "DATA" && $_->{sid} == $sid }
		@$frames;

	return $length;
}

###############################################################################
