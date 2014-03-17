package t::Util;

use strict;
use warnings;
use Test::More;
use Exporter 'import';

use JSON::WebEncryption;

our @EXPORT = qw(test_encode_decode);

sub test_encode_decode {
    my %specs = @_;
    my ($desc, $input, $expects_exception) =
        @specs{qw/desc input expects_exception/};

    my ($plaintext, $encoding, $public_key, $private_key, $secret, $algorithm, $extra_headers) =
        @$input{qw/plaintext encoding public_key private_key secret algorithm extra_headers/};
    $public_key  ||= $secret;
    $private_key ||= $secret;

    my $test = sub {
        my $jwt = encode_jwe $plaintext, $encoding, $public_key, $algorithm, $extra_headers;
        note "jwt: $jwt";
        return decode_jwe $jwt, $private_key;
    };
    subtest $desc => sub {
        unless ($expects_exception) {
            my $got = $test->();
            is_deeply $got, $plaintext;
        }
        else {
            eval { $test->() };
            like $@, qr/$expects_exception/;
        }
    };
}

1;
__END__
