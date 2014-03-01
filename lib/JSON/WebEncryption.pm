package JSON::WebEncryption;

use strict;

use parent 'Exporter';

use Carp qw(croak);
use Crypt::CBC;
use JSON qw(decode_json encode_json);
use Digest::SHA qw(hmac_sha256 hmac_sha512);
use MIME::Base64 qw(encode_base64url decode_base64url);

our @EXPORT = qw( encode_jwe decode_jwe );

our %allowed_enc = (
#                   Type     keysize ivsize    pading  integrity func
"A128CBC+HS256" => ['Rijndael', '128', '128', 'PKCS#5', \&hmac_sha256], # AES 128 in CBC with SHA256 HMAC integrity check
"A256CBC+HS512" => ['Rijndael', '256', '128', 'PKCS#5', \&hmac_sha512], # AES 256 in CBC with SHA512 HMAC integrity check
"BF128BC+HS256" => ['Blowfish', '128', '64', 'PKCS#5', \&hmac_sha256], # Blowfish 128 in CBC with SHA256 HMAC integrity check
);

my %crypt_padding_map = (
    'PKCS#5' => 'standard'
);

sub __allowed_enc      { \%allowed_enc };
sub __crypt_padding_map{ \%crypt_padding_map };

# -----------------------------------------------------------------------------

sub encode_from_hash {
    my ($self, $hash) = @_;

    return $self->encode(encode_json($hash));
}

# -----------------------------------------------------------------------------

sub decode_to_hash {
    my ($self, $jwe) = @_;

    return decode_json($self->decode($jwe));
}

# -----------------------------------------------------------------------------

sub encode
{
    my ($self, $ciphertext, $enc, $key, $extra_headers, $alg ) = @_;

    $alg //= 'RSA1_5';

    # At the moment, only direct encryption with an agreed shared key is allowed
    croak "Unsupported alg value. Possible values are 'dir'."  unless $self->alg eq 'dir';

    my $enc_params = __allowed_enc->{$self->enc};

    croak "Unsupported enc value. Possible values are ".join( ', ', (keys &__allowed_enc) ) unless $enc_params;

    my $cipherType   = $enc_params->[0];
    my $keysize      = $enc_params->[1] / 8; # /8 to get it in bytes
    my $ivsize       = $enc_params->[2] / 8; # /8 to get it in bytes
    my $padding      = __crypt_padding_map->{ $enc_params->[3] };
    my $integrity_fn = $enc_params->[4];

    # Create initialisation vector
    # 
    my $iv = Crypt::CBC->random_bytes($ivsize);
    my $cipher = $self->_getCipher( $cipherType, $key, $padding, $iv, $keysize );
    my $ciphertext = $cipher->encrypt( $plaintext );

    my $header = {
        typ => 'JWE',
        alg => $self->alg,
        enc => $self->enc,
        %$extra_headers,
    };

    my $jwe_encryptedKey = ''; # Empty for 'dir' algorithm

    my @segment;
    push @segment, encode_base64url( encode_json($header) );
    push @segment, encode_base64url( $jwe_encryptedKey );
    push @segment, encode_base64url( $iv );
    push @segment, encode_base64url( $ciphertext );

    my $to_be_signed = join('.', @segment);

    my $icheck = encode_base64url( &$integrity_fn( $to_be_signed ) );

   return $to_be_signed.".$icheck"; 
}

# -----------------------------------------------------------------------------

sub encode_jwe
{
    local $Carp::CarpLevel = $Carp::CarpLevel + 1;
    __PACKAGE__->encode(@_);
}

# -----------------------------------------------------------------------------

sub decode
{
    my ($self, $jwe, $key) = @_;

    my @segment = split( /\./, $jwe );

    # Decode the header first, to see what we're dealing with
    #
    my $header = decode_json( decode_base64url( $segment[0] ) );

    croak "Cannot decode a non JWE message."  if $header->{typ} ne 'JWE';

    croak "Unsupported alg value. Acceptable values are 'dir'."  if $header->{alg} ne 'dir';

    my $enc_params = __allowed_enc->{$header->{enc}};

    croak "Unsupported enc value in JWE. JWE may be decoded with env values of ".join( ', ', (keys &__allowed_enc) ) unless $enc_params;
    my $jwe_encryptedKey = decode_base64url( $segment[1] );
    my $iv               = decode_base64url( $segment[2] );
    my $ciphertext       = decode_base64url( $segment[3] );
    my $icheckB64        = $segment[4];

    my $cipherType   = $enc_params->[0];
    my $keysize      = $enc_params->[1] / 8; # /8 to get it in bytes
    my $ivsize       = $enc_params->[2] / 8; # /8 to get it in bytes
    my $padding      = __crypt_padding_map->{ $enc_params->[3] };
    my $integrity_fn = $enc_params->[4];
    
    my $signed_section = substr( $jwe, 0, rindex($jwe, '.') );

    if( $icheckB64 ne encode_base64url( &$integrity_fn($signed_section) ) )
    {
        croak "Cannot decode JWE." ;
    }

    my $cipher = $self->_getCipher( $cipherType, $key, $padding, $iv, $keysize );
    my $plaintext = $cipher->decrypt( $ciphertext );

    return $plaintext;
}

# -----------------------------------------------------------------------------

sub decode_jwe
{
    local $Carp::CarpLevel = $Carp::CarpLevel + 1;
    __PACKAGE__->decode(@_);
}

# -----------------------------------------------------------------------------

sub _getCipher
{
    my ($self, $cipherType, $symetric_key, $padding, $iv, $keysize) = @_;
    my $cipher = Crypt::CBC->new( -literal_key => 1,
                                  -key         => $symetric_key,
                                  -keysize     => $keysize,
                                  -iv          => $iv,
                                  #-header      => 'salt', # Openssl Compatible
                                  -header      => 'none',
                                  -padding     => $padding,
                                  -cipher      => $cipherType
                                );
}

# -----------------------------------------------------------------------------
1;

__END__

=head1 NAME

JSON::WebEncryption - Perl JSON Web Encryption (JWE) implementation

=head1 DESCRIPTION



=cut
