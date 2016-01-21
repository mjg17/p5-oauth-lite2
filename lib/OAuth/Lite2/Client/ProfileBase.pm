package OAuth::Lite2::Client::ProfileBase;
use strict;
use warnings;
use parent 'Class::ErrorHandler';
use bytes ();

use Carp ();
use Try::Tiny qw/try catch/;
use HTTP::Request;
use HTTP::Headers;
use LWP::UserAgent;
use Params::Validate;
use OAuth::Lite2;
use OAuth::Lite2::Util qw(build_content);
use OAuth::Lite2::Client::TokenResponseParser;

=head1 NAME

OAuth::Lite2::Client::ProfileBase - Common parent for OAuth::Lite2::Client::*

=cut

sub new {

    my $class = shift;

    my %args = Params::Validate::validate(@_, $class->_param_spec_for_new);

    my $self = bless {
        last_request      => undef,
        last_response     => undef,
        %args,
    }, $class;

    unless ($self->{agent}) {
        $self->{agent} = LWP::UserAgent->new;
        $self->{agent}->agent(
            join "/", __PACKAGE__, $OAuth::Lite2::VERSION);
    }

    $self->{response_parser} = OAuth::Lite2::Client::TokenResponseParser->new;

    return $self;
}

sub _param_spec_for_new {
    my $class = shift;

    return {
        id                 => 1,
        secret             => 1,
        authorize_uri      => { default => undef },
        access_token_uri   => { default => undef },
        refresh_token_uri  => { default => undef }, # unused?
        agent              => { default => undef },
    };
}

sub _get_token {
    my ($self, $params, %args) = @_;

    unless (exists $args{uri}) {
        $args{uri} = $self->{access_token_uri}
            || Carp::croak "uri not found";
    }

    # $args{format} ||= $self->{format};
    # $params->{format} = $args{format};

    unless ($args{use_basic_schema}){
        $params->{client_id}      = $self->{id};
        $params->{client_secret}  = $self->{secret};
    }

    my $content = build_content($params);
    my $headers = HTTP::Headers->new;
    $headers->header("Content-Type" => q{application/x-www-form-urlencoded});
    $headers->header("Content-Length" => bytes::length($content));
    $headers->authorization_basic($self->{id}, $self->{secret})
        if($args{use_basic_schema});
    my $req = HTTP::Request->new( POST => $args{uri}, $headers, $content );

    my $res = $self->{agent}->request($req);
    $self->{last_request}  = $req;
    $self->{last_response} = $res;

    my $response_parser = $args{response_parser};
    $response_parser ||= $self->{response_parser};

    my ($token, $errmsg);
    try {
        $token = $response_parser->parse($res);
    } catch {
        $errmsg = "$_";
    };
    return $token || $self->error($errmsg);
}

=head2 refresh_access_token( %params )

Refresh access token by refresh_token,
returns L<OAuth::Lite2::Client::Token> object.

=over 4

=item refresh_token

=back

=cut

sub refresh_access_token {
    my $self = shift;

    my %args = Params::Validate::validate(@_, {
        refresh_token => 1,
        uri           => { optional => 1 },
        use_basic_schema    => { optional => 1 },
        # secret_type => { optional => 1 },
    });

    # This should use refresh_token_uri, and fall through to access_token_uri
    unless (exists $args{uri}) {
        $args{uri} = $self->{access_token_uri}
            || Carp::croak "uri not found";
    }

    my %params = (
        grant_type    => 'refresh_token',
        refresh_token => $args{refresh_token},
    );

    # $params{secret_type} = $args{secret_type}
    #     if $args{secret_type};

    return $self->_get_token(\%params, %args);
}

=head2 last_request

Returns a HTTP::Request object that is used
when you obtain or refresh access token last time internally.

=head2 last_request

Returns a HTTP::Response object that is used
when you obtain or refresh access token last time internally.

=cut

sub last_request  { $_[0]->{last_request}  }
sub last_response { $_[0]->{last_response} }

=head1 AUTHOR

Lyo Kato, E<lt>lyo.kato@gmail.comE<gt>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2010 by Lyo Kato

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.8.8 or,
at your option, any later version of Perl 5 you may have available.

=cut

1;