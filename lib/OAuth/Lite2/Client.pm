package OAuth::Lite2::Client;
use strict;
use warnings;
use parent 'Class::ErrorHandler';

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

OAuth::Lite2::Client - Common parent for OAuth::Lite2::Client::*

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

    my ($token, $errmsg);
    try {
        $token = $self->{response_parser}->parse($res);
    } catch {
        $errmsg = "$_";
    };
    return $token || $self->error($errmsg);
}

=head1 AUTHOR

Lyo Kato, E<lt>lyo.kato@gmail.comE<gt>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2010 by Lyo Kato

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.8.8 or,
at your option, any later version of Perl 5 you may have available.

=cut

1;
