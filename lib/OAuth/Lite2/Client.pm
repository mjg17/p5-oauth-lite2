package OAuth::Lite2::Client;
use strict;
use warnings;
use parent 'Class::ErrorHandler';

use LWP::UserAgent;
use Params::Validate;
use OAuth::Lite2;
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

=head1 AUTHOR

Lyo Kato, E<lt>lyo.kato@gmail.comE<gt>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2010 by Lyo Kato

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.8.8 or,
at your option, any later version of Perl 5 you may have available.

=cut

1;
