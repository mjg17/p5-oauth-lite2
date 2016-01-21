package OAuth::Lite2::Client::WebServer;

use strict;
use warnings;
use parent 'OAuth::Lite2::Client';

use URI;
use Carp ();
use Params::Validate qw(HASHREF);
use OAuth::Lite2::Client::StateResponseParser;

=head1 NAME

OAuth::Lite2::Client::WebServer - OAuth 2.0 Web Server Profile Client

=head1 SYNOPSIS

    my $client = OAuth::Lite2::Client::WebServer->new(
        id               => q{my_client_id},
        secret           => q{my_client_secret},
        authorize_uri    => q{http://example.org/authorize},
        access_token_uri => q{http://example.org/token},
    );

    # redirect user to authorize page.
    sub start_authorize {
        my $your_app = shift;
        my $redirect_url = $client->uri_to_redirect(
            redirect_uri => q{http://yourapp/callback},
            scope        => q{photo},
            state        => q{optional_state},
        );

        $your_app->res->redirect( $redirect_url );
    }

    # this method corresponds to the url 'http://yourapp/callback'
    sub callback {
        my $your_app = shift;

        my $code = $your_app->request->param("code");

        my $access_token = $client->get_access_token(
            code         => $code,
            redirect_uri => q{http://yourapp/callback},
        ) or return $your_app->error( $client->errstr );

        $your_app->store->save( access_token  => $access_token->access_token  );
        $your_app->store->save( expires_at    => time() + $access_token->expires_in    );
        $your_app->store->save( refresh_token => $access_token->refresh_token );
    }

    sub refresh_access_token {
        my $your_app = shift;

        my $access_token = $client->refresh_access_token(
            refresh_token => $refresh_token,
        ) or return $your_app->error( $client->errstr );

        $your_app->store->save( access_token  => $access_token->access_token  );
        $your_app->store->save( expires_at    => time() + $access_token->expires_in    );
        $your_app->store->save( refresh_token => $access_token->refresh_token );
    }


    sub access_to_protected_resource {
        my $your_app = shift;

        my $access_token  = $your_app->store->get("access_token");
        my $expires_at    = $your_app->store->get("expires_at");
        my $refresh_token = $your_app->store->get("refresh_token");

        unless ($access_token) {
            $your_app->start_authorize();
            return;
        }

        if ($expires_at < time()) {
            $your_app->refresh_access_token();
            return;
        }

        my $req = HTTP::Request->new( GET => q{http://example.org/photo} );
        $req->header( Authorization => sprintf(q{OAuth %s}, $access_token) );
        my $agent = LWP::UserAgent->new;
        my $res = $agent->request($req);
        ...
    }


=head1 DESCRIPTION

Client library for OAuth 2.0 Web Server Profile.

=head1 METHODS

=head2 new( %params )

=over 4

=item id

Client ID

=item secret

Client secret

=item authorize_uri

authorization page uri on auth-server.

=item access_token_uri

token endpoint uri on auth-server.

=item refresh_token_uri

refresh-token endpoint uri on auth-server.
if you omit this, access_token_uri is used instead.

=item agent

user agent. if you omit this, LWP::UserAgent's object is set by default.
You can use your custom agent or preset-agents.

See also

L<OAuth::Lite2::Agent::Dump>
L<OAuth::Lite2::Agent::Strict>
L<OAuth::Lite2::Agent::PSGIMock>

=back

=cut

sub new {

    my $class = shift;

    my $self = $class->SUPER::new(@_);

    $self->{state_response_parser} = OAuth::Lite2::Client::StateResponseParser->new;

    return $self;
}

sub _param_spec_for_new {
    my $class = shift;

    return {
        %{$class->SUPER::_param_spec_for_new},
        authorize_uri => { default => undef },
    };
}

=head2 uri_to_redirect( %params )

=cut

sub uri_to_redirect {
    my $self = shift;
    my %args = Params::Validate::validate(@_, {
        redirect_uri => 1,
        state        => { optional => 1 },
        scope        => { optional => 1 },
        immediate    => { optional => 1 },
        uri          => { optional => 1 },
        extra        => { optional => 1, type => HASHREF },
    });

    my %params = (
        response_type => 'code',
        client_id     => $self->{id},
        redirect_uri  => $args{redirect_uri},
    );
    $params{state}     = $args{state}     if $args{state};
    $params{scope}     = $args{scope}     if $args{scope};
    $params{immediate} = $args{immediate} if $args{immediate};

    if ($args{extra}) {
        for my $key ( keys %{$args{extra}} ) {
            $params{$key} = $args{extra}{$key};
        }
    }

    my $uri = $args{uri}
        || $self->{authorize_uri}
        || Carp::croak "uri not found";

    $uri = URI->new($uri);
    $uri->query_form(%params);
    return $uri->as_string;
}

=head2 get_access_token( %params )

execute verification,
and returns L<OAuth::Lite2::Client::Token> object.

=over 4

=item code

Authorization-code that is issued beforehand by server

=item redirect_uri

The URL that has used for user authorization's callback

=back

=cut

sub get_access_token {
    my $self = shift;

    my %args = Params::Validate::validate(@_, {
        code            => 1,
        redirect_uri    => 1,
        server_state    => { optional => 1 },
        uri             => { optional => 1 },
        use_basic_schema    => { optional => 1 },
        # secret_type => { optional => 1 },
        # format      => { optional => 1 },
    });

    my %params = (
        grant_type    => 'authorization_code',
        code          => $args{code},
        redirect_uri  => $args{redirect_uri},
    );
    $params{server_state} = $args{server_state} if $args{server_state};

    # $params{secret_type} = $args{secret_type}
    #    if $args{secret_type};

    return $self->_get_token(\%params, %args);
}

=head2 get_server_state

Obtain L<OAuth::Lite2::Client::ServerState> object.

=cut

sub get_server_state {
    my $self = shift;

    my %args = Params::Validate::validate(@_, {
        uri           => { optional => 1 },
    });

    my %params = (
        grant_type => 'server_state',
        client_id  => $self->{id},
    );

    $args{response_parser} = $self->{state_response_parser};

    return $self->_get_token(\%params, %args);
}

=head1 AUTHOR

Ryo Ito, E<lt>ritou.06@gmail.comE<gt>

Lyo Kato, E<lt>lyo.kato@gmail.comE<gt>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2010 by Lyo Kato

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.8.8 or,
at your option, any later version of Perl 5 you may have available.

=cut

1;
