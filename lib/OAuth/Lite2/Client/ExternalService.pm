package OAuth::Lite2::Client::ExternalService;

use strict;
use warnings;
use parent 'OAuth::Lite2::Client::ProfileBase';

use Params::Validate;

=head1 NAME

OAuth::Lite2::Client::ExternalService - OAuth 2.0 Federated Assertion Profile Client

=head1 SYNOPSIS

    my $client = OAuth::Lite2::Client::ExternalService->new(
        id               => q{my_client_id},
        secret           => q{my_client_secret},
        access_token_uri => q{http://example.org/token},
    );

    sub get_access_token {
        my $your_app = shift;

        my $access_token = $client->get_access_token(
            assertion => $your_app->request->param("assertion"), 
            scope     => q{photo}, 
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
            $your_app->show_reauthorize_page();
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

OAuth 2.0 Federated Assertion Profile Client.


=head2 new( %params )

=over 4

=item id

Client ID

=item secret

Client secret

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

=head2 get_access_token( %params )

=over 4

=item assertion

=item type

=item iss

=item aud

=item scope

=back

=cut

sub get_access_token {
    my $self = shift;

    my %args = Params::Validate::validate(@_, {
        assertion        => 1,
        type   => { optional => 1 },
        iss    => { optional => 1 },
        aud    => { optional => 1 },
        scope            => { optional => 1 },
        uri              => { optional => 1 },
        use_basic_schema => { optional => 1 },
    });

    my %params = (
        grant_type => 'external_service',
        assertion  => $args{assertion},
    );

    # optional params
    $params{type} = $args{type}
        if $args{type};
    $params{iss} = $args{iss}
        if $args{iss};
    $params{aud} = $args{aud}
        if $args{aud};
    $params{scope} = $args{scope}
        if $args{scope};

    return $self->_get_token(\%params, %args);
}

=head1 AUTHOR

Ryo Ito, E<lt>ritou.06@gmail.comE<gt>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2014 by Ryo Ito

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.8.8 or,
at your option, any later version of Perl 5 you may have available.

=cut

1;
