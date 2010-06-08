package OAuth::Lite2::Server::Action::Token::ClientCredentials;

use strict;
use warnings;

use parent 'OAuth::Lite2::Server::Action::Token';
use OAuth::Lite2::Error;

sub handle_request {
    my ($self, $ctx) = @_;

    my $dh  = $ctx->data_handler;
    my $req = $ctx->request;

    my $client_id = $req->param("client_id");
    OAuth::Lite2::Error::Server::MissingParam->throw(
        message => "'client_id' not found"
    ) unless $client_id;

    my $client_secret = $req->param("client_secret");
    OAuth::Lite2::Error::Server::MissingParam->throw(
        message => "'client_secret' not found"
    ) unless $client_secret;

    my $user_id = $dh->get_client_user_id($client_id, $client_secret)
        or OAuth::Lite2::Error::Server::InvalidClient->throw;

    my $scope = $req->param("scope");

    my $auth_info = $dh->create_or_update_auth_info(
        client_id => $client_id,
        user_id   => $user_id,
        scope     => $scope,
    );
    # TODO check returned $auth_info?

    my $secret_type = $req->param("secret_type");

    my $access_token = $dh->create_or_update_access_token(
        auth_info   => $auth_info,
        secret_type => $secret_type,
    );
    # TODO check returned $access_token?

    my $res = {
        access_token => $access_token->token,
    };
    $res->{expires_in} = $access_token->expires_in
        if $access_token->expires_in;
    $res->{access_token_secret} = $access_token->secret
        if $access_token->secret;
    $res->{refresh_token} = $auth_info->refresh_token
        if $auth_info->refresh_token;
    $res->{scope} = $auth_info->scope
        if $auth_info->scope;
    $res->{secret_type} = $secret_type
        if $secret_type;

    return $res;
}

1;
