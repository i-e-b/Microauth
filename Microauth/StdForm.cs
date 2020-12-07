﻿// ReSharper disable StringLiteralTypo

namespace Microauth
{
    public static class StdForm
    {
        public static string SignInPage(string? redirect, string state, string code)
        {
            return $@"<html>
<head>
    <title>Sign In</title>
</head>
<body>

<span>Loading...</span>

<form id='appForm' method='post' name='oauthResponse' action='{redirect}'>
    <input type='hidden' name='state' value='{state}'/>
    <input type='hidden' name='code' value='{code}'/>
    </form>

<script type='text/javascript'>
    setTimeout(function () {{
        document.forms.oauthResponse.submit();
    }});
</script>

</body>
</html>
".Replace('\'', '"');
        }

        public static string OauthConfig()
        {
            return @"{
    'issuer': 'https://localhost:6080/oauth2/default',
    'authorization_endpoint': 'https://localhost:6080/oauth2/default/v1/authorize',
    'token_endpoint': 'https://localhost:6080/oauth2/default/v1/token',
    'userinfo_endpoint': 'https://localhost:6080/oauth2/default/v1/userinfo',
    'registration_endpoint': 'https://localhost:6080/oauth2/v1/clients',
    'jwks_uri': 'https://localhost:6080/oauth2/default/v1/keys',
    'response_types_supported': [
        'code',
        'id_token',
        'code id_token',
        'code token',
        'id_token token',
        'code id_token token'
    ],
    'response_modes_supported': [
        'query',
        'fragment',
        'form_post',
        'okta_post_message'
    ],
    'grant_types_supported': [
        'authorization_code',
        'implicit',
        'refresh_token',
        'password'
    ],
    'subject_types_supported': [
        'public'
    ],
    'id_token_signing_alg_values_supported': [
        'RS256'
    ],
    'scopes_supported': [
        'openid',
        'profile',
        'email',
        'address',
        'phone',
        'offline_access'
    ],
    'token_endpoint_auth_methods_supported': [
        'client_secret_basic',
        'client_secret_post',
        'client_secret_jwt',
        'private_key_jwt',
        'none'
    ],
    'claims_supported': [
        'iss',
        'ver',
        'sub',
        'aud',
        'iat',
        'exp',
        'jti',
        'auth_time',
        'amr',
        'idp',
        'nonce',
        'name',
        'nickname',
        'preferred_username',
        'given_name',
        'middle_name',
        'family_name',
        'email',
        'email_verified',
        'profile',
        'zoneinfo',
        'locale',
        'address',
        'phone_number',
        'picture',
        'website',
        'gender',
        'birthdate',
        'updated_at',
        'at_hash',
        'c_hash'
    ],
    'code_challenge_methods_supported': [
        'S256'
    ],
    'introspection_endpoint': 'https://localhost:6080/oauth2/default/v1/introspect',
    'introspection_endpoint_auth_methods_supported': [
        'client_secret_basic',
        'client_secret_post',
        'client_secret_jwt',
        'private_key_jwt',
        'none'
    ],
    'revocation_endpoint': 'https://localhost:6080/oauth2/default/v1/revoke',
    'revocation_endpoint_auth_methods_supported': [
        'client_secret_basic',
        'client_secret_post',
        'client_secret_jwt',
        'private_key_jwt',
        'none'
    ],
    'end_session_endpoint': 'https://localhost:6080/oauth2/default/v1/logout',
    'request_parameter_supported': true,
    'request_object_signing_alg_values_supported': [
        'HS256',
        'HS384',
        'HS512',
        'RS256',
        'RS384',
        'RS512',
        'ES256',
        'ES384',
        'ES512'
    ]
}".Replace('\'', '"');
        }
    }
}