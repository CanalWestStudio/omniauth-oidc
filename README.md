# OmniAuth::Oidc

An OmniAuth strategy for OpenID Connect (OIDC) authentication. Supports multiple OIDC providers, PKCE, RP-Initiated Logout, and automatic discovery via the provider's configuration endpoint.

Requires Ruby 3.1+.

## Installation

    $ bundle add omniauth-oidc

Or install directly:

    $ gem install omniauth-oidc

## Configuration

You need a Client ID, Client Secret, and the OIDC configuration endpoint URL at minimum.

```ruby
# config/initializers/omniauth.rb
Rails.application.config.middleware.use OmniAuth::Builder do
  provider :oidc, {
    name: :my_provider,
    client_options: {
      identifier: ENV["MY_PROVIDER_CLIENT_ID"],
      secret: ENV["MY_PROVIDER_CLIENT_SECRET"],
      config_endpoint: "https://provider.example.com/.well-known/openid-configuration"
    }
  }
end
```

With Devise:

```ruby
Devise.setup do |config|
  config.omniauth :oidc, {
    name: :my_provider,
    scope: [:openid, :email, :profile],
    uid_field: "preferred_username",
    client_options: {
      identifier: ENV["MY_PROVIDER_CLIENT_ID"],
      secret: ENV["MY_PROVIDER_CLIENT_SECRET"],
      config_endpoint: "https://provider.example.com/.well-known/openid-configuration"
    }
  }
end
```

The gem fetches authorization, token, userinfo, and JWKS endpoints automatically from the `config_endpoint`. You can override any of them explicitly in `client_options` if needed.

The gem does not accept `redirect_uri` as a configurable option — it is built dynamically from the provider `name` (see [Routes](#routes)).

### All Options

| Option | Description | Default |
|---|---|---|
| `name` | Provider identifier, used in route paths | `:oidc` |
| `issuer` | Expected token issuer | Fetched from `config_endpoint` |
| `scope` | OIDC scopes | `[:openid]` |
| `response_type` | `"code"` or `"id_token"` | `"code"` |
| `response_mode` | `:query`, `:fragment`, `:form_post`, or `:web_message` | `nil` |
| `display` | `:page`, `:popup`, `:touch`, or `:wap` | `nil` |
| `prompt` | `:none`, `:login`, `:consent`, or `:select_account` | `nil` |
| `require_state` | Verify the `state` parameter on callbacks | `true` |
| `state` | Custom state value or a `Proc` that returns one | Random 16-byte hex |
| `send_nonce` | Include a nonce in the authorization request | `true` |
| `fetch_user_info` | Fetch user info from the userinfo endpoint | `true` |
| `uid_field` | User info field to use as `uid` | `"sub"` |
| `send_scope_to_token_endpoint` | Include scope in the token request | `true` |
| `client_auth_method` | Auth method for the token endpoint (e.g. `:basic`, `:jwks`) | `:basic` |
| `pkce` | Enable PKCE (S256) | `false` |
| `pkce_verifier` | Custom PKCE verifier `Proc` | Random 128-char hex |
| `pkce_options` | Custom code challenge generation `Proc` and method | SHA256 / `"S256"` |
| `extra_authorize_params` | Hash of extra params merged into the authorization request | `{}` |
| `allow_authorize_params` | List of dynamic param keys allowed from the request | `[]` |
| `acr_values` | Authentication Class Reference values ([RFC 9470](https://www.rfc-editor.org/rfc/rfc9470.html)) | `nil` |
| `logout_path` | Path that triggers RP-Initiated Logout | `"/logout"` |
| `post_logout_redirect_uri` | Where to redirect after provider logout | `nil` |
| `client_signing_alg` | Expected JWT signing algorithm (e.g. `:RS256`) | `nil` (any) |
| `jwt_secret_base64` | Base64-encoded secret for HMAC signing algorithms | `client_options.secret` |
| `client_jwk_signing_key` | JWK key for JWT verification | `nil` |
| `client_x509_signing_key` | X.509 certificate for JWT verification | `nil` |

### Client Options

| Option | Description | Default |
|---|---|---|
| `identifier` | OAuth 2.0 client ID | **required** |
| `secret` | OAuth 2.0 client secret | **required** |
| `config_endpoint` | OIDC discovery endpoint URL | **required** |
| `scheme` | HTTP scheme | `"https"` |
| `host` | Authorization server host | From `config_endpoint` |
| `port` | Authorization server port | `443` |
| `authorization_endpoint` | Override discovered authorize URL | From `config_endpoint` |
| `token_endpoint` | Override discovered token URL | From `config_endpoint` |
| `userinfo_endpoint` | Override discovered userinfo URL | From `config_endpoint` |
| `jwks_uri` | Override discovered JWKS URL | From `config_endpoint` |
| `end_session_endpoint` | Provider logout URL | From `config_endpoint` |
| `environment` | Custom environment param sent with authorization requests | `nil` |

## Routes

The callback URL follows the pattern `https://your-app.com/auth/<name>/callback`, where `<name>` is the provider name from your configuration. Register this URL with your OIDC provider as an allowed redirect URI.

```ruby
# config/routes.rb
Rails.application.routes.draw do
  match "auth/:provider/callback", to: "callbacks#omniauth", via: [:get, :post]
end
```

To initiate authentication, use a POST link (OmniAuth requires POST for CSRF protection):

```ruby
<%= button_to "Login with My Provider", "/auth/my_provider" %>
```

## Handling Callbacks

```ruby
class CallbacksController < ApplicationController
  def omniauth
    auth = request.env["omniauth.auth"]

    user = User.find_or_create_by(uid: auth["uid"]) do |u|
      u.name = auth["info"]["name"]
      u.email = auth["info"]["email"]
    end

    session[:user_id] = user.id
    redirect_to root_path, notice: "Logged in"
  end
end
```

### Access Token Only (No User Info)

Set `fetch_user_info: false` to skip the userinfo endpoint. The callback will contain only credentials:

```ruby
provider :oidc, {
  name: :my_provider,
  fetch_user_info: false,
  client_options: {
    identifier: ENV["MY_PROVIDER_CLIENT_ID"],
    secret: ENV["MY_PROVIDER_CLIENT_SECRET"],
    config_endpoint: "https://provider.example.com/.well-known/openid-configuration"
  }
}
```

```ruby
# request.env["omniauth.auth"] will contain:
# {
#   "provider" => :my_provider,
#   "credentials" => {
#     "id_token" => "...",
#     "token" => "...",
#     "refresh_token" => "...",
#     "expires_in" => 300,
#     "scope" => nil
#   }
# }
```

## RP-Initiated Logout

To log the user out of both your application and the OIDC provider, configure `logout_path` and `end_session_endpoint`:

```ruby
provider :oidc, {
  name: :my_provider,
  logout_path: "/logout",
  post_logout_redirect_uri: "https://your-app.com/signed_out",
  client_options: {
    identifier: ENV["MY_PROVIDER_CLIENT_ID"],
    secret: ENV["MY_PROVIDER_CLIENT_SECRET"],
    config_endpoint: "https://provider.example.com/.well-known/openid-configuration",
    end_session_endpoint: "https://provider.example.com/signout"
  }
}
```

When a request matches `logout_path`, the gem redirects to the provider's `end_session_endpoint` with `id_token_hint` (from the session) and `post_logout_redirect_uri` if configured.

The `end_session_endpoint` can also be discovered automatically from the `config_endpoint` if the provider advertises it.

See the [OIDC RP-Initiated Logout spec](https://openid.net/specs/openid-connect-rpinitiated-1_0.html) for details.

## Security

### What the gem handles

- **TLS 1.2+** — All HTTP requests enforce a minimum of TLS 1.2, allowing TLS 1.3 negotiation
- **State validation** — The `state` parameter is verified on callbacks to prevent CSRF (enabled by default)
- **Nonce verification** — A session-stored nonce is used for ID token verification; nonces from request params are never accepted
- **PKCE** — Proof Key for Code Exchange (S256) is available via `pkce: true`
- **Security headers** — All redirects include `Cache-Control: no-cache, no-store`, `Pragma: no-cache`, and `Referrer-Policy: no-referrer`
- **RP-Initiated Logout** — Sends `id_token_hint` with end-session requests per the OIDC spec
- **No `open-uri`** — The gem avoids `Kernel.open` by using Faraday for all HTTP

### Host application responsibilities

**Session and cookie security:**
- Configure session cookies with `Secure`, `HttpOnly`, and `SameSite=Lax` (or `Strict`)
- In Rails: `config.session_store :cookie_store, secure: true, httponly: true, same_site: :lax`

**HTTPS:**
- Enforce HTTPS on all pages
- In Rails: `config.force_ssl = true`

**Token storage:**
- Encrypt refresh tokens at rest if persisted (e.g. AES-256-GCM)
- Store encryption keys separately from encrypted data
- Never log OAuth tokens or user credentials

**Input handling:**
- Sanitize user info from the OIDC provider before rendering in views
- Use parameterized queries when storing user data

### Reporting vulnerabilities

If you discover a security vulnerability, please report it privately via [GitHub Security Advisories](https://github.com/CanalWestStudio/omniauth-oidc/security/advisories) rather than opening a public issue.

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/CanalWestStudio/omniauth-oidc. Contributors are expected to adhere to the [code of conduct](https://github.com/CanalWestStudio/omniauth-oidc/blob/main/CODE_OF_CONDUCT.md).

## License

Available as open source under the terms of the [MIT License](https://opensource.org/licenses/MIT).
