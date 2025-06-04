# frozen_string_literal: true

$LOAD_PATH.unshift File.expand_path("../lib", __dir__)
require "omniauth-oidc"

require "minitest/autorun"
require "minitest/mock"
require "webmock/minitest"
require "rack/test"

# Disable real HTTP requests
WebMock.disable_net_connect!

module TestHelpers
  # Intuit OIDC configuration for testing
  def intuit_oidc_config
    @intuit_oidc_config ||= {
      "issuer" => "https://oauth.platform.intuit.com/op/v1",
      "authorization_endpoint" => "https://appcenter.intuit.com/connect/oauth2",
      "token_endpoint" => "https://oauth.platform.intuit.com/oauth2/v1/tokens/bearer",
      "userinfo_endpoint" => "https://accounts.platform.intuit.com/v1/openid_connect/userinfo",
      "jwks_uri" => "https://oauth.platform.intuit.com/op/v1/jwks",
      "end_session_endpoint" => "https://oauth.platform.intuit.com/op/v1/logout",
      "scopes_supported" => ["openid", "profile", "email", "phone", "address"],
      "response_types_supported" => ["code", "id_token"],
      "subject_types_supported" => ["public"],
      "id_token_signing_alg_values_supported" => ["RS256"]
    }
  end

  def intuit_jwks
    @intuit_jwks ||= {
      "keys" => [
        {
          "kty" => "RSA",
          "kid" => "test-key-id",
          "use" => "sig",
          "alg" => "RS256",
          "n" => "test-modulus",
          "e" => "AQAB"
        }
      ]
    }
  end

  def sample_id_token_payload
    {
      "sub" => "test-user-123",
      "aud" => "test-client-id",
      "iss" => "https://oauth.platform.intuit.com/op/v1",
      "exp" => (Time.now + 3600).to_i,
      "iat" => Time.now.to_i,
      "nonce" => "test-nonce",
      "email" => "test@example.com",
      "email_verified" => true,
      "given_name" => "Test",
      "family_name" => "User",
      "realmId" => "123456789"
    }
  end

  def sample_token_response
    {
      "access_token" => "test-access-token",
      "token_type" => "Bearer",
      "expires_in" => 3600,
      "refresh_token" => "test-refresh-token",
      "id_token" => "test-id-token"
    }
  end

  def sample_userinfo_response
    {
      "sub" => "test-user-123",
      "email" => "test@example.com",
      "email_verified" => true,
      "given_name" => "Test",
      "family_name" => "User",
      "name" => "Test User",
      "picture" => "https://example.com/avatar.jpg"
    }
  end

  def mock_intuit_endpoints!
    # Mock discovery endpoint
    stub_request(:get, "https://oauth.platform.intuit.com/.well-known/openid_connect/configuration")
      .to_return(
        status: 200,
        body: intuit_oidc_config.to_json,
        headers: { 'Content-Type' => 'application/json' }
      )

    # Mock JWKS endpoint
    stub_request(:get, "https://oauth.platform.intuit.com/op/v1/jwks")
      .to_return(
        status: 200,
        body: intuit_jwks.to_json,
        headers: { 'Content-Type' => 'application/json' }
      )

    # Mock token endpoint
    stub_request(:post, "https://oauth.platform.intuit.com/oauth2/v1/tokens/bearer")
      .to_return(
        status: 200,
        body: sample_token_response.to_json,
        headers: { 'Content-Type' => 'application/json' }
      )

    # Mock userinfo endpoint
    stub_request(:get, "https://accounts.platform.intuit.com/v1/openid_connect/userinfo")
      .with(headers: { 'Authorization' => 'Bearer test-access-token' })
      .to_return(
        status: 200,
        body: sample_userinfo_response.to_json,
        headers: { 'Content-Type' => 'application/json' }
      )
  end

  def build_omniauth_env(path = "/auth/oidc", params = {})
    Rack::MockRequest.env_for(path, params)
  end

  def build_callback_env(code: "test-code", state: "test-state")
    build_omniauth_env("/auth/oidc/callback", {
      'REQUEST_METHOD' => 'GET',
      'QUERY_STRING' => "code=#{code}&state=#{state}"
    })
  end

  def default_oidc_options
    # Create properly structured options that match OmniAuth's structure
    options = OpenStruct.new({
      name: :oidc,
      scope: ['openid', 'profile', 'email'],
      response_type: 'code',
      require_state: true,
      send_nonce: true,
      fetch_user_info: true,
      pkce: false,
      logout_path: '/logout'
    })

    # Create client_options as OpenStruct so it responds to method calls
    options.client_options = OpenStruct.new({
      identifier: 'test-client-id',
      secret: 'test-client-secret',
      config_endpoint: 'https://oauth.platform.intuit.com/.well-known/openid_connect/configuration',
      scheme: 'https',
      port: 443
    })

    options
  end
end

# Include helpers in all test classes
class Minitest::Test
  include TestHelpers
end
