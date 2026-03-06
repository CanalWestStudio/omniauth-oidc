# frozen_string_literal: true

if ENV["COVERAGE"]
  require "simplecov"
  SimpleCov.start do
    add_filter "/test/"
  end
end

$LOAD_PATH.unshift File.expand_path("../lib", __dir__)
require "omniauth-oidc"

require "minitest/autorun"
require "webmock/minitest"
require "rack/test"
require "json"
require "openssl"

# Silence OmniAuth logger during tests
OmniAuth.config.logger = Logger.new("/dev/null")
# Allow GET requests in tests to simplify test setup
OmniAuth.config.allowed_request_methods = [:post, :get]
OmniAuth.config.silence_get_warning = true
# Disable CSRF protection in tests
OmniAuth.config.request_validation_phase = nil

module OidcTestHelper
  ISSUER = "https://provider.example.com"
  CLIENT_ID = "test-client-id"
  CLIENT_SECRET = "test-client-secret"
  CONFIG_ENDPOINT = "#{ISSUER}/.well-known/openid-configuration"

  def build_app(strategy_opts = {})
    default_opts = {
      name: :test_oidc,
      client_options: {
        identifier: CLIENT_ID,
        secret: CLIENT_SECRET,
        config_endpoint: CONFIG_ENDPOINT
      }
    }
    merged = deep_merge(default_opts, strategy_opts)

    app = lambda { |env|
      [200, { "Content-Type" => "text/plain" }, ["OK"]]
    }

    OmniAuth::Strategies::Oidc.new(app, merged)
  end

  def make_request(strategy, path, params: {}, session: {}, method: "GET")
    query = URI.encode_www_form(params)
    url = "http://example.com#{path}"
    url += "?#{query}" unless query.empty?

    env = Rack::MockRequest.env_for(url, "REQUEST_METHOD" => method)
    env["rack.session"] = session
    env["omniauth.strategy"] = strategy

    strategy.call!(env)
    env
  end

  def openid_configuration(overrides = {})
    {
      issuer: ISSUER,
      authorization_endpoint: "#{ISSUER}/authorize",
      token_endpoint: "#{ISSUER}/token",
      userinfo_endpoint: "#{ISSUER}/userinfo",
      jwks_uri: "#{ISSUER}/jwks",
      end_session_endpoint: "#{ISSUER}/logout",
      scopes_supported: ["openid", "email", "profile"]
    }.merge(overrides)
  end

  def stub_config_endpoint(config = openid_configuration)
    stub_request(:get, CONFIG_ENDPOINT)
      .to_return(
        status: 200,
        body: config.to_json,
        headers: { "Content-Type" => "application/json" }
      )
  end

  def stub_jwks_endpoint(jwk_set)
    stub_request(:get, "#{ISSUER}/jwks")
      .to_return(
        status: 200,
        body: jwk_set.to_json,
        headers: { "Content-Type" => "application/json" }
      )
  end

  def stub_token_endpoint(id_token: nil, access_token: "test-access-token")
    token_response = {
      access_token: access_token,
      token_type: "Bearer",
      expires_in: 3600,
      id_token: id_token
    }.compact
    stub_request(:post, "#{ISSUER}/token")
      .to_return(
        status: 200,
        body: token_response.to_json,
        headers: { "Content-Type" => "application/json" }
      )
  end

  def stub_userinfo_endpoint(user_info = {})
    default_info = {
      sub: "user-123",
      name: "Test User",
      email: "test@example.com",
      email_verified: true,
      given_name: "Test",
      family_name: "User"
    }
    stub_request(:get, "#{ISSUER}/userinfo")
      .to_return(
        status: 200,
        body: default_info.merge(user_info).to_json,
        headers: { "Content-Type" => "application/json" }
      )
  end

  def generate_rsa_keypair
    key = OpenSSL::PKey::RSA.generate(2048)
    jwk = JSON::JWK.new(key, kid: "test-key-1")
    [key, jwk]
  end

  def generate_id_token(claims, key, algorithm: :RS256, kid: "test-key-1")
    jwt = JSON::JWT.new(claims)
    jwt.header[:kid] = kid
    jwt.sign(key, algorithm).to_s
  end

  def standard_id_token_claims(overrides = {})
    {
      iss: ISSUER,
      sub: "user-123",
      aud: CLIENT_ID,
      exp: Time.now.to_i + 3600,
      iat: Time.now.to_i,
      nonce: "test-nonce"
    }.merge(overrides)
  end

  def generate_self_signed_cert(key)
    cert = OpenSSL::X509::Certificate.new
    cert.version = 2
    cert.serial = 1
    cert.subject = OpenSSL::X509::Name.parse("/CN=test")
    cert.issuer = cert.subject
    cert.public_key = key.public_key
    cert.not_before = Time.now - 3600
    cert.not_after = Time.now + 3600
    cert.sign(key, OpenSSL::Digest.new("SHA256"))
    cert
  end

  private

  def deep_merge(hash1, hash2)
    hash1.merge(hash2) do |_key, old_val, new_val|
      if old_val.is_a?(Hash) && new_val.is_a?(Hash)
        deep_merge(old_val, new_val)
      else
        new_val
      end
    end
  end
end
