# frozen_string_literal: true

require "test_helper"

class TestVerify < Minitest::Test
  include OidcTestHelper

  def setup
    @key, @jwk = generate_rsa_keypair
    @jwk_set = { keys: [@jwk] }
    OmniAuth::Strategies::Oidc::Transport.reset!
  end

  def test_decode_id_token_with_rs256
    strategy = build_app
    stub_config_endpoint
    stub_jwks_endpoint(@jwk_set)
    init_strategy(strategy)

    id_token = generate_id_token(standard_id_token_claims, @key)
    decoded = strategy.send(:decode_id_token, id_token)

    assert_equal "user-123", decoded.sub
    assert_equal ISSUER, decoded.iss
  end

  def test_decode_id_token_with_hs256
    secret = "super-secret-key-for-hmac-testing"
    strategy = build_app(client_options: { secret: secret })
    stub_config_endpoint
    init_strategy(strategy)

    claims = standard_id_token_claims
    jwt = JSON::JWT.new(claims)
    id_token = jwt.sign(secret, :HS256).to_s

    decoded = strategy.send(:decode_id_token, id_token)
    assert_equal "user-123", decoded.sub
  end

  def test_validate_client_algorithm_raises_on_mismatch
    strategy = build_app(client_signing_alg: :RS256)
    stub_config_endpoint
    init_strategy(strategy)

    error = assert_raises(OmniAuth::Strategies::Oidc::CallbackError) do
      strategy.send(:validate_client_algorithm!, :HS256)
    end

    assert_equal :invalid_jwt_algorithm, error.error
    assert_includes error.message, "HS256"
    assert_includes error.message, "RS256"
  end

  def test_validate_client_algorithm_passes_when_matching
    strategy = build_app(client_signing_alg: :RS256)
    init_strategy(strategy)

    # Should not raise
    strategy.send(:validate_client_algorithm!, :RS256)
  end

  def test_validate_client_algorithm_skips_when_not_configured
    strategy = build_app
    init_strategy(strategy)

    # Should not raise when client_signing_alg is nil
    strategy.send(:validate_client_algorithm!, :RS256)
  end

  def test_verify_id_token_uses_stored_nonce_not_params
    strategy = build_app
    stub_config_endpoint
    stub_jwks_endpoint(@jwk_set)

    stored_nonce = "correct-stored-nonce"
    claims = standard_id_token_claims(nonce: stored_nonce)
    id_token = generate_id_token(claims, @key)

    # Initialize strategy with attacker nonce in params but correct nonce in session
    init_strategy(strategy,
      params: { "nonce" => "attacker-injected-nonce" },
      session: { "omniauth.nonce" => stored_nonce })

    # Should not raise — uses stored nonce which matches the token
    strategy.send(:verify_id_token!, id_token)
  end

  def test_public_key_from_jwk_signing_key
    jwk_json = @jwk.to_json
    strategy = build_app(client_jwk_signing_key: jwk_json)
    stub_config_endpoint
    init_strategy(strategy)

    public_key = strategy.send(:public_key)
    assert public_key, "Expected a public key from JWK"
  end

  def test_public_key_from_x509
    cert = generate_self_signed_cert(@key)
    strategy = build_app(client_x509_signing_key: cert.to_pem)
    stub_config_endpoint
    init_strategy(strategy)

    public_key = strategy.send(:public_key)
    assert_instance_of OpenSSL::PKey::RSA, public_key
  end

  def test_public_key_falls_back_to_jwks_uri
    strategy = build_app
    stub_config_endpoint
    stub_jwks_endpoint(@jwk_set)
    init_strategy(strategy)

    public_key = strategy.send(:public_key)
    assert public_key, "Expected public key from JWKS URI"
  end

  def test_pkce_authorize_params
    strategy = build_app(pkce: true)
    init_strategy(strategy)

    verifier = SecureRandom.hex(64)
    pkce_params = strategy.send(:pkce_authorize_params, verifier)

    assert pkce_params[:code_challenge], "Expected code_challenge"
    assert_equal "S256", pkce_params[:code_challenge_method]
    refute_equal verifier, pkce_params[:code_challenge], "Challenge should differ from verifier"
  end

  def test_base64_decoded_jwt_secret
    secret = "my-jwt-secret"
    encoded = Base64.encode64(secret)
    strategy = build_app(jwt_secret_base64: encoded)
    init_strategy(strategy)

    result = strategy.send(:base64_decoded_jwt_secret)
    assert_equal secret, result
  end

  def test_base64_decoded_jwt_secret_returns_nil_when_not_configured
    strategy = build_app
    init_strategy(strategy)

    result = strategy.send(:base64_decoded_jwt_secret)
    assert_nil result
  end

  def test_secret_prefers_jwt_secret_base64
    jwt_secret = "jwt-specific-secret"
    encoded = Base64.encode64(jwt_secret)
    strategy = build_app(
      jwt_secret_base64: encoded,
      client_options: { secret: "client-secret" }
    )
    init_strategy(strategy)

    assert_equal jwt_secret, strategy.send(:secret)
  end

  def test_secret_falls_back_to_client_secret
    strategy = build_app(client_options: { secret: "client-secret" })
    init_strategy(strategy)

    assert_equal "client-secret", strategy.send(:secret)
  end

  def test_deep_underscore_keys
    strategy = build_app
    init_strategy(strategy)

    input = { "givenName" => "Jane", "familyName" => "Doe", "nested" => { "phoneNumber" => "123" } }
    result = strategy.send(:deep_underscore_keys, input)

    assert_equal "Jane", result[:given_name]
    assert_equal "Doe", result[:family_name]
    assert_equal "123", result[:nested][:phone_number]
  end

  def test_deep_underscore_keys_handles_already_underscored
    strategy = build_app
    init_strategy(strategy)

    input = { "email" => "test@example.com", "sub" => "123" }
    result = strategy.send(:deep_underscore_keys, input)

    assert_equal "test@example.com", result[:email]
    assert_equal "123", result[:sub]
  end

  private

  def init_strategy(strategy, params: {}, session: {})
    query = URI.encode_www_form(params)
    url = "http://example.com/"
    url += "?#{query}" unless query.empty?

    env = Rack::MockRequest.env_for(url)
    env["rack.session"] = session
    strategy.call!(env)
  rescue WebMock::NetConnectNotAllowedError, OmniAuth::Error, OmniAuth::Strategies::Oidc::CallbackError
    # Expected during init — strategy needs env set up but won't complete a full phase
  end
end
