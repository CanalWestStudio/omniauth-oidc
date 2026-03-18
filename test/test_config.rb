# frozen_string_literal: true

require "test_helper"

class TestConfig < Minitest::Test
  include OidcTestHelper

  def setup
    OmniAuth::Strategies::Oidc::Transport.reset!
    OmniauthOidc::Config.clear_cache!
  end

  def test_fetch_parses_discovery_document
    stub_config_endpoint

    config = OmniauthOidc::Config.fetch(CONFIG_ENDPOINT)

    assert_equal ISSUER, config.issuer
    assert_equal "#{ISSUER}/authorize", config.authorization_endpoint
    assert_equal "#{ISSUER}/token", config.token_endpoint
    assert_equal "#{ISSUER}/userinfo", config.userinfo_endpoint
    assert_equal "#{ISSUER}/jwks", config.jwks_uri
    assert_equal "#{ISSUER}/logout", config.end_session_endpoint
    assert_equal [ "openid", "email", "profile" ], config.scopes_supported
  end

  def test_fetch_handles_string_keys
    stub_request(:get, CONFIG_ENDPOINT)
      .to_return(
        status: 200,
        body: { "issuer" => ISSUER, "token_endpoint" => "#{ISSUER}/token" }.to_json,
        headers: { "Content-Type" => "application/json" }
      )

    config = OmniauthOidc::Config.fetch(CONFIG_ENDPOINT)

    assert_equal ISSUER, config.issuer
    assert_equal "#{ISSUER}/token", config.token_endpoint
  end

  def test_missing_optional_fields_are_nil
    stub_request(:get, CONFIG_ENDPOINT)
      .to_return(
        status: 200,
        body: { "issuer" => ISSUER }.to_json,
        headers: { "Content-Type" => "application/json" }
      )

    config = OmniauthOidc::Config.fetch(CONFIG_ENDPOINT)

    assert_equal ISSUER, config.issuer
    assert_nil config.end_session_endpoint
    assert_nil config.scopes_supported
  end

  def test_respond_to_known_fields
    stub_config_endpoint

    config = OmniauthOidc::Config.fetch(CONFIG_ENDPOINT)

    assert_respond_to config, :issuer
    assert_respond_to config, :end_session_endpoint
  end

  def test_does_not_respond_to_unknown_fields
    stub_config_endpoint

    config = OmniauthOidc::Config.fetch(CONFIG_ENDPOINT)

    refute_respond_to config, :some_unknown_field
  end

  def test_fetch_caches_result
    stub = stub_config_endpoint

    config1 = OmniauthOidc::Config.fetch(CONFIG_ENDPOINT)
    config2 = OmniauthOidc::Config.fetch(CONFIG_ENDPOINT)

    assert_same config1, config2
    assert_requested stub, times: 1
  end

  def test_fetch_cache_expires_after_ttl
    stub = stub_config_endpoint

    OmniauthOidc::Config.fetch(CONFIG_ENDPOINT, ttl: 0)
    OmniauthOidc::Config.fetch(CONFIG_ENDPOINT, ttl: 0)

    assert_requested stub, times: 2
  end

  def test_clear_cache
    stub = stub_config_endpoint

    OmniauthOidc::Config.fetch(CONFIG_ENDPOINT)
    OmniauthOidc::Config.clear_cache!
    OmniauthOidc::Config.fetch(CONFIG_ENDPOINT)

    assert_requested stub, times: 2
  end
end
