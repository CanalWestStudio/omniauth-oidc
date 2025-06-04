# frozen_string_literal: true

require "test_helper"

class DiscoveryTest < Minitest::Test
  def setup
    @options = default_oidc_options
    @request = OpenStruct.new(params: {})
    @configuration = OmniAuth::Strategies::Oidc::Configuration.new(@options, @request)
    @discovery = OmniAuth::Strategies::Oidc::Discovery.new(@configuration)

    mock_intuit_endpoints!
  end

  def test_fetches_oidc_configuration
    config = @discovery.oidc_configuration

    assert_equal "https://oauth.platform.intuit.com/op/v1", config["issuer"]
    assert_equal "https://appcenter.intuit.com/connect/oauth2", config["authorization_endpoint"]
    assert_equal "https://oauth.platform.intuit.com/oauth2/v1/tokens/bearer", config["token_endpoint"]
  end

  def test_caches_oidc_configuration
    # First call should make HTTP request
    config1 = @discovery.oidc_configuration

    # Second call should use cached version
    config2 = @discovery.oidc_configuration

    assert_same config1, config2
  end

  def test_endpoint_accessors
    assert_equal "https://oauth.platform.intuit.com/op/v1", @discovery.issuer
    assert_equal "https://appcenter.intuit.com/connect/oauth2", @discovery.authorization_endpoint
    assert_equal "https://oauth.platform.intuit.com/oauth2/v1/tokens/bearer", @discovery.token_endpoint
    assert_equal "https://accounts.platform.intuit.com/v1/openid_connect/userinfo", @discovery.userinfo_endpoint
    assert_equal "https://oauth.platform.intuit.com/op/v1/jwks", @discovery.jwks_uri
  end

  def test_fetches_jwks
    jwks = @discovery.jwks

    assert jwks.is_a?(Hash)
    assert jwks["keys"].is_a?(Array)
    assert_equal "test-key-id", jwks["keys"].first["kid"]
  end

  def test_handles_invalid_configuration_response
    stub_request(:get, "https://oauth.platform.intuit.com/.well-known/openid_connect/configuration")
      .to_return(status: 200, body: "invalid json", headers: {})

    error = assert_raises(OmniauthOidc::Errors::ConfigurationError) do
      @discovery.oidc_configuration
    end

    assert_includes error.message, "Failed to fetch OIDC configuration"
  end

  def test_handles_missing_required_fields
    invalid_config = intuit_oidc_config.dup
    invalid_config.delete("issuer")

    stub_request(:get, "https://oauth.platform.intuit.com/.well-known/openid_connect/configuration")
      .to_return(
        status: 200,
        body: invalid_config.to_json,
        headers: { 'Content-Type' => 'application/json' }
      )

    error = assert_raises(OmniauthOidc::Errors::ConfigurationError) do
      @discovery.oidc_configuration
    end

    assert_includes error.message, "Missing required configuration fields"
  end

  def test_handles_network_errors
    stub_request(:get, "https://oauth.platform.intuit.com/.well-known/openid_connect/configuration")
      .to_raise(SocketError.new("Network error"))

    error = assert_raises(OmniauthOidc::Errors::ConfigurationError) do
      @discovery.oidc_configuration
    end

    assert_includes error.message, "Failed to fetch OIDC configuration"
  end

  def test_validates_issuer_format
    invalid_config = intuit_oidc_config.dup
    invalid_config["issuer"] = "not-a-url"

    stub_request(:get, "https://oauth.platform.intuit.com/.well-known/openid_connect/configuration")
      .to_return(
        status: 200,
        body: invalid_config.to_json,
        headers: { 'Content-Type' => 'application/json' }
      )

    error = assert_raises(OmniauthOidc::Errors::ConfigurationError) do
      @discovery.oidc_configuration
    end

    assert_includes error.message, "Invalid issuer format"
  end

  def test_handles_jwks_fetch_errors
    stub_request(:get, "https://oauth.platform.intuit.com/op/v1/jwks")
      .to_raise(SocketError.new("Network error"))

    error = assert_raises(OmniauthOidc::Errors::VerificationError) do
      @discovery.jwks
    end

    assert_includes error.message, "Failed to fetch JWKS"
  end
end