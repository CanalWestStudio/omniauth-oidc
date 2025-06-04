# frozen_string_literal: true

require "test_helper"

class ConfigurationTest < Minitest::Test
  def setup
    @options = default_oidc_options
    @request = OpenStruct.new(params: {})
  end

  def test_initializes_with_valid_options
    config = OmniAuth::Strategies::Oidc::Configuration.new(@options, @request)

    assert_equal 'test-client-id', config.client_id
    assert_equal 'test-client-secret', config.client_secret
    assert_equal 'https://oauth.platform.intuit.com/.well-known/openid_connect/configuration', config.config_endpoint
  end

  def test_validates_required_client_id
    @options.client_options.identifier = nil

    error = assert_raises(OmniauthOidc::Errors::ConfigurationError) do
      OmniAuth::Strategies::Oidc::Configuration.new(@options, @request)
    end

    assert_includes error.message, "Client ID is required"
  end

  def test_validates_required_client_secret
    @options.client_options.secret = nil

    error = assert_raises(OmniauthOidc::Errors::ConfigurationError) do
      OmniAuth::Strategies::Oidc::Configuration.new(@options, @request)
    end

    assert_includes error.message, "Client secret is required"
  end

  def test_validates_required_config_endpoint
    @options.client_options.config_endpoint = nil

    error = assert_raises(OmniauthOidc::Errors::ConfigurationError) do
      OmniAuth::Strategies::Oidc::Configuration.new(@options, @request)
    end

    assert_includes error.message, "Configuration endpoint is required"
  end

  def test_validates_response_type
    @options.response_type = "invalid"

    error = assert_raises(OmniauthOidc::Errors::ConfigurationError) do
      OmniAuth::Strategies::Oidc::Configuration.new(@options, @request)
    end

    assert_includes error.message, "Invalid response type"
  end

  def test_validates_pkce_with_code_flow_only
    @options.pkce = true
    @options.response_type = "id_token"

    error = assert_raises(OmniauthOidc::Errors::ConfigurationError) do
      OmniAuth::Strategies::Oidc::Configuration.new(@options, @request)
    end

    assert_includes error.message, "PKCE can only be used with authorization code flow"
  end

  def test_scope_formatting
    @options.scope = [:openid, :profile, :email]
    config = OmniAuth::Strategies::Oidc::Configuration.new(@options, @request)

    assert_equal "openid profile email", config.scope
  end

  def test_boolean_methods
    config = OmniAuth::Strategies::Oidc::Configuration.new(@options, @request)

    assert config.require_state?
    assert config.send_nonce?
    assert config.fetch_user_info?
    refute config.pkce?
  end

  def test_endpoint_validation
    @options.client_options.config_endpoint = "invalid-url"

    error = assert_raises(OmniauthOidc::Errors::ConfigurationError) do
      OmniAuth::Strategies::Oidc::Configuration.new(@options, @request)
    end

    assert_includes error.message, "Invalid configuration endpoint format"
  end
end