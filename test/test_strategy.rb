# frozen_string_literal: true

require "test_helper"

class TestStrategy < Minitest::Test
  include OidcTestHelper

  def test_uid_field_defaults_to_sub
    strategy = build_app
    assert_equal "sub", strategy.options.uid_field
  end

  def test_default_scope_is_openid
    strategy = build_app
    assert_equal [ :openid ], strategy.options.scope
  end

  def test_default_response_type_is_code
    strategy = build_app
    assert_equal "code", strategy.options.response_type
  end

  def test_require_state_defaults_to_true
    strategy = build_app
    assert strategy.options.require_state
  end

  def test_pkce_defaults_to_false
    strategy = build_app
    refute strategy.options.pkce
  end

  def test_send_nonce_defaults_to_true
    strategy = build_app
    assert strategy.options.send_nonce
  end

  def test_fetch_user_info_defaults_to_true
    strategy = build_app
    assert strategy.options.fetch_user_info
  end

  def test_logout_path_default
    strategy = build_app
    assert_equal "/logout", strategy.options.logout_path
  end

  def test_config_raises_without_endpoint
    strategy = build_app(client_options: { config_endpoint: nil })
    init_strategy(strategy)

    assert_raises(OmniAuth::Error) { strategy.config }
  end

  def test_config_fetches_from_endpoint
    strategy = build_app
    stub_config_endpoint
    init_strategy(strategy)

    config = strategy.config
    assert config, "Expected config to be fetched"
  end

  def test_end_session_uri_with_valid_endpoint
    strategy = build_app(
      post_logout_redirect_uri: "http://example.com/logged_out",
      client_options: { end_session_endpoint: "#{ISSUER}/logout" }
    )
    init_strategy(strategy, session: { "omniauth.id_token" => "test-id-token" })

    uri = strategy.end_session_uri

    assert uri, "Expected an end_session_uri"
    parsed = URI.parse(uri)
    params = URI.decode_www_form(parsed.query).to_h

    assert_equal "http://example.com/logged_out", params["post_logout_redirect_uri"]
    assert_equal "test-id-token", params["id_token_hint"]
  end

  def test_end_session_uri_without_id_token
    strategy = build_app(
      post_logout_redirect_uri: "http://example.com/logged_out",
      client_options: { end_session_endpoint: "#{ISSUER}/logout" }
    )
    init_strategy(strategy)

    uri = strategy.end_session_uri
    parsed = URI.parse(uri)
    params = URI.decode_www_form(parsed.query).to_h

    assert_equal "http://example.com/logged_out", params["post_logout_redirect_uri"]
    refute params.key?("id_token_hint")
  end

  def test_end_session_uri_returns_nil_for_invalid_endpoint
    strategy = build_app(client_options: { end_session_endpoint: "not-a-url" })
    init_strategy(strategy)

    assert_nil strategy.end_session_uri
  end

  def test_end_session_uri_returns_nil_when_no_endpoint
    strategy = build_app(client_options: { end_session_endpoint: nil })
    init_strategy(strategy)

    assert_nil strategy.end_session_uri
  end

  def test_callback_error_message_format
    error = OmniAuth::Strategies::Oidc::CallbackError.new(
      error: :access_denied,
      reason: "User cancelled",
      uri: "https://provider.example.com/error"
    )

    assert_equal "access_denied | User cancelled | https://provider.example.com/error", error.message
  end

  def test_callback_error_message_with_nil_fields
    error = OmniAuth::Strategies::Oidc::CallbackError.new(
      error: :access_denied,
      reason: nil,
      uri: nil
    )

    assert_equal "access_denied", error.message
  end

  def test_client_initialization
    strategy = build_app(
      client_options: {
        identifier: "my-id",
        secret: "my-secret",
        scheme: "https",
        port: 443
      }
    )

    client = strategy.client
    assert_equal "my-id", client.identifier
  end

  def test_oauth2_client_returns_oauth2_client
    strategy = build_app(
      client_options: {
        identifier: "my-id",
        secret: "my-secret"
      }
    )
    stub_config_endpoint
    init_strategy(strategy)

    oauth2_client = strategy.oauth2_client

    assert_instance_of OAuth2::Client, oauth2_client
    assert_equal "my-id", oauth2_client.id
    assert_equal "my-secret", oauth2_client.secret
    assert_equal "#{ISSUER}/token", oauth2_client.token_url
  end

  def test_oauth2_client_is_memoized
    strategy = build_app
    stub_config_endpoint
    init_strategy(strategy)

    assert_same strategy.oauth2_client, strategy.oauth2_client
  end

  def test_version_is_semver
    assert_match(/\A\d+\.\d+\.\d+\z/, OmniauthOidc::VERSION)
  end

  private

  def init_strategy(strategy, session: {})
    env = Rack::MockRequest.env_for("http://example.com/")
    env["rack.session"] = session
    strategy.call!(env)
  rescue WebMock::NetConnectNotAllowedError, OmniAuth::Error, OmniAuth::Strategies::Oidc::CallbackError
    # Expected during init — strategy needs env set up but won't complete a full phase
  end
end
