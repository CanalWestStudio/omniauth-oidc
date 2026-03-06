# frozen_string_literal: true

require "test_helper"

class TestTransport < Minitest::Test
  def setup
    OmniAuth::Strategies::Oidc::Transport.instance_variable_set(:@connection, nil)
  end

  def test_get_request
    stub_request(:get, "https://example.com/data")
      .to_return(status: 200, body: '{"key":"value"}', headers: { "Content-Type" => "application/json" })

    response = OmniAuth::Strategies::Oidc::Transport.get("https://example.com/data")

    assert_equal 200, response.status
    assert_equal '{"key":"value"}', response.body
  end

  def test_get_sends_user_agent
    stub_request(:get, "https://example.com/data")
      .with(headers: { "User-Agent" => OmniauthOidc::USER_AGENT })
      .to_return(status: 200, body: "{}")

    OmniAuth::Strategies::Oidc::Transport.get("https://example.com/data")

    assert_requested(:get, "https://example.com/data",
      headers: { "User-Agent" => OmniauthOidc::USER_AGENT })
  end

  def test_get_with_custom_headers
    stub_request(:get, "https://example.com/data")
      .with(headers: { "Authorization" => "Bearer token123" })
      .to_return(status: 200, body: "{}")

    OmniAuth::Strategies::Oidc::Transport.get(
      "https://example.com/data",
      headers: { "Authorization" => "Bearer token123" }
    )

    assert_requested(:get, "https://example.com/data",
      headers: { "Authorization" => "Bearer token123" })
  end

  def test_post_request
    stub_request(:post, "https://example.com/token")
      .with(body: "grant_type=authorization_code")
      .to_return(status: 200, body: '{"access_token":"abc"}')

    response = OmniAuth::Strategies::Oidc::Transport.post(
      "https://example.com/token",
      body: "grant_type=authorization_code"
    )

    assert_equal 200, response.status
  end

  def test_fetch_json_parses_response
    stub_request(:get, "https://example.com/config")
      .to_return(
        status: 200,
        body: '{"issuer":"https://example.com","authorization_endpoint":"https://example.com/auth"}',
        headers: { "Content-Type" => "application/json" }
      )

    result = OmniAuth::Strategies::Oidc::Transport.fetch_json("https://example.com/config")

    assert_equal "https://example.com", result["issuer"]
    assert_equal "https://example.com/auth", result["authorization_endpoint"]
  end

  def test_connection_sets_minimum_tls_version
    connection = OmniAuth::Strategies::Oidc::Transport.connection
    ssl_config = connection.ssl

    assert_equal OpenSSL::SSL::TLS1_2_VERSION, ssl_config.min_version
  end
end
