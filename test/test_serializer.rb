# frozen_string_literal: true

require "test_helper"

class TestSerializer < Minitest::Test
  include OidcTestHelper

  def setup
    OmniAuth::Strategies::Oidc::Transport.instance_variable_set(:@connection, nil)
  end

  def test_serialized_request_options_structure
    strategy = build_app(
      response_type: "code",
      response_mode: :query,
      scope: [:openid, :email],
      send_nonce: true,
      prompt: :login,
      hd: "example.com",
      acr_values: "urn:mace:incommon:iap:silver"
    )
    stub_config_endpoint
    init_strategy(strategy)

    opts = strategy.send(:serialized_request_options)

    assert_equal "code", opts[:response_type]
    assert_equal :query, opts[:response_mode]
    assert_includes opts[:scope], :openid
    assert_includes opts[:scope], :email
    assert opts[:state], "Expected state"
    assert opts[:nonce], "Expected nonce"
    assert_equal :login, opts[:prompt]
    assert_equal "example.com", opts[:hd]
    assert_equal "urn:mace:incommon:iap:silver", opts[:acr_values]
  end

  def test_serialized_request_options_excludes_nonce_when_disabled
    strategy = build_app(send_nonce: false)
    stub_config_endpoint
    init_strategy(strategy)

    opts = strategy.send(:serialized_request_options)
    assert_nil opts[:nonce]
  end

  private

  def init_strategy(strategy)
    env = Rack::MockRequest.env_for("http://example.com/auth/test_oidc")
    env["rack.session"] = {}
    strategy.call!(env)
  rescue StandardError
    # Swallow
  end
end
