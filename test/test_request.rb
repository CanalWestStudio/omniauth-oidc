# frozen_string_literal: true

require "test_helper"

class TestRequest < Minitest::Test
  include OidcTestHelper

  def setup
    OmniAuth::Strategies::Oidc::Transport.reset!
    stub_config_endpoint
  end

  def test_authorize_uri_includes_required_params
    strategy = build_app(scope: [ :openid, :email ])
    location = run_request_phase(strategy)

    uri = URI.parse(location)
    params = URI.decode_www_form(uri.query).to_h

    assert_equal "code", params["response_type"]
    assert_includes params["scope"], "openid"
    assert_includes params["scope"], "email"
    assert params["state"], "Expected state parameter"
  end

  def test_authorize_uri_includes_nonce_when_enabled
    strategy = build_app(send_nonce: true)
    location = run_request_phase(strategy)

    params = parse_redirect_params(location)
    assert params["nonce"], "Expected nonce parameter"
  end

  def test_authorize_uri_excludes_nonce_when_disabled
    strategy = build_app(send_nonce: false)
    location = run_request_phase(strategy)

    params = parse_redirect_params(location)
    refute params.key?("nonce"), "Expected no nonce parameter"
  end

  def test_authorize_uri_with_pkce
    strategy = build_app(pkce: true)
    session = {}
    location = run_request_phase(strategy, session: session)

    params = parse_redirect_params(location)
    assert params["code_challenge"], "Expected code_challenge"
    assert_equal "S256", params["code_challenge_method"]
    assert session["omniauth.pkce.verifier"], "Expected PKCE verifier stored in session"
  end

  def test_authorize_uri_merges_extra_authorize_params
    strategy = build_app(extra_authorize_params: { tenant: "common", custom: "value" })
    location = run_request_phase(strategy)

    params = parse_redirect_params(location)
    assert_equal "common", params["tenant"]
    assert_equal "value", params["custom"]
  end

  def test_authorize_uri_includes_allowed_dynamic_params
    strategy = build_app(allow_authorize_params: [ :login_hint ])
    location = run_request_phase(strategy, params: { "login_hint" => "user@example.com" })

    query_params = parse_redirect_params(location)
    assert_equal "user@example.com", query_params["login_hint"]
  end

  def test_authorize_uri_includes_environment_when_set
    strategy = build_app(client_options: { environment: "sandbox" })
    location = run_request_phase(strategy)

    params = parse_redirect_params(location)
    assert_equal "sandbox", params["environment"]
  end

  def test_authorize_uri_with_id_token_response_type
    strategy = build_app(response_type: "id_token")
    location = run_request_phase(strategy)

    params = parse_redirect_params(location)
    assert_equal "id_token", params["response_type"]
  end

  def test_authorize_uri_includes_prompt
    strategy = build_app(prompt: :login)
    location = run_request_phase(strategy)

    params = parse_redirect_params(location)
    assert_equal "login", params["prompt"]
  end

  def test_state_defaults_to_random_hex
    strategy = build_app
    session = {}
    run_request_phase(strategy, session: session)

    state = session["omniauth.state"]
    assert state, "Expected state in session"
    assert_match(/\A[0-9a-f]{32}\z/, state, "Expected 32 hex chars")
  end

  def test_new_state_uses_custom_proc
    custom_state = "custom-state-value"
    strategy = build_app(state: -> { custom_state })
    session = {}
    run_request_phase(strategy, session: session)

    assert_equal custom_state, session["omniauth.state"]
  end

  def test_new_state_with_env_aware_proc
    strategy = build_app(state: ->(env) { "state-for-#{env['SERVER_NAME']}" })
    session = {}
    run_request_phase(strategy, session: session)

    assert_equal "state-for-example.com", session["omniauth.state"]
  end

  def test_redirect_includes_security_headers
    strategy = build_app
    _location, headers = run_request_phase_with_headers(strategy)

    assert_equal "no-cache, no-store, must-revalidate", headers["Cache-Control"]
    assert_equal "no-cache", headers["Pragma"]
    assert_equal "no-referrer", headers["Referrer-Policy"]
  end

  private

  def run_request_phase(strategy, params: {}, session: {})
    query = URI.encode_www_form(params)
    url = "http://example.com/auth/test_oidc"
    url += "?#{query}" unless query.empty?

    env = Rack::MockRequest.env_for(url, "REQUEST_METHOD" => "POST")
    env["rack.session"] = session

    response = strategy.call(env)
    assert_equal 302, response[0], "Expected redirect from request phase, got #{response[0]}"
    response[1]["Location"]
  end

  def run_request_phase_with_headers(strategy, session: {})
    env = Rack::MockRequest.env_for("http://example.com/auth/test_oidc", "REQUEST_METHOD" => "POST")
    env["rack.session"] = session
    response = strategy.call(env)
    [ response[1]["Location"], response[1] ]
  end

  def parse_redirect_params(location)
    uri = URI.parse(location)
    URI.decode_www_form(uri.query).to_h
  end
end
