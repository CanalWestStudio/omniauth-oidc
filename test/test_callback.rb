# frozen_string_literal: true

require "test_helper"

class TestCallback < Minitest::Test
  include OidcTestHelper

  def setup
    @key, @jwk = generate_rsa_keypair
    @jwk_set = { keys: [@jwk] }
    @nonce = "test-nonce"
    @id_token = generate_id_token(standard_id_token_claims(nonce: @nonce), @key)
    OmniAuth::Strategies::Oidc::Transport.instance_variable_set(:@connection, nil)
  end

  # --- Error handling ---

  def test_callback_fails_on_error_param
    strategy = build_app(require_state: false)
    response = run_callback(strategy,
      params: { "error" => "access_denied", "error_description" => "User denied" })

    assert_failure_redirect(response)
  end

  def test_callback_fails_on_error_reason_param
    strategy = build_app(require_state: false)
    response = run_callback(strategy,
      params: { "error_reason" => "user_denied" })

    assert_failure_redirect(response)
  end

  # --- State validation (RUB-5) ---

  def test_callback_raises_csrf_when_state_missing_and_required
    strategy = build_app(require_state: true)
    response = run_callback(strategy,
      params: { "code" => "auth-code" },
      session: { "omniauth.state" => "expected-state" })

    assert_includes response[1]["Location"], "csrf_detected"
  end

  def test_callback_raises_csrf_when_state_mismatch
    strategy = build_app(require_state: true)
    response = run_callback(strategy,
      params: { "code" => "auth-code", "state" => "wrong-state" },
      session: { "omniauth.state" => "expected-state" })

    assert_includes response[1]["Location"], "csrf_detected"
  end

  def test_callback_passes_with_valid_state
    strategy = build_app(require_state: true)
    stub_all_endpoints

    response = run_callback(strategy,
      params: { "code" => "auth-code", "state" => "valid-state" },
      session: { "omniauth.state" => "valid-state", "omniauth.nonce" => @nonce })

    refute_failure_redirect(response)
  end

  def test_callback_allows_no_state_when_not_required
    strategy = build_app(require_state: false)
    stub_all_endpoints

    response = run_callback(strategy,
      params: { "code" => "auth-code" },
      session: { "omniauth.nonce" => @nonce })

    refute_includes response[1]["Location"].to_s, "csrf_detected",
      "Should not detect CSRF when state is not required"
  end

  def test_callback_detects_csrf_when_state_sent_but_not_required
    strategy = build_app(require_state: false)
    stub_config_endpoint

    response = run_callback(strategy,
      params: { "code" => "auth-code", "state" => "sent-state" },
      session: { "omniauth.state" => "different-state" })

    assert_includes response[1]["Location"], "csrf_detected"
  end

  # --- ID token storage ---

  def test_callback_stores_id_token_in_session
    strategy = build_app(require_state: false)
    stub_all_endpoints

    session = { "omniauth.nonce" => @nonce }
    run_callback(strategy, params: { "code" => "auth-code" }, session: session)

    assert_equal @id_token, session["omniauth.id_token"]
  end

  # --- Response type handling ---

  def test_callback_fails_on_missing_code
    strategy = build_app(response_type: "code", require_state: false)
    stub_config_endpoint

    response = run_callback(strategy, params: {}, session: {})

    assert_failure_redirect(response)
  end

  # --- Fetch user info ---

  def test_callback_with_fetch_user_info_true
    strategy = build_app(require_state: false, fetch_user_info: true)
    stub_all_endpoints

    session = { "omniauth.nonce" => @nonce }
    response = run_callback(strategy,
      params: { "code" => "auth-code" },
      session: session)

    refute_failure_redirect(response)
  end

  def test_callback_with_fetch_user_info_false
    strategy = build_app(require_state: false, fetch_user_info: false)
    stub_all_endpoints

    session = { "omniauth.nonce" => @nonce }
    response = run_callback(strategy,
      params: { "code" => "auth-code" },
      session: session)

    refute_failure_redirect(response)
  end

  # --- Timeout handling ---

  def test_callback_handles_timeout
    strategy = build_app(require_state: false)
    stub_config_endpoint
    stub_request(:post, "#{ISSUER}/token").to_timeout

    response = run_callback(strategy,
      params: { "code" => "auth-code" },
      session: {})

    assert_failure_redirect(response)
  end

  private

  def stub_all_endpoints
    stub_config_endpoint
    stub_jwks_endpoint(@jwk_set)
    stub_token_endpoint(id_token: @id_token)
    stub_userinfo_endpoint
  end

  def run_callback(strategy, params: {}, session: {})
    query = URI.encode_www_form(params)
    url = "http://example.com/auth/test_oidc/callback?#{query}"

    env = Rack::MockRequest.env_for(url)
    env["rack.session"] = session

    strategy.call(env)
  end

  def assert_failure_redirect(response)
    assert_equal 302, response[0], "Expected redirect"
    assert_includes response[1]["Location"], "failure",
      "Expected failure redirect, got: #{response[1]["Location"]}"
  end

  def refute_failure_redirect(response)
    location = response[1]["Location"].to_s
    refute_includes location, "failure",
      "Expected successful callback, got: #{location}"
  end
end
