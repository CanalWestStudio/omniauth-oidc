# frozen_string_literal: true

require "base64"
require "timeout"
require "net/http"
require "open-uri"
require "omniauth"
require "openid_connect"
require "openid_config_parser"
require "forwardable"
require "securerandom"

# Require core service objects and components we've built
require_relative "oidc/configuration"
require_relative "oidc/discovery"
require_relative "oidc/http/client"
require_relative "oidc/http/response"
require_relative "oidc/errors/configuration_error"
require_relative "oidc/errors/token_error"
require_relative "oidc/errors/verification_error"

module OmniAuth
  module Strategies
    # OIDC strategy for omniauth - Clean orchestrator following single responsibility
    class Oidc
      include OmniAuth::Strategy

      RESPONSE_TYPE_EXCEPTIONS = {
        "id_token" => { exception_class: OmniauthOidc::Errors::MissingIdTokenError, key: :missing_id_token }.freeze,
        "code" => { exception_class: OmniauthOidc::Errors::MissingCodeError, key: :missing_code }.freeze
      }.freeze

      # Configuration options
      option :name, :oidc
      option(:client_options, identifier: nil,
                              secret: nil,
                              host: nil,
                              scheme: "https",
                              port: 443,
                              config_endpoint: nil,
                              authorization_endpoint: nil,
                              token_endpoint: nil,
                              userinfo_endpoint: nil,
                              jwks_uri: nil,
                              end_session_endpoint: nil,
                              environment: nil)

      option :issuer
      option :client_signing_alg
      option :jwt_secret_base64
      option :client_jwk_signing_key
      option :client_x509_signing_key
      option :scope, [:openid]
      option :response_type, "code"
      option :require_state, true
      option :state
      option :response_mode
      option :display, nil
      option :prompt, nil
      option :hd, nil
      option :max_age
      option :ui_locales
      option :id_token_hint
      option :acr_values
      option :send_nonce, true
      option :fetch_user_info, true
      option :send_scope_to_token_endpoint, true
      option :client_auth_method
      option :post_logout_redirect_uri
      option :extra_authorize_params, {}
      option :allow_authorize_params, []
      option :uid_field, "sub"
      option :pkce, false
      option :pkce_verifier, nil
      option :pkce_options, {
        code_challenge: proc { |verifier|
          Base64.urlsafe_encode64(Digest::SHA2.digest(verifier), padding: false)
        },
        code_challenge_method: "S256"
      }
      option :logout_path, "/logout"

      # Public API methods
      def uid
        # Get UID from userinfo or ID token
        uid_field = configuration.uid_field

        if @user_info_data && (@user_info_data[uid_field] || @user_info_data[uid_field.to_s])
          @user_info_data[uid_field] || @user_info_data[uid_field.to_s]
        elsif @id_token_data && (@id_token_data[uid_field] || @id_token_data[uid_field.to_s])
          @id_token_data[uid_field] || @id_token_data[uid_field.to_s]
        else
          "unknown"
        end
      end

      info do
        # Build user info from available data
        user_info = {}

        source_data = @user_info_data || @id_token_data || {}

        user_info[:name] = source_data['name']
        user_info[:email] = source_data['email']
        user_info[:email_verified] = source_data['emailVerified'] || source_data['email_verified'] # Support both formats
        user_info[:first_name] = source_data['givenName'] || source_data['given_name'] # Support both formats
        user_info[:last_name] = source_data['familyName'] || source_data['family_name'] # Support both formats
        user_info[:phone] = source_data['phoneNumber'] || source_data['phone_number'] # Support both formats
        user_info[:picture] = source_data['picture']
        user_info[:locale] = source_data['locale']

        user_info.compact
      end

      extra do
        extra_data = { scope: configuration.scope }

        # Include raw user info if available
        extra_data[:raw_info] = @user_info_data if @user_info_data

        # Include ID token claims if available
        extra_data[:id_token] = @id_token_data if @id_token_data

        # For Intuit integration - include realmId if present
        if @id_token_data && @id_token_data['realmId']
          extra_data[:realmId] = @id_token_data['realmId']
        end

        # Also check for realmId in request params (Intuit sends it as a parameter)
        if request.params['realmId']
          extra_data[:realmId] = request.params['realmId']
        end

        extra_data
      end

      credentials do
        creds = {}

        if @access_token
          creds[:token] = @access_token
          creds[:expires_at] = Time.now.to_i + 3600 # Default 1 hour if not specified
        end

        if @refresh_token
          creds[:refresh_token] = @refresh_token
        end

        if @id_token_raw
          creds[:id_token] = @id_token_raw
        end

        creds
      end

      # Authorization phase - build authorization URL and redirect
      def request_phase
        # Store state and nonce in session for security
        store_state if configuration.require_state?
        store_nonce if configuration.send_nonce?
        store_pkce_verifier if configuration.pkce?

        # Build authorization URL
        authorization_url = build_authorization_url

        # Redirect to authorization endpoint
        redirect(authorization_url)
      end

      # Callback phase - handle authorization response
      def callback_phase
        validate_callback_params!

        case configuration.response_type
        when "code"
          handle_authorization_code_flow
        when "id_token"
          handle_implicit_flow
        else
          fail!(:unsupported_response_type, "Unsupported response type: #{configuration.response_type}")
        end

        super
      rescue OmniauthOidc::Errors::ConfigurationError => e
        fail!(:configuration_error, e)
      rescue OmniauthOidc::Errors::TokenError => e
        fail!(:token_error, e)
      rescue OmniauthOidc::Errors::VerificationError => e
        fail!(:verification_error, e)
      rescue StandardError => e
        fail!(:unknown_error, e)
      end

      # Handle logout requests
      def other_phase
        if logout_request?
          redirect_to_logout
        else
          call_app!
        end
      end

      private

      # Service object accessors
      def configuration
        @configuration ||= Configuration.new(options, request)
      end

      def discovery_service
        @discovery_service ||= Discovery.new(configuration)
      end

      # Authorization flow implementation
      def build_authorization_url
        uri = URI(discovery_service.authorization_endpoint)
        uri.query = URI.encode_www_form(authorization_params)
        uri.to_s
      end

      def authorization_params
        params = {
          response_type: configuration.response_type,
          scope: configuration.scope,
          client_id: configuration.client_id,
          redirect_uri: redirect_uri
        }

        # Add state for CSRF protection
        params[:state] = session["omniauth.state"] if configuration.require_state?

        # Add nonce for ID token security
        params[:nonce] = session["omniauth.nonce"] if configuration.send_nonce?

        # Add PKCE parameters if enabled
        if configuration.pkce?
          params[:code_challenge] = pkce_code_challenge
          params[:code_challenge_method] = configuration.pkce_options[:code_challenge_method]
        end

        # Add optional parameters
        params[:response_mode] = configuration.response_mode if configuration.response_mode
        params[:display] = configuration.display if configuration.display
        params[:prompt] = configuration.prompt if configuration.prompt
        params[:max_age] = configuration.max_age if configuration.max_age
        params[:ui_locales] = configuration.ui_locales if configuration.ui_locales
        params[:hd] = configuration.hd if configuration.hd

        # Add extra parameters from configuration
        params.merge!(configuration.extra_authorize_params)

        params.compact
      end

      def handle_authorization_code_flow
        # Exchange authorization code for tokens
        exchange_code_for_tokens

        # Fetch user info if enabled
        fetch_user_info if configuration.fetch_user_info?

        # Build final auth hash
        build_auth_hash
      end

      def handle_implicit_flow
        # For implicit flow, we get the ID token directly
        @id_token_raw = request.params["id_token"]
        # TODO: Verify ID token signature and claims
        # For now, just decode without verification (not recommended for production)
        @id_token_data = JSON::JWT.decode(@id_token_raw, :skip_verification) if @id_token_raw

        build_auth_hash
      end

      def exchange_code_for_tokens
        token_params = {
          grant_type: 'authorization_code',
          code: request.params["code"],
          redirect_uri: redirect_uri,
          client_id: configuration.client_id
        }

        # Add client secret for authentication
        if configuration.client_secret
          token_params[:client_secret] = configuration.client_secret
        end

        # Add PKCE verifier if used
        if configuration.pkce?
          token_params[:code_verifier] = session.delete("omniauth.pkce.verifier")
        end

        # Add scope if required
        if configuration.send_scope_to_token_endpoint?
          token_params[:scope] = configuration.scope
        end

        headers = {
          'Content-Type' => 'application/x-www-form-urlencoded',
          'Accept' => 'application/json'
        }

        # Make token request
        token_response = Http::Client.post(
          discovery_service.token_endpoint,
          body: URI.encode_www_form(token_params),
          headers: headers
        )

        # Extract tokens from response
        @access_token = token_response['access_token']
        @refresh_token = token_response['refresh_token']
        @id_token_raw = token_response['id_token']

        # Decode ID token if present (TODO: add proper verification)
        if @id_token_raw
          @id_token_data = JSON::JWT.decode(@id_token_raw, :skip_verification)
        end
      end

      def fetch_user_info
        return unless @access_token && discovery_service.userinfo_endpoint

        headers = {
          'Authorization' => "Bearer #{@access_token}",
          'Accept' => 'application/json'
        }

        @user_info_data = Http::Client.get(
          discovery_service.userinfo_endpoint,
          headers: headers
        )
      end

      def build_auth_hash
        env["omniauth.auth"] = OmniAuth::AuthHash.new({
          provider: name,
          uid: uid,
          info: info,
          extra: extra,
          credentials: credentials
        })
      end

      # Validation methods
      def validate_callback_params!
        validate_state! if configuration.require_state?
        validate_error_params!
        validate_response_type!
      end

      def validate_state!
        stored_state = session.delete("omniauth.state")
        current_state = request.params["state"]

        return if stored_state == current_state

        raise OmniauthOidc::Errors::VerificationError, "Invalid state parameter"
      end

      def validate_error_params!
        return unless request.params["error"]

        error_description = request.params["error_description"] || request.params["error_reason"]
        raise OmniauthOidc::Errors::TokenError, "#{request.params['error']}: #{error_description}"
      end

      def validate_response_type!
        return if request.params.key?(configuration.response_type)

        error_info = RESPONSE_TYPE_EXCEPTIONS[configuration.response_type]
        fail!(error_info[:key], error_info[:exception_class].new(request.params["error"]))
      end

      # Session management
      def store_state
        state_value = configuration.state || SecureRandom.hex(32)
        session["omniauth.state"] = state_value
      end

      def store_nonce
        nonce_value = SecureRandom.hex(16)
        session["omniauth.nonce"] = nonce_value
      end

      def store_pkce_verifier
        verifier = configuration.pkce_verifier || SecureRandom.urlsafe_base64(32)
        session["omniauth.pkce.verifier"] = verifier
      end

      def pkce_code_challenge
        verifier = session["omniauth.pkce.verifier"]
        return nil unless verifier

        configuration.pkce_options[:code_challenge].call(verifier)
      end

      # Utility methods
      def redirect_uri
        options.redirect_uri || "#{full_host}#{callback_path}"
      end

      def logout_request?
        logout_path_pattern.match?(request.url)
      end

      def redirect_to_logout
        return call_app! unless end_session_uri

        redirect(end_session_uri)
      end

      def end_session_uri
        return unless discovery_service.end_session_endpoint

        uri = URI(discovery_service.end_session_endpoint)
        uri.query = URI.encode_www_form(post_logout_redirect_uri: configuration.post_logout_redirect_uri) if configuration.post_logout_redirect_uri
        uri.to_s
      end

      def logout_path_pattern
        @logout_path_pattern ||= /\A#{Regexp.quote(request.base_url)}#{configuration.logout_path}/
      end

      # Legacy error class for backward compatibility
      class CallbackError < StandardError
        attr_accessor :error, :error_reason, :error_uri

        def initialize(data)
          super
          self.error = data[:error]
          self.error_reason = data[:reason]
          self.error_uri = data[:uri]
        end

        def message
          [error, error_reason, error_uri].compact.join(" | ")
        end
      end
    end
  end
end

OmniAuth.config.add_camelization "OmniauthOidc", "OmniAuthOidc"
