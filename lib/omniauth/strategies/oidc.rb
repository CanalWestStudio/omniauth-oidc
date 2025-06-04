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
        uid_field = configuration.uid_field
        get_user_attribute(uid_field) || "unknown"
      end

      info do
        source_data = @user_info_data || @id_token_data || {}

        {
          name: source_data['name'],
          email: source_data['email'],
          email_verified: normalize_email_verified(source_data),
          first_name: get_name_field(source_data, 'givenName', 'given_name'),
          last_name: get_name_field(source_data, 'familyName', 'family_name'),
          phone: get_name_field(source_data, 'phoneNumber', 'phone_number'),
          picture: source_data['picture'],
          locale: source_data['locale']
        }.compact
      end

      extra do
        extra_data = { scope: configuration.scope }

        # Include raw user info if available
        extra_data[:raw_info] = @user_info_data if @user_info_data

        # Include ID token claims if available
        extra_data[:id_token] = @id_token_data if @id_token_data

        # Include realmId for Intuit integration
        realm_id = find_realm_id
        extra_data[:realmId] = realm_id if realm_id

        extra_data
      end

      credentials do
        creds = {}

        if @access_token
          creds[:token] = @access_token
          creds[:expires_at] = Time.now.to_i + 3600 # Default 1 hour if not specified
        end

        creds[:refresh_token] = @refresh_token if @refresh_token
        creds[:id_token] = @id_token_raw if @id_token_raw

        creds
      end

      # Authorization phase - build authorization URL and redirect
      def request_phase
        setup_security_parameters
        redirect(build_authorization_url)
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

      # Helper methods for data extraction
      def get_user_attribute(field)
        [@user_info_data, @id_token_data].compact.each do |data|
          value = data[field] || data[field.to_s]
          return value if value
        end
        nil
      end

      def get_name_field(data, camel_case, snake_case)
        data[camel_case] || data[snake_case]
      end

      def normalize_email_verified(source_data)
        email_verified = source_data['emailVerified'] || source_data['email_verified']

        case email_verified
        when true, 'true', 1, '1'
          true
        when false, 'false', 0, '0'
          false
        when nil
          nil  # Keep as nil for compliance - don't assume verification status
        else
          # For any other value, convert to boolean based on presence
          !email_verified.nil? && !email_verified.to_s.empty?
        end
      end

      def find_realm_id
        # Check ID token first, then request params (Intuit sends it as a parameter)
        (@id_token_data && @id_token_data['realmId']) || request.params['realmId']
      end

      # Security setup
      def setup_security_parameters
        store_state if configuration.require_state?
        store_nonce if configuration.send_nonce?
        store_pkce_verifier if configuration.pkce?
      end

      # Authorization flow implementation
      def build_authorization_url
        uri = URI(discovery_service.authorization_endpoint)
        uri.query = URI.encode_www_form(authorization_params)
        uri.to_s
      end

      def authorization_params
        params = base_authorization_params
        add_security_params(params)
        add_optional_params(params)
        params.merge!(configuration.extra_authorize_params)
        params.compact
      end

      def base_authorization_params
        {
          response_type: configuration.response_type,
          scope: configuration.scope,
          client_id: configuration.client_id,
          redirect_uri: redirect_uri
        }
      end

      def add_security_params(params)
        params[:state] = session["omniauth.state"] if configuration.require_state?
        params[:nonce] = session["omniauth.nonce"] if configuration.send_nonce?

        if configuration.pkce?
          params[:code_challenge] = pkce_code_challenge
          params[:code_challenge_method] = configuration.pkce_options[:code_challenge_method]
        end
      end

      def add_optional_params(params)
        optional_mappings = {
          response_mode: :response_mode,
          display: :display,
          prompt: :prompt,
          max_age: :max_age,
          ui_locales: :ui_locales,
          hd: :hd
        }

        optional_mappings.each do |param, config_method|
          value = configuration.send(config_method)
          params[param] = value if value
        end
      end

      def handle_authorization_code_flow
        exchange_code_for_tokens
        fetch_user_info if should_fetch_user_info?
        build_auth_hash
      end

      def handle_implicit_flow
        @id_token_raw = request.params["id_token"]
        @id_token_data = decode_id_token(@id_token_raw) if @id_token_raw
        build_auth_hash
      end

      def exchange_code_for_tokens
        token_params = build_token_params
        headers = {
          'Content-Type' => 'application/x-www-form-urlencoded',
          'Accept' => 'application/json'
        }

        log_timing("Token exchange") do
          token_response = Http::Client.post(
            discovery_service.token_endpoint,
            body: URI.encode_www_form(token_params),
            headers: headers,
            timeout: 3
          )

          extract_tokens(token_response)
        end
      end

      def build_token_params
        params = {
          grant_type: 'authorization_code',
          code: request.params["code"],
          redirect_uri: redirect_uri,
          client_id: configuration.client_id
        }

        params[:client_secret] = configuration.client_secret if configuration.client_secret
        params[:code_verifier] = session.delete("omniauth.pkce.verifier") if configuration.pkce?
        params[:scope] = configuration.scope if configuration.send_scope_to_token_endpoint?

        params
      end

      def extract_tokens(token_response)
        @access_token = token_response['access_token']
        @refresh_token = token_response['refresh_token']
        @id_token_raw = token_response['id_token']
        @id_token_data = decode_id_token(@id_token_raw) if @id_token_raw
      end

      def decode_id_token(token)
        # Note: In production, proper signature verification should be implemented
        JSON::JWT.decode(token, :skip_verification)
      end

      def should_fetch_user_info?
        return false unless configuration.fetch_user_info?
        return true if needs_userinfo_for_compliance?
        !has_sufficient_id_token_data?
      end

      def fetch_user_info
        return unless @access_token && discovery_service.userinfo_endpoint

        log_user_info_decision

        headers = {
          'Authorization' => "Bearer #{@access_token}",
          'Accept' => 'application/json'
        }

        log_timing("UserInfo fetch") do
          @user_info_data = Http::Client.get(
            discovery_service.userinfo_endpoint,
            headers: headers,
            timeout: 3
          )
        end
      end

      def log_user_info_decision
        if needs_userinfo_for_compliance?
          log_info("[OIDC] Fetching userinfo for compliance fields (emailVerified)")
        elsif !has_sufficient_id_token_data?
          log_info("[OIDC] Fetching userinfo for additional user data")
        else
          log_info("[OIDC] Skipping userinfo fetch - ID token has sufficient data")
        end
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

      # Smart UserInfo logic
      def has_sufficient_id_token_data?
        return false unless @id_token_data

        # Check if ID token has the essential fields we need
        essential_fields = ['sub']
        useful_fields = ['email', 'givenName', 'given_name', 'name', 'familyName', 'family_name']

        has_essential = essential_fields.all? { |field| @id_token_data[field] }
        has_useful_data = useful_fields.any? { |field| @id_token_data[field] }

        has_essential && has_useful_data
      end

      def needs_userinfo_for_compliance?
        return false unless @id_token_data

        # Check if critical compliance fields are missing from ID token
        critical_fields = ['emailVerified', 'email_verified']
        critical_fields.none? { |field| @id_token_data.key?(field) }
      end

      # Logout functionality
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
        if configuration.post_logout_redirect_uri
          uri.query = URI.encode_www_form(post_logout_redirect_uri: configuration.post_logout_redirect_uri)
        end
        uri.to_s
      end

      def logout_path_pattern
        @logout_path_pattern ||= /\A#{Regexp.quote(request.base_url)}#{configuration.logout_path}/
      end

      # Utility methods
      def redirect_uri
        options.redirect_uri || "#{full_host}#{callback_path}"
      end

      def log_timing(description)
        return yield unless logger

        start_time = Time.now
        result = yield
        elapsed_time = ((Time.now - start_time) * 1000).round(2)
        log_info("[OIDC] #{description} completed in #{elapsed_time}ms")
        result
      end

      def log_info(message)
        logger&.info(message)
      end

      def logger
        @logger ||= begin
          if defined?(Rails) && Rails.respond_to?(:logger) && Rails.logger
            Rails.logger
          elsif defined?(Logger)
            Logger.new($stdout)
          end
        end
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
