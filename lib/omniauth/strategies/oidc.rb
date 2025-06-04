# frozen_string_literal: true

require "base64"
require "timeout"
require "net/http"
require "open-uri"
require "omniauth"
require "openid_connect"
require "openid_config_parser"
require "forwardable"
require "httparty"

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
        # Simplified for now - will delegate to user_info_service later
        "test-uid"
      end

      info do
        # Simplified for now - will delegate to serializers later
        { name: "Test User" }
      end

      extra do
        # Simplified for now - will delegate to serializers later
        { scope: configuration.scope }
      end

      credentials do
        # Simplified for now - will delegate to serializers later
        { token: "test-token" }
      end

      # Authorization phase - simplified for now
      def request_phase
        # For now, just demonstrate that configuration and discovery work
        config = configuration
        discovery = discovery_service

        # This would normally build authorization URL and redirect
        redirect("/auth/oidc/callback?code=test&state=test")
      end

      # Callback phase - simplified for now
      def callback_phase
        validate_callback_params!

        # Simplified success response
        env["omniauth.auth"] = OmniAuth::AuthHash.new({
          provider: name,
          uid: uid,
          info: info,
          extra: extra,
          credentials: credentials
        })

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

      # Validation methods - simplified
      def validate_callback_params!
        validate_state! if configuration.require_state?
        validate_error_params!
      end

      def validate_state!
        stored_state = session.delete("omniauth.state")
        current_state = params["state"]

        return if stored_state == current_state

        raise OmniauthOidc::Errors::VerificationError, "Invalid state parameter"
      end

      def validate_error_params!
        return unless params["error"]

        error_description = params["error_description"] || params["error_reason"]
        raise OmniauthOidc::Errors::TokenError, "#{params['error']}: #{error_description}"
      end

      # Utility methods
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
