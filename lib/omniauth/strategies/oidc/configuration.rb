# frozen_string_literal: true

require 'forwardable'

module OmniAuth
  module Strategies
    class Oidc
      # Configuration service - handles all configuration logic and validation
      class Configuration
        extend Forwardable

        attr_reader :options, :request

        # Delegate simple option accessors
        def_delegators :options, :issuer, :response_type, :response_mode, :client_auth_method,
                       :require_state, :send_nonce, :pkce, :pkce_options, :client_signing_alg,
                       :jwt_secret_base64, :client_jwk_signing_key, :client_x509_signing_key,
                       :fetch_user_info, :uid_field, :send_scope_to_token_endpoint,
                       :display, :prompt, :hd, :max_age, :id_token_hint, :acr_values,
                       :logout_path, :post_logout_redirect_uri, :state, :pkce_verifier

        # Delegate client_options accessors
        def_delegator :client_options, :identifier, :client_id
        def_delegator :client_options, :secret, :client_secret
        def_delegator :client_options, :authorization_endpoint
        def_delegator :client_options, :token_endpoint
        def_delegator :client_options, :userinfo_endpoint
        def_delegator :client_options, :jwks_uri
        def_delegator :client_options, :end_session_endpoint
        def_delegator :client_options, :host
        def_delegator :client_options, :environment

        def initialize(options, request)
          @options = options
          @request = request
          validate!
        end

        def client_options
          options.client_options
        end

        # Endpoints with fallbacks
        def config_endpoint
          client_options.config_endpoint || request.params["config_endpoint"]
        end

        # Connection settings with defaults
        def scheme
          client_options.scheme || "https"
        end

        def port
          client_options.port || 443
        end

        # OAuth/OIDC settings with processing
        def scope
          Array(options.scope).join(' ')
        end

        # Boolean accessors (delegate doesn't work well with ? methods)
        def require_state?
          options.require_state
        end

        def send_nonce?
          options.send_nonce
        end

        def pkce?
          options.pkce
        end

        def fetch_user_info?
          options.fetch_user_info
        end

        def send_scope_to_token_endpoint?
          options.send_scope_to_token_endpoint
        end

        # UI settings with request fallbacks
        def ui_locales
          options.ui_locales || request.params["ui_locales"]
        end

        def login_hint
          request.params["login_hint"]
        end

        def claims_locales
          request.params["claims_locales"]
        end

        # Additional parameters with defaults
        def extra_authorize_params
          options.extra_authorize_params || {}
        end

        def allow_authorize_params
          options.allow_authorize_params || []
        end

        private

        def validate!
          validate_required_options!
          validate_client_configuration!
          validate_endpoints!
        end

        def validate_required_options!
          raise OmniauthOidc::Errors::ConfigurationError, "Client ID is required" unless client_id
          raise OmniauthOidc::Errors::ConfigurationError, "Client secret is required" unless client_secret
          raise OmniauthOidc::Errors::ConfigurationError, "Configuration endpoint is required" unless config_endpoint
        end

        def validate_client_configuration!
          validate_response_type!
          validate_client_auth_method! if client_auth_method
          validate_pkce_configuration! if pkce?
        end

        def validate_response_type!
          valid_response_types = %w[code id_token]
          return if valid_response_types.include?(response_type)

          raise OmniauthOidc::Errors::ConfigurationError, "Invalid response type: #{response_type}"
        end

        def validate_client_auth_method!
          valid_auth_methods = %w[client_secret_basic client_secret_post]
          return if valid_auth_methods.include?(client_auth_method.to_s)

          raise OmniauthOidc::Errors::ConfigurationError, "Invalid client auth method: #{client_auth_method}"
        end

        def validate_pkce_configuration!
          return if response_type == "code"

          raise OmniauthOidc::Errors::ConfigurationError, "PKCE can only be used with authorization code flow"
        end

        def validate_endpoints!
          unless valid_uri?(config_endpoint)
            raise OmniauthOidc::Errors::ConfigurationError, "Invalid configuration endpoint format"
          end

          validate_optional_endpoints!
        end

        def validate_optional_endpoints!
          endpoints = [authorization_endpoint, token_endpoint, userinfo_endpoint, jwks_uri, end_session_endpoint].compact
          endpoints.each do |endpoint|
            next if valid_uri?(endpoint)

            raise OmniauthOidc::Errors::ConfigurationError, "Invalid endpoint format: #{endpoint}"
          end
        end

        def valid_uri?(uri_string)
          return false unless uri_string

          uri = URI.parse(uri_string)
          uri.is_a?(URI::HTTP) || uri.is_a?(URI::HTTPS)
        rescue URI::InvalidURIError
          false
        end
      end
    end
  end
end