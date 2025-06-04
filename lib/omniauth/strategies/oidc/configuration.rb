# frozen_string_literal: true

module OmniAuth
  module Strategies
    class Oidc
      # Configuration service - handles all configuration logic and validation
      class Configuration
        attr_reader :options, :request

        def initialize(options, request)
          @options = options
          @request = request
          validate!
        end

        # Client configuration
        def client_id
          client_options.identifier
        end

        def client_secret
          client_options.secret
        end

        def client_options
          options.client_options
        end

        # Endpoints
        def config_endpoint
          client_options.config_endpoint || request.params["config_endpoint"]
        end

        def authorization_endpoint
          client_options.authorization_endpoint
        end

        def token_endpoint
          client_options.token_endpoint
        end

        def userinfo_endpoint
          client_options.userinfo_endpoint
        end

        def jwks_uri
          client_options.jwks_uri
        end

        def end_session_endpoint
          client_options.end_session_endpoint
        end

        # Connection settings
        def scheme
          client_options.scheme || "https"
        end

        def host
          client_options.host
        end

        def port
          client_options.port || 443
        end

        def environment
          client_options.environment
        end

        # OAuth/OIDC settings
        def issuer
          options.issuer
        end

        def scope
          Array(options.scope).join(' ')
        end

        def response_type
          options.response_type
        end

        def response_mode
          options.response_mode
        end

        def client_auth_method
          options.client_auth_method
        end

        # Security settings
        def require_state?
          options.require_state
        end

        def send_nonce?
          options.send_nonce
        end

        def pkce?
          options.pkce
        end

        def pkce_options
          options.pkce_options
        end

        def client_signing_alg
          options.client_signing_alg
        end

        def jwt_secret_base64
          options.jwt_secret_base64
        end

        def client_jwk_signing_key
          options.client_jwk_signing_key
        end

        def client_x509_signing_key
          options.client_x509_signing_key
        end

        # User info settings
        def fetch_user_info?
          options.fetch_user_info
        end

        def uid_field
          options.uid_field
        end

        def send_scope_to_token_endpoint?
          options.send_scope_to_token_endpoint
        end

        # UI settings
        def display
          options.display
        end

        def prompt
          options.prompt
        end

        def ui_locales
          options.ui_locales || request.params["ui_locales"]
        end

        def login_hint
          request.params["login_hint"]
        end

        def claims_locales
          request.params["claims_locales"]
        end

        def hd
          options.hd
        end

        def max_age
          options.max_age
        end

        def id_token_hint
          options.id_token_hint
        end

        def acr_values
          options.acr_values
        end

        # Session and redirect settings
        def logout_path
          options.logout_path
        end

        def post_logout_redirect_uri
          options.post_logout_redirect_uri
        end

        # Additional parameters
        def extra_authorize_params
          options.extra_authorize_params || {}
        end

        def allow_authorize_params
          options.allow_authorize_params || []
        end

        # State and nonce
        def state
          options.state
        end

        def pkce_verifier
          options.pkce_verifier
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
          # Validate response type
          valid_response_types = %w[code id_token]
          unless valid_response_types.include?(response_type)
            raise OmniauthOidc::Errors::ConfigurationError, "Invalid response type: #{response_type}"
          end

          # Validate client auth method if specified
          if client_auth_method
            valid_auth_methods = %w[client_secret_basic client_secret_post]
            unless valid_auth_methods.include?(client_auth_method.to_s)
              raise OmniauthOidc::Errors::ConfigurationError, "Invalid client auth method: #{client_auth_method}"
            end
          end

          # Validate PKCE configuration
          if pkce? && response_type != "code"
            raise OmniauthOidc::Errors::ConfigurationError, "PKCE can only be used with authorization code flow"
          end
        end

        def validate_endpoints!
          # Validate config endpoint format
          unless valid_uri?(config_endpoint)
            raise OmniauthOidc::Errors::ConfigurationError, "Invalid configuration endpoint format"
          end

          # Validate other endpoints if provided
          [authorization_endpoint, token_endpoint, userinfo_endpoint, jwks_uri, end_session_endpoint].compact.each do |endpoint|
            unless valid_uri?(endpoint)
              raise OmniauthOidc::Errors::ConfigurationError, "Invalid endpoint format: #{endpoint}"
            end
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