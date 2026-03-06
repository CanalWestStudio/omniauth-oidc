# frozen_string_literal: true

require "base64"
require "timeout"
require "omniauth"
require "openid_connect"
require "forwardable"

require_relative "oidc/callback"
require_relative "oidc/request"
require_relative "oidc/serializer"
require_relative "oidc/transport"
require_relative "oidc/verify"

module OmniAuth
  module Strategies
    # OIDC strategy for omniauth
    class Oidc
      include OmniAuth::Strategy
      include Callback
      include Request
      include Serializer
      include Verify

      extend Forwardable

      RESPONSE_TYPE_EXCEPTIONS = {
        "id_token" => { exception_class: OmniauthOidc::MissingIdTokenError, key: :missing_id_token }.freeze,
        "code" => { exception_class: OmniauthOidc::MissingCodeError, key: :missing_code }.freeze
      }.freeze

      def_delegator :request, :params

      option :name, :oidc                                   # to separate each oidc provider available in the app
      option(:client_options, identifier: nil,              # client id, required
                              secret: nil,                  # client secret, required
                              host: nil,                    # oidc provider host, optional
                              scheme: "https",              # connection scheme, optional
                              port: 443,                    # connection port, optional
                              config_endpoint: nil,         # all data will be fetched from here, required
                              authorization_endpoint: nil,  # optional
                              token_endpoint: nil,          # optional
                              userinfo_endpoint: nil,       # optional
                              jwks_uri: nil,                # optional
                              end_session_endpoint: nil,    # optional
                              environment: nil)             # optional

      option :issuer
      option :client_signing_alg
      option :jwt_secret_base64
      option :client_jwk_signing_key
      option :client_x509_signing_key
      option :scope, [ :openid ]
      option :response_type, "code" # ['code', 'id_token']
      option :require_state, true
      option :state
      option :response_mode # [:query, :fragment, :form_post, :web_message]
      option :display, nil # [:page, :popup, :touch, :wap]
      option :prompt, nil # [:none, :login, :consent, :select_account]
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

      # Cross-module state contract. These methods and instance variables are
      # shared between Callback, Verify, and Serializer modules during the
      # callback phase:
      #
      # Callback provides:
      #   access_token  — OpenIDConnect access token (lazy-initialized, memoized)
      #   store_id_token — persists id_token to session for RP-Initiated Logout
      #
      # Verify provides:
      #   user_info          — merged UserInfo from access token + id_token claims
      #   decoded_id_token   — decoded and verified JWT (attr_reader)
      #   verify_id_token!   — verifies id_token signature, issuer, nonce
      #   decode_id_token    — decodes JWT, sets @decoded_id_token
      #   secret, public_key — signing key resolution
      #
      # Serializer reads:
      #   access_token, user_info, decoded_id_token (via id_token_raw_attributes)
      #
      # Oidc (this class) provides to all modules:
      #   client, config, client_options, scope, session, params, options,
      #   redirect_uri, stored_state, new_nonce, host, issuer

      SECURITY_HEADERS = {
        "Cache-Control" => "no-cache, no-store, must-revalidate",
        "Pragma" => "no-cache",
        "Referrer-Policy" => "no-referrer"
      }.freeze

      def redirect(uri)
        response = super
        SECURITY_HEADERS.each { |k, v| response[1][k] = v }
        response
      end

      def uid
        user_info.raw_attributes[options.uid_field.to_sym] || user_info.sub
      end

      info { serialized_user_info }

      extra { serialized_extra }

      credentials { serialized_credentials }

      # Initialize OpenIDConnect Client with options
      def client
        @client ||= ::OpenIDConnect::Client.new(client_options)
      end

      # Config is built from the JSON response from the OIDC config endpoint
      def config
        unless client_options.config_endpoint || params["config_endpoint"]
          raise Error,
                "Configuration endpoint is missing from options"
        end

        @config ||= OmniauthOidc::Config.fetch(client_options.config_endpoint)
      end

      # Detects if current request is for the logout url and makes a redirect to end session with OIDC provider
      def other_phase
        if logout_path_pattern.match?(request.url)
          options.issuer = issuer if options.issuer.to_s.empty?

          return redirect(end_session_uri) if end_session_uri
        end
        call_app!
      end

      # URL to end authenticated user's session with OIDC provider
      def end_session_uri
        return unless end_session_endpoint_is_valid?

        end_session = URI(client_options.end_session_endpoint)
        end_session_params = {}
        end_session_params[:post_logout_redirect_uri] = options.post_logout_redirect_uri if options.post_logout_redirect_uri
        end_session_params[:id_token_hint] = session["omniauth.id_token"] if session["omniauth.id_token"]
        end_session.query = URI.encode_www_form(end_session_params) unless end_session_params.empty?
        end_session.to_s
      end

      private

      def issuer
        @issuer ||= config.issuer
      end

      def host
        @host ||= URI.parse(config.issuer).host
      end

      # get scope list from options or provider config defaults
      def scope
        options.scope || config.scopes_supported
      end

      def authorization_code
        params["code"]
      end

      def client_options
        options.client_options
      end

      def stored_state
        session.delete("omniauth.state")
      end

      def new_nonce
        session["omniauth.nonce"] = SecureRandom.hex(16)
      end

      def script_name
        return "" if @env.nil?

        super
      end

      def session
        return {} if @env.nil?

        super
      end

      def redirect_uri
        options.redirect_uri || full_host + callback_path
      end

      # Configure OIDC discovery endpoints on a target object (client_options or client).
      # Called by both Request and Callback phases to avoid duplication.
      def configure_discovery_endpoints(target)
        target.host = host
        target.authorization_endpoint = config.authorization_endpoint
        target.token_endpoint = config.token_endpoint
        target.userinfo_endpoint = config.userinfo_endpoint

        if target.respond_to?(:jwks_uri=)
          target.jwks_uri = config.jwks_uri
        end

        if config.end_session_endpoint && target.respond_to?(:end_session_endpoint=)
          target.end_session_endpoint = config.end_session_endpoint
        end
      end

      def end_session_endpoint_is_valid?
        client_options.end_session_endpoint &&
          client_options.end_session_endpoint.match?(URI::RFC2396_PARSER.make_regexp)
      end

      def logout_path_pattern
        @logout_path_pattern ||= /\A#{Regexp.quote(request.base_url)}#{options.logout_path}/
      end

      # Override for the CallbackError class
      class CallbackError < StandardError
        attr_accessor :error, :error_reason, :error_uri

        def initialize(data)
          super
          self.error = data[:error]
          self.error_reason = data[:reason]
          self.error_uri = data[:uri]
        end

        def message
          [ error, error_reason, error_uri ].compact.join(" | ")
        end
      end
    end
  end
end

OmniAuth.config.add_camelization "OmniauthOidc", "OmniAuthOidc"
