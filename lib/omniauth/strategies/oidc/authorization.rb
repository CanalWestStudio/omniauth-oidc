# frozen_string_literal: true

require 'securerandom'
require 'base64'
require 'digest'

module OmniAuth
  module Strategies
    class Oidc
      # Authorization service - handles authorization URL building and request phase
      class Authorization
        attr_reader :configuration, :request, :session

        def initialize(configuration, request, session)
          @configuration = configuration
          @request = request
          @session = session
        end

        def request_phase
          # Store state and nonce in session
          store_state if configuration.require_state?
          store_nonce if configuration.send_nonce?
          store_pkce_verifier if configuration.pkce?

          # Build authorization URL and redirect
          authorization_url = build_authorization_url
          redirect_to_authorization(authorization_url)
        end

        private

        def build_authorization_url
          uri = URI(discovery_service.authorization_endpoint)
          uri.query = URI.encode_www_form(authorization_params)
          uri.to_s
        end

        def authorization_params
          params = base_authorization_params

          # Add optional parameters
          params.merge!(optional_authorization_params)

          # Add custom parameters
          params.merge!(custom_authorization_params)

          # Filter allowed parameters
          filter_allowed_params(params)
        end

        def base_authorization_params
          {
            response_type: configuration.response_type,
            scope: configuration.scope,
            client_id: configuration.client_id,
            redirect_uri: redirect_uri
          }
        end

        def optional_authorization_params
          params = {}

          params[:state] = session_state if configuration.require_state?
          params[:nonce] = session_nonce if configuration.send_nonce?
          params[:response_mode] = configuration.response_mode if configuration.response_mode
          params[:display] = configuration.display if configuration.display
          params[:prompt] = configuration.prompt if configuration.prompt
          params[:max_age] = configuration.max_age if configuration.max_age
          params[:ui_locales] = configuration.ui_locales if configuration.ui_locales
          params[:id_token_hint] = configuration.id_token_hint if configuration.id_token_hint
          params[:login_hint] = configuration.login_hint if configuration.login_hint
          params[:acr_values] = configuration.acr_values if configuration.acr_values
          params[:hd] = configuration.hd if configuration.hd

          # Add PKCE parameters
          if configuration.pkce?
            params[:code_challenge] = pkce_code_challenge
            params[:code_challenge_method] = configuration.pkce_options[:code_challenge_method]
          end

          params.compact
        end

        def custom_authorization_params
          # Add extra authorize params from configuration
          extra_params = configuration.extra_authorize_params.dup

          # Add any request parameters that are in the allow list
          allowed_request_params = configuration.allow_authorize_params
          allowed_request_params.each do |param_name|
            param_value = request.params[param_name.to_s]
            extra_params[param_name] = param_value if param_value
          end

          extra_params
        end

        def filter_allowed_params(params)
          # Remove any nil values
          params.compact
        end

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

        def session_state
          session["omniauth.state"]
        end

        def session_nonce
          session["omniauth.nonce"]
        end

        def session_pkce_verifier
          session["omniauth.pkce.verifier"]
        end

        def pkce_code_challenge
          verifier = session_pkce_verifier
          return nil unless verifier

          configuration.pkce_options[:code_challenge].call(verifier)
        end

        def redirect_uri
          # This would typically come from the strategy's callback_path
          # For now, we'll construct it based on request
          "#{request.scheme}://#{request.host}#{request.script_name}/auth/#{configuration.options.name}/callback"
        end

        def discovery_service
          @discovery_service ||= Discovery.new(configuration)
        end

        def redirect_to_authorization(url)
          # This method would typically use the strategy's redirect method
          # For the service object, we'll return the URL and let the strategy handle the redirect
          raise NotImplementedError, "Authorization service should return URL to strategy for redirect"
        end
      end
    end
  end
end