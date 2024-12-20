# frozen_string_literal: true

module OmniAuth
  module Strategies
    class Oidc
      # Callback phase
      module Callback
        def callback_phase # rubocop:disable Metrics
          error_handler

          verify_id_token!(params["id_token"]) if configured_response_type == "id_token"

          client.redirect_uri = redirect_uri

          return id_token_callback_phase if configured_response_type == "id_token"

          client.authorization_code = authorization_code

          access_token
          super
        rescue CallbackError => e
          fail!(e.error, e)
        rescue ::Rack::OAuth2::Client::Error => e
          fail!(e.response[:error], e)
        rescue ::Timeout::Error, ::Errno::ETIMEDOUT => e
          fail!(:timeout, e)
        rescue ::SocketError => e
          fail!(:failed_to_connect, e)
        end

        private

        def access_token
          return @access_token if @access_token

          token_request_params = {
            scope: (scope if options.send_scope_to_token_endpoint),
            client_auth_method: options.client_auth_method
          }

          if options.pkce
            token_request_params[:code_verifier] =
              params["code_verifier"] || session.delete("omniauth.pkce.verifier")
          end

          set_client_options_for_callback_phase

          @access_token = client.access_token!(token_request_params)

          verify_id_token!(@access_token.id_token) if configured_response_type == "code"

          options.fetch_user_info ? get_user_info_from_access_token : define_access_token
        end

        def id_token_callback_phase
          user_data = decode_id_token(params["id_token"]).raw_attributes

          define_user_info
        end

        def valid_response_type?
          return true if params.key?(configured_response_type)

          error_attrs = RESPONSE_TYPE_EXCEPTIONS[configured_response_type]
          fail!(error_attrs[:key], error_attrs[:exception_class].new(params["error"]))

          false
        end

        def get_user_info_from_access_token
          headers = {
            Authorization: "Bearer #{@access_token}"
          }

          Transport.request('GET', config.userinfo_endpoint, headers=headers)

          define_user_info
        end

        def define_user_info
          env["omniauth.auth"] = AuthHash.new(serialized_user_info_auth_hash)
        end

        def define_access_token
          env["omniauth.auth"] = AuthHash.new(serialized_access_token_auth_hash)
        end

        def configured_response_type
          @configured_response_type ||= options.response_type.to_s
        end

        # Parse response from OIDC endpoint and set client options for callback phase
        def set_client_options_for_callback_phase
          client.host = host
          client.redirect_uri = redirect_uri
          client.authorization_endpoint = config.authorization_endpoint
          client.token_endpoint = config.token_endpoint
          client.userinfo_endpoint = config.userinfo_endpoint
        end

        def error_handler
          error = params["error_reason"] || params["error"]
          error_description = params["error_description"] || params["error_reason"]
          invalid_state = (options.require_state && params["state"].to_s.empty?) || params["state"] != stored_state

          raise CallbackError, error: params["error"], reason: error_description, uri: params["error_uri"] if error
          raise CallbackError, error: :csrf_detected, reason: "Invalid 'state' parameter" if invalid_state

          return unless valid_response_type?

          options.issuer = issuer if options.issuer.nil? || options.issuer.empty?
        end
      end
    end
  end
end
