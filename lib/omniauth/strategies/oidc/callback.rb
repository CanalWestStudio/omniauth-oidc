# frozen_string_literal: true

require_relative 'discovery_service'
require_relative 'token_service'

module OmniAuth
  module Strategies
    class Oidc
      # Optimized callback phase with performance monitoring
      module Callback
        def callback_phase
          log_timing("[OIDC CALLBACK] Full callback phase") do
            error_handler

            verify_id_token!(params["id_token"]) if configured_response_type == "id_token"

            client.redirect_uri = redirect_uri

            return id_token_callback_phase if configured_response_type == "id_token"

            client.authorization_code = authorization_code

            # Optimized token exchange
            perform_token_exchange
            super
          end
        rescue CallbackError => e
          log_error("[OIDC CALLBACK] CallbackError: #{e.message}")
          fail!(e.error, e)
        rescue ::Rack::OAuth2::Client::Error => e
          log_error("[OIDC CALLBACK] OAuth2 Error: #{e.message}")
          fail!(e.response[:error], e)
        rescue ::Timeout::Error, ::Errno::ETIMEDOUT => e
          log_error("[OIDC CALLBACK] Timeout: #{e.message}")
          fail!(:timeout, e)
        rescue ::SocketError => e
          log_error("[OIDC CALLBACK] Network Error: #{e.message}")
          fail!(:failed_to_connect, e)
        rescue => e
          log_error("[OIDC CALLBACK] Unexpected Error: #{e.class.name}: #{e.message}")
          fail!(:unknown_error, e)
        end

        private

        def perform_token_exchange
          log_timing("[OIDC CALLBACK] Token exchange phase") do
            return @access_token if @access_token

            # Prepare token exchange parameters
            extra_params = build_token_exchange_params

            # Use optimized token service
            @token_response = TokenService.exchange_code_for_tokens(
              config,
              client_options,
              authorization_code,
              redirect_uri,
              extra_params
            )

            unless @token_response
              log_error("[OIDC CALLBACK] Token exchange failed - no token response received")
              raise CallbackError, error: :token_exchange_failed, reason: "Failed to exchange authorization code for tokens"
            end

            @access_token = @token_response.access_token

            # Verify ID token if present
            if @token_response.id_token && configured_response_type == "code"
              log_timing("[OIDC CALLBACK] ID token verification") do
                verify_id_token!(@token_response.id_token)
              end
            end

            # Fetch user info if enabled and not skipped
            if should_fetch_user_info?
              fetch_user_info_optimized
            else
              log_info("[OIDC CALLBACK] Skipping user info fetch (fetch_user_info: false)")
              define_access_token
            end
          end
        end

        def build_token_exchange_params
          params = {}

          # Add scope if required
          if options.send_scope_to_token_endpoint
            params[:scope] = scope
          end

          # Add client auth method
          params[:client_auth_method] = options.client_auth_method

          # Add PKCE verifier if present
          if options.pkce
            params[:code_verifier] = params["code_verifier"] || session.delete("omniauth.pkce.verifier")
          end

          params
        end

        def should_fetch_user_info?
          options.fetch_user_info && config&.userinfo_endpoint
        end

        def fetch_user_info_optimized
          log_timing("[OIDC CALLBACK] User info fetch") do
            @user_info_data = TokenService.fetch_user_info(
              config.userinfo_endpoint,
              @access_token
            )

            if @user_info_data
              log_info("[OIDC CALLBACK] User info fetched successfully")
              define_user_info_with_data
            else
              log_info("[OIDC CALLBACK] User info fetch failed, falling back to token data")
              define_access_token
            end
          end
        end

        def id_token_callback_phase
          log_timing("[OIDC CALLBACK] ID token callback phase") do
            user_data = decode_id_token(params["id_token"]).raw_attributes
            log_info("[OIDC CALLBACK] ID token decoded successfully")
            define_user_info
          end
        end

        def valid_response_type?
          return true if params.key?(configured_response_type)

          error_attrs = RESPONSE_TYPE_EXCEPTIONS[configured_response_type]
          fail!(error_attrs[:key], error_attrs[:exception_class].new(params["error"]))

          false
        end

        # Legacy method for backward compatibility - now just delegates
        def get_user_info_from_access_token
          fetch_user_info_optimized
        end

        def define_user_info
          log_timing("[OIDC CALLBACK] Building auth hash with user info") do
            env["omniauth.auth"] = AuthHash.new(serialized_user_info_auth_hash)
          end
        end

        def define_user_info_with_data
          log_timing("[OIDC CALLBACK] Building auth hash with fetched user data") do
            # Store user info for serialization
            @fetched_user_info = @user_info_data
            env["omniauth.auth"] = AuthHash.new(serialized_user_info_auth_hash)
          end
        end

        def define_access_token
          log_timing("[OIDC CALLBACK] Building auth hash with token data only") do
            env["omniauth.auth"] = AuthHash.new(serialized_access_token_auth_hash)
          end
        end

        def configured_response_type
          @configured_response_type ||= options.response_type.to_s
        end

        # Legacy method - kept for compatibility but optimized
        def access_token
          perform_token_exchange
          @access_token
        end

        # Parse response from OIDC endpoint and set client options for callback phase
        def set_client_options_for_callback_phase
          log_timing("[OIDC CALLBACK] Setting client options") do
            client.host = host
            client.redirect_uri = redirect_uri
            client.authorization_endpoint = config.authorization_endpoint
            client.token_endpoint = config.token_endpoint
            client.userinfo_endpoint = config.userinfo_endpoint
          end
        end

        def error_handler
          log_timing("[OIDC CALLBACK] Error validation") do
            error = params["error_reason"] || params["error"]
            error_description = params["error_description"] || params["error_reason"]
            invalid_state = (options.require_state && params["state"].to_s.empty?) || params["state"] != stored_state

            if error
              log_error("[OIDC CALLBACK] Provider error: #{error} - #{error_description}")
              raise CallbackError, error: params["error"], reason: error_description, uri: params["error_uri"]
            end

            if invalid_state
              log_error("[OIDC CALLBACK] Invalid state parameter")
              raise CallbackError, error: :csrf_detected, reason: "Invalid 'state' parameter"
            end

            return unless valid_response_type?

            options.issuer = issuer if options.issuer.nil? || options.issuer.empty?
          end
        end

        # Performance logging helpers
        def log_timing(description, &block)
          start_time = Time.now
          result = yield
          duration = ((Time.now - start_time) * 1000).round(1)
          log_info("#{description} completed in #{duration}ms")
          result
        end

        def log_info(message)
          logger.info(message) if logger
        end

        def log_error(message)
          logger.error(message) if logger
        end

        def logger
          @logger ||= defined?(Rails) ? Rails.logger : Logger.new(STDOUT)
        end
      end
    end
  end
end
