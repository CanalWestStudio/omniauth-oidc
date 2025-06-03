# frozen_string_literal: true

require_relative 'http_client'
require 'uri'
require 'base64'
require 'json'

module OmniAuth
  module Strategies
    class Oidc
      # Token exchange service with performance monitoring
      class TokenService
        TOKEN_TIMEOUT = 5 # seconds

        class << self
          # Exchange authorization code for access tokens
          def exchange_code_for_tokens(config, client_options, authorization_code, redirect_uri, extra_params = {})
            start_time = current_time_ms

            begin
              token_endpoint = config.token_endpoint
              raise "Token endpoint not available" unless token_endpoint

              log_info("[TOKEN] Exchanging authorization code at #{URI.parse(token_endpoint).host}")

              # Build token request parameters
              token_params = build_token_params(
                client_options,
                authorization_code,
                redirect_uri,
                extra_params
              )

              headers = build_token_headers(client_options)
              form_data = URI.encode_www_form(token_params)

              log_info("[TOKEN] Request details:")
              log_info("[TOKEN]   URL: #{token_endpoint}")
              log_info("[TOKEN]   Method: POST")
              log_info("[TOKEN]   Content-Type: #{headers['Content-Type']}")
              log_info("[TOKEN]   Authorization: #{headers['Authorization'] ? 'Basic [REDACTED]' : 'MISSING'}")
              log_info("[TOKEN]   Body length: #{form_data.length} bytes")

              response = HttpClient.post(
                token_endpoint,
                body: form_data,
                headers: headers,
                timeout: Configuration.token_timeout
              )

              execution_time = current_time_ms - start_time

              if response.is_a?(Hash) && response['access_token']
                log_info("[TOKEN] ✅ Token exchange completed in #{execution_time}ms")
                return TokenResponse.new(response)
              else
                log_error("[TOKEN] ❌ Invalid token response (#{response.class})")
                return nil
              end

            rescue => e
              execution_time = current_time_ms - start_time
              log_error("[TOKEN] ❌ Token exchange failed after #{execution_time}ms: #{e.message}")

              if e.message.include?("HTTP 401")
                log_error("[TOKEN] ❌ Authentication failed - check client credentials")
              end

              return nil
            end
          end

          # Fetch user info using access token
          def fetch_user_info(userinfo_endpoint, access_token)
            return nil unless userinfo_endpoint && access_token

            start_time = current_time_ms

            begin
              log_info("[USERINFO] Fetching user info from #{URI.parse(userinfo_endpoint).host}")

              response = HttpClient.get(userinfo_endpoint, {
                timeout: Configuration.userinfo_timeout,
                headers: {
                  "Authorization" => "Bearer #{access_token}",
                  "Accept" => "application/json"
                }
              })

              execution_time = current_time_ms - start_time

              if response.is_a?(Hash)
                log_info("[USERINFO] ✅ User info fetched in #{execution_time}ms")
                return response
              else
                log_error("[USERINFO] ❌ Invalid user info response (#{response.class})")
                return nil
              end

            rescue => e
              execution_time = current_time_ms - start_time
              log_error("[USERINFO] ❌ User info fetch failed after #{execution_time}ms: #{e.message}")
              return nil
            end
          end

          private

          def build_token_params(client_options, authorization_code, redirect_uri, extra_params)
            params = {
              grant_type: 'authorization_code',
              code: authorization_code,
              redirect_uri: redirect_uri,
              client_id: client_options.identifier
            }

            # Add client secret to body if using client_secret_post method
            if client_options.secret && extra_params[:client_auth_method] == :client_secret_post
              params[:client_secret] = client_options.secret
              log_debug("[TOKEN] Using client_secret_post authentication method")
            else
              log_debug("[TOKEN] Using client_secret_basic authentication method (Authorization header)")
            end

            # Add PKCE verifier if present
            if extra_params[:code_verifier]
              params[:code_verifier] = extra_params[:code_verifier]
              log_debug("[TOKEN] Added PKCE code_verifier")
            end

            # Add scope if required
            if extra_params[:scope] && extra_params[:send_scope_to_token_endpoint]
              params[:scope] = Array(extra_params[:scope]).join(' ')
              log_debug("[TOKEN] Added scope: #{params[:scope]}")
            end

            log_info("[TOKEN] Token params: grant_type=#{params[:grant_type]}, redirect_uri=#{params[:redirect_uri]}, client_id=#{params[:client_id][0..10]}...")

            params
          end

          def build_token_headers(client_options)
            headers = {
              'Content-Type' => 'application/x-www-form-urlencoded',
              'Accept' => 'application/json'
            }

            # Add Basic Auth header for client authentication
            if client_options.secret && client_options.identifier
              credentials = "#{client_options.identifier}:#{client_options.secret}"
              auth_string = Base64.strict_encode64(credentials)
              headers['Authorization'] = "Basic #{auth_string}"

              log_info("[TOKEN] Built Basic Auth for client_id: #{client_options.identifier[0..10]}...")
              log_info("[TOKEN] Authorization header length: #{headers['Authorization'].length}")
            else
              log_error("[TOKEN] Missing client credentials! identifier: #{client_options.identifier ? 'present' : 'missing'}, secret: #{client_options.secret ? 'present' : 'missing'}")
            end

            headers
          end

          def current_time_ms
            (Time.now.to_f * 1000).to_i
          end

          def log_info(message)
            logger.info(message) if logger
          end

          def log_error(message)
            logger.error(message) if logger
          end

          def log_debug(message)
            logger.debug(message) if logger
          end

          def logger
            @logger ||= defined?(Rails) ? Rails.logger : Logger.new(STDOUT)
          end
        end

        # Token response wrapper with convenient accessors
        class TokenResponse
          attr_reader :raw_data

          def initialize(token_data)
            @raw_data = token_data
          end

          def access_token
            @raw_data['access_token']
          end

          def id_token
            @raw_data['id_token']
          end

          def refresh_token
            @raw_data['refresh_token']
          end

          def token_type
            @raw_data['token_type'] || 'Bearer'
          end

          def expires_in
            @raw_data['expires_in']&.to_i
          end

          def scope
            @raw_data['scope']
          end

          def expires_at
            return nil unless expires_in
            Time.now + expires_in
          end

          def expired?
            return false unless expires_at
            Time.now >= expires_at
          end

          def to_h
            @raw_data
          end

          # For backward compatibility
          def raw_attributes
            @raw_data
          end
        end
      end
    end
  end
end