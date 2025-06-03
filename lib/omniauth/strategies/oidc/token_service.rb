# frozen_string_literal: true

require_relative 'http_client'
require 'uri'
require 'base64'
require 'json'

module OmniAuth
  module Strategies
    class Oidc
      # Optimized token exchange service with performance monitoring
      class TokenService
        TOKEN_TIMEOUT = 5 # seconds - token exchanges can be slower than discovery

        class << self
          # Exchange authorization code for tokens with optimized performance
          # Maintains backward compatibility with original callback signature
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

              # Build headers for token exchange
              headers = build_token_headers(client_options)

              # Prepare form data for token exchange
              form_data = URI.encode_www_form(token_params)

              # Use the modernized HTTP client
              response = HttpClient.post(
                token_endpoint,
                body: form_data,
                headers: headers,
                timeout: Configuration.token_timeout
              )

              execution_time = current_time_ms - start_time

              if response.is_a?(HTTPX::Response) && response.status >= 200 && response.status < 300
                token_data = parse_json_response(response.body)

                if token_data && validate_token_response(token_data)
                  log_info("[TOKEN] ✅ Token exchange completed in #{execution_time}ms")
                  return TokenResponse.new(token_data)
                else
                  log_error("[TOKEN] ❌ Invalid token response")
                  return nil
                end
              else
                status = response.is_a?(HTTPX::Response) ? response.status : "ERROR"
                log_error("[TOKEN] ❌ HTTP #{status}: Token exchange failed")
                return nil
              end

            rescue => e
              execution_time = current_time_ms - start_time
              log_error("[TOKEN] ❌ Token exchange failed after #{execution_time}ms: #{e.message}")
              raise
            end
          end

          # Fetch user info with optimized performance
          def fetch_user_info(userinfo_endpoint, access_token)
            return nil unless userinfo_endpoint && access_token

            start_time = current_time_ms

            begin
              log_info("[USERINFO] Fetching user info from #{URI.parse(userinfo_endpoint).host}")

              # Use the modernized HTTP client with bearer token
              response = HttpClient.get(userinfo_endpoint, {
                timeout: Configuration.userinfo_timeout,
                headers: {
                  "Authorization" => "Bearer #{access_token}",
                  "Accept" => "application/json"
                }
              })

              execution_time = current_time_ms - start_time

              if response.is_a?(HTTPX::Response) && response.status >= 200 && response.status < 300
                user_data = parse_json_response(response.body)

                if user_data
                  log_info("[USERINFO] ✅ User info fetched in #{execution_time}ms")
                  return user_data
                else
                  log_error("[USERINFO] ❌ Invalid user info response")
                  return nil
                end
              else
                status = response.is_a?(HTTPX::Response) ? response.status : "ERROR"
                log_error("[USERINFO] ❌ HTTP #{status}: User info fetch failed")
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

            # Add client secret if using client_secret_post
            if client_options.secret && extra_params[:client_auth_method] != :client_secret_basic
              params[:client_secret] = client_options.secret
            end

            # Add PKCE verifier if present
            if extra_params[:code_verifier]
              params[:code_verifier] = extra_params[:code_verifier]
            end

            # Add scope if required
            if extra_params[:scope]
              params[:scope] = Array(extra_params[:scope]).join(' ')
            end

            params
          end

          def build_token_headers(client_options)
            headers = {
              'Content-Type' => 'application/x-www-form-urlencoded',
              'Accept' => 'application/json'
            }

            # Add basic auth header if using client_secret_basic (default)
            if client_options.secret
              auth_string = Base64.strict_encode64("#{client_options.identifier}:#{client_options.secret}")
              headers['Authorization'] = "Basic #{auth_string}"
            end

            headers
          end

          def parse_json_response(body)
            JSON.parse(body)
          rescue JSON::ParserError => e
            log_error("[TOKEN] JSON parse error: #{e.message}")
            nil
          end

          def validate_token_response(token_data)
            # Check for required token response fields
            return false unless token_data.is_a?(Hash)
            return false unless token_data['access_token']

            # Warn about missing optional but common fields
            unless token_data['token_type']
              log_info("[TOKEN] Warning: token_type not present in response")
            end

            true
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

          # For backward compatibility with existing callback expectations
          def raw_attributes
            @raw_data
          end
        end
      end
    end
  end
end