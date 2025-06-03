require_relative 'http_client'
require 'uri'
require 'base64'

module OmniAuth
  module Strategies
    class Oidc
      # Optimized token exchange service
      class TokenService
        TOKEN_TIMEOUT = 5 # seconds - token exchanges can be slower than discovery

        class << self
          def exchange_code_for_tokens(config, client_options, authorization_code, redirect_uri, extra_params = {})
            log_timing("Token exchange") do
              token_endpoint = config.token_endpoint
              raise "Token endpoint not available" unless token_endpoint

              # Build token request
              token_params = build_token_params(
                client_options,
                authorization_code,
                redirect_uri,
                extra_params
              )

              # Prepare headers
              headers = build_token_headers(client_options)

              # Make token request
              log_info("[OIDC TOKEN] Exchanging code for tokens at #{token_endpoint}")

              response = HttpClient.post(
                token_endpoint,
                body: URI.encode_www_form(token_params),
                headers: headers,
                timeout: TOKEN_TIMEOUT
              )

              if response.is_a?(Hash) && response['access_token']
                log_info("[OIDC TOKEN] Token exchange successful")
                TokenResponse.new(response)
              else
                log_error("Invalid token response: #{response}")
                raise "Invalid token response from provider"
              end
            end
          rescue => e
            log_error("Token exchange failed: #{e.message}")
            raise
          end

          def fetch_user_info(userinfo_endpoint, access_token)
            return nil unless userinfo_endpoint && access_token

            log_timing("UserInfo fetch") do
              headers = {
                'Authorization' => "Bearer #{access_token}",
                'Accept' => 'application/json'
              }

              log_info("[OIDC USERINFO] Fetching user info from #{userinfo_endpoint}")

              response = HttpClient.get(
                userinfo_endpoint,
                headers: headers,
                timeout: TOKEN_TIMEOUT
              )

              if response.is_a?(Hash)
                log_info("[OIDC USERINFO] User info fetch successful")
                response
              else
                log_error("Invalid userinfo response: #{response}")
                nil
              end
            end
          rescue => e
            log_error("UserInfo fetch failed: #{e.message}")
            nil
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

          def log_timing(description, &block)
            start_time = Time.now
            result = yield
            duration = ((Time.now - start_time) * 1000).round(1)
            log_info("[OIDC TOKEN TIMING] #{description} completed in #{duration}ms")
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

        # Token response wrapper
        class TokenResponse
          attr_reader :access_token, :id_token, :refresh_token, :token_type, :expires_in

          def initialize(response_hash)
            @access_token = response_hash['access_token']
            @id_token = response_hash['id_token']
            @refresh_token = response_hash['refresh_token']
            @token_type = response_hash['token_type'] || 'Bearer'
            @expires_in = response_hash['expires_in']&.to_i
            @raw_response = response_hash
          end

          def raw_attributes
            @raw_response
          end

          def expired?
            return false unless @expires_in
            # Add some buffer for clock skew
            Time.now.to_i >= (@created_at.to_i + @expires_in - 30)
          end

          private

          def initialize_timestamps
            @created_at = Time.now
          end
        end
      end
    end
  end
end