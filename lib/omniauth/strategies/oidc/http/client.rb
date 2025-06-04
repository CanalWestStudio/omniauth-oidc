# frozen_string_literal: true

require 'faraday'
require 'faraday/net_http_persistent'
require 'faraday/retry'
require_relative 'response'

module OmniAuth
  module Strategies
    class Oidc
      module Http
        # High-performance HTTP client for OIDC operations with connection pooling
        class Client
          # Aggressive timeouts for better performance
          DEFAULT_TIMEOUT = 5      # Reduced from 10s
          DEFAULT_OPEN_TIMEOUT = 3 # Connection establishment timeout
          DEFAULT_HEADERS = {
            'User-Agent' => 'omniauth-oidc-gem/2.0',
            'Accept' => 'application/json',
            'Connection' => 'keep-alive'
          }.freeze

          class << self
            def get(url, headers: {}, timeout: DEFAULT_TIMEOUT)
              execute_request(:get, url, headers: headers, timeout: timeout)
            end

            def post(url, body: nil, headers: {}, timeout: DEFAULT_TIMEOUT)
              execute_request(:post, url, body: body, headers: headers, timeout: timeout)
            end

            private

            def execute_request(method, url, body: nil, headers: {}, timeout: DEFAULT_TIMEOUT)
              request_headers = DEFAULT_HEADERS.merge(headers)

              log_request(method, url)
              start_time = Time.now

              response = connection(timeout).public_send(method, url) do |req|
                request_headers.each { |key, value| req.headers[key] = value }
                req.body = body if body && method == :post
              end

              elapsed_time = ((Time.now - start_time) * 1000).round(2)
              wrapped_response = Response.new(response)
              log_response(wrapped_response, elapsed_time)

              handle_response(wrapped_response)
            rescue Faraday::TimeoutError => e
              elapsed_time = ((Time.now - start_time) * 1000).round(2)
              logger&.error("[OIDC HTTP] Timeout after #{elapsed_time}ms: #{e.message}")
              raise OmniauthOidc::Errors::TokenError, "Request timeout after #{elapsed_time}ms: #{e.message}"
            rescue Faraday::ConnectionFailed => e
              elapsed_time = ((Time.now - start_time) * 1000).round(2)
              logger&.error("[OIDC HTTP] Connection failed after #{elapsed_time}ms: #{e.message}")
              raise OmniauthOidc::Errors::TokenError, "Connection failed: #{e.message}"
            rescue Faraday::Error => e
              elapsed_time = ((Time.now - start_time) * 1000).round(2)
              logger&.error("[OIDC HTTP] Network error after #{elapsed_time}ms: #{e.message}")
              raise OmniauthOidc::Errors::TokenError, "Network error: #{e.message}"
            rescue StandardError => e
              elapsed_time = ((Time.now - start_time) * 1000).round(2)
              logger&.error("[OIDC HTTP] Request failed after #{elapsed_time}ms: #{e.message}")
              raise OmniauthOidc::Errors::TokenError, "HTTP request failed: #{e.message}"
            end

            def connection(timeout = DEFAULT_TIMEOUT)
              @connections ||= {}
              key = "#{timeout}_#{DEFAULT_OPEN_TIMEOUT}"

              @connections[key] ||= Faraday.new do |faraday|
                # Use persistent HTTP connections for performance
                faraday.adapter :net_http_persistent do |http|
                  http.idle_timeout = 5  # Keep connections alive for 5 seconds
                  # Note: pool_size is not configurable in net-http-persistent
                end

                # Set timeouts
                faraday.options.timeout = timeout
                faraday.options.open_timeout = DEFAULT_OPEN_TIMEOUT

                # Handle JSON responses
                faraday.response :json, content_type: /\bjson$/

                # Add retry middleware for temporary failures
                faraday.request :retry, max: 2, interval: 0.1,
                                retry_statuses: [429, 500, 502, 503, 504],
                                methods: [:get, :post]
              end
            end

            def handle_response(response)
              if response.success?
                response.parsed_body || response.body
              else
                raise OmniauthOidc::Errors::TokenError, "HTTP #{response.status}: #{response.error_message}"
              end
            end

            def log_request(method, url)
              return unless logger

              # Sanitize URL to remove sensitive query parameters
              sanitized_url = sanitize_url_for_logging(url)
              logger.info("[OIDC HTTP] #{method.upcase} #{sanitized_url}")
            end

            def log_response(response, elapsed_time = nil)
              return unless logger

              status_text = response.success? ? "SUCCESS" : "ERROR"
              time_info = elapsed_time ? " (#{elapsed_time}ms)" : ""
              logger.info("[OIDC HTTP] Response: #{response.status} #{status_text}#{time_info}")

              if response.error?
                # Don't log full error message as it might contain sensitive data
                logger.error("[OIDC HTTP] Error: HTTP #{response.status}")
              end
            end

            def sanitize_url_for_logging(url)
              uri = URI.parse(url)

              # Remove query parameters that might contain sensitive data
              if uri.query
                # Parse query parameters
                params = URI.decode_www_form(uri.query)

                # List of sensitive parameters to filter out
                sensitive_params = %w[
                  code access_token refresh_token id_token
                  state nonce client_secret authorization_code
                  realmId realm_id companyID company_id
                  user_id uid email phone
                ]

                # Filter out sensitive parameters
                safe_params = params.reject do |key, _|
                  sensitive_params.any? { |sensitive| key.to_s.downcase.include?(sensitive.downcase) }
                end

                # Rebuild URL with safe parameters only
                uri.query = safe_params.any? ? URI.encode_www_form(safe_params) : nil
              end

              uri.to_s
            rescue URI::InvalidURIError
              # If URL parsing fails, just return a generic message
              "[SANITIZED_URL]"
            end

            def logger
              @logger ||= begin
                if defined?(Rails) && Rails.respond_to?(:logger) && Rails.logger
                  Rails.logger
                elsif defined?(Logger)
                  Logger.new($stdout)
                end
              end
            end
          end
        end
      end
    end
  end
end