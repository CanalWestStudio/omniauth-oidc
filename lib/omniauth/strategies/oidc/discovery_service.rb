# frozen_string_literal: true

require "ostruct"

module OmniAuth
  module Strategies
    class Oidc
      # OIDC discovery service with caching and performance monitoring
      class DiscoveryService
        CACHE_TTL = 300 # 5 minutes - OIDC configs rarely change
        FALLBACK_TIMEOUT = 2 # seconds

        class << self
          # Fetch OIDC configuration with caching and performance optimization
          def fetch_configuration(config_endpoint)
            start_time = current_time_ms

            begin
              log_info("[DISCOVERY] Fetching OIDC configuration from #{config_endpoint}")

              # Use the modernized HTTP client with caching
              response = HttpClient.get(config_endpoint, {
                timeout: Configuration.discovery_timeout,
                cache_ttl: Configuration.cache_ttl,
                headers: {
                  "Accept" => "application/json"
                }
              })

              execution_time = current_time_ms - start_time

              # HttpClient now returns parsed Hash responses
              if response.is_a?(Hash) && validate_configuration(response)
                log_info("[DISCOVERY] ✅ Configuration fetched in #{execution_time}ms")
                return create_config_object(response)
              else
                log_error("[DISCOVERY] ❌ Invalid configuration data")
                return nil
              end

            rescue => e
              execution_time = current_time_ms - start_time
              log_error("[DISCOVERY] ❌ Failed after #{execution_time}ms: #{e.message}")
              return nil
            end
          end

          def fetch_jwks(jwks_uri)
            return nil unless jwks_uri

            log_timing("JWKS fetch") do
              HttpClient.get(jwks_uri, {
                timeout: Configuration.discovery_timeout,
                cache_ttl: Configuration.cache_ttl
              })
            end
          rescue => e
            log_error("Failed to fetch JWKS from #{jwks_uri}: #{e.message}")
            nil
          end

          private

          def validate_configuration(config_data)
            return false unless config_data.is_a?(Hash)

            required_fields = %w[issuer authorization_endpoint token_endpoint]
            missing_fields = required_fields.select { |field| config_data[field].nil? || config_data[field].empty? }

            if missing_fields.any?
              log_error("[DISCOVERY] Missing required fields: #{missing_fields.join(', ')}")
              return false
            end

            true
          end

          def create_config_object(config_data)
            # Create an OpenStruct-like object that mimics the expected interface
            OpenStruct.new(config_data)
          end

          def current_time_ms
            (Time.now.to_f * 1000).to_i
          end

          def log_timing(description, &block)
            start_time = Time.now
            result = yield
            duration = ((Time.now - start_time) * 1000).round(1)
            log_info("[OIDC DISCOVERY] #{description} completed in #{duration}ms")
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
end