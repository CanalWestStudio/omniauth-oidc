# frozen_string_literal: true

require_relative 'http/client'

module OmniAuth
  module Strategies
    class Oidc
      # OIDC Discovery service - handles configuration and JWKS fetching
      class Discovery
        # More aggressive caching for performance
        CACHE_TTL = 900 # 15 minutes cache for configuration (up from 1 hour)
        JWKS_CACHE_TTL = 300 # 5 minutes cache for JWKS

        # Class-level cache to share across instances
        @@config_cache = {}
        @@jwks_cache = {}

        attr_reader :configuration

        def initialize(configuration)
          @configuration = configuration
        end

        # Clear class-level cache (useful for testing)
        def self.clear_cache!
          @@config_cache.clear
          @@jwks_cache.clear
        end

        # Get OIDC configuration from discovery endpoint with caching
        def oidc_configuration
          cache_key = configuration.config_endpoint

          # Check class-level cache first
          if @@config_cache[cache_key] && config_cache_valid?(cache_key)
            log_info("[OIDC Discovery] Using cached configuration")
            return @@config_cache[cache_key][:data]
          end

          # Fetch fresh configuration
          config_data = fetch_oidc_configuration

          # Cache it
          @@config_cache[cache_key] = {
            data: config_data,
            cached_at: Time.now
          }

          config_data
        end

        # Individual endpoint accessors
        def issuer
          oidc_configuration['issuer']
        end

        def authorization_endpoint
          configuration.authorization_endpoint || oidc_configuration['authorization_endpoint']
        end

        def token_endpoint
          configuration.token_endpoint || oidc_configuration['token_endpoint']
        end

        def userinfo_endpoint
          configuration.userinfo_endpoint || oidc_configuration['userinfo_endpoint']
        end

        def jwks_uri
          configuration.jwks_uri || oidc_configuration['jwks_uri']
        end

        def end_session_endpoint
          configuration.end_session_endpoint || oidc_configuration['end_session_logout_endpoint']
        end

        def scopes_supported
          oidc_configuration['scopes_supported'] || ['openid']
        end

        def response_types_supported
          oidc_configuration['response_types_supported'] || ['code']
        end

        def subject_types_supported
          oidc_configuration['subject_types_supported'] || ['public']
        end

        def id_token_signing_alg_values_supported
          oidc_configuration['id_token_signing_alg_values_supported'] || ['RS256']
        end

        # Fetch JWKS for token verification
        def jwks
          cache_key = jwks_uri
          return nil unless cache_key

          # Check class-level cache first
          if @@jwks_cache[cache_key] && jwks_cache_valid?(cache_key)
            log_info("[OIDC Discovery] Using cached JWKS")
            return @@jwks_cache[cache_key][:data]
          end

          # Fetch fresh JWKS
          jwks_data = fetch_jwks

          # Cache it
          @@jwks_cache[cache_key] = {
            data: jwks_data,
            cached_at: Time.now
          }

          jwks_data
        end

        private

        def fetch_oidc_configuration
          endpoint = configuration.config_endpoint

          log_info("[OIDC Discovery] Fetching configuration from #{endpoint}")
          start_time = Time.now

          # Use shorter timeout for better performance
          config_data = Http::Client.get(endpoint, timeout: 5)  # Reduced from 10s

          elapsed_time = ((Time.now - start_time) * 1000).round(2)
          log_info("[OIDC Discovery] Configuration fetched in #{elapsed_time}ms")

          unless config_data.is_a?(Hash)
            raise OmniauthOidc::Errors::ConfigurationError, "Invalid configuration response format"
          end

          validate_required_configuration!(config_data)
          config_data
        rescue => e
          elapsed_time = ((Time.now - start_time) * 1000).round(2)
          log_error("[OIDC Discovery] Configuration fetch failed after #{elapsed_time}ms: #{e.message}")
          raise OmniauthOidc::Errors::ConfigurationError, "Failed to fetch OIDC configuration: #{e.message}"
        end

        def fetch_jwks
          return nil unless jwks_uri

          log_info("[OIDC Discovery] Fetching JWKS from #{jwks_uri}")
          start_time = Time.now

          # Use shorter timeout for better performance
          jwks_data = Http::Client.get(jwks_uri, timeout: 5)  # Reduced from 10s

          elapsed_time = ((Time.now - start_time) * 1000).round(2)
          log_info("[OIDC Discovery] JWKS fetched in #{elapsed_time}ms")

          unless jwks_data.is_a?(Hash) && jwks_data['keys']
            raise OmniauthOidc::Errors::VerificationError, "Invalid JWKS response format"
          end

          jwks_data
        rescue => e
          elapsed_time = ((Time.now - start_time) * 1000).round(2)
          log_error("[OIDC Discovery] JWKS fetch failed after #{elapsed_time}ms: #{e.message}")
          raise OmniauthOidc::Errors::VerificationError, "Failed to fetch JWKS: #{e.message}"
        end

        def validate_required_configuration!(config)
          required_fields = %w[issuer authorization_endpoint token_endpoint]

          missing_fields = required_fields.select { |field| config[field].nil? || config[field].empty? }

          if missing_fields.any?
            raise OmniauthOidc::Errors::ConfigurationError,
                  "Missing required configuration fields: #{missing_fields.join(', ')}"
          end

          # Validate issuer matches expected format
          unless valid_issuer?(config['issuer'])
            raise OmniauthOidc::Errors::ConfigurationError, "Invalid issuer format: #{config['issuer']}"
          end
        end

        def valid_issuer?(issuer)
          return false unless issuer

          uri = URI.parse(issuer)
          uri.is_a?(URI::HTTP) || uri.is_a?(URI::HTTPS)
        rescue URI::InvalidURIError
          false
        end

        def jwks_cache_valid?(cache_key)
          return false unless @@jwks_cache[cache_key]

          Time.now - @@jwks_cache[cache_key][:cached_at] < JWKS_CACHE_TTL
        end

        def config_cache_valid?(cache_key)
          return false unless @@config_cache[cache_key]

          Time.now - @@config_cache[cache_key][:cached_at] < CACHE_TTL
        end

        def log_info(message)
          return unless logger

          logger.info(message)
        end

        def log_error(message)
          return unless logger

          logger.error(message)
        end

        def logger
          @logger ||= begin
            if defined?(Rails) && Rails.respond_to?(:logger) && Rails.logger
              Rails.logger
            elsif defined?(Logger)
              Logger.new(STDOUT)
            end
          end
        end
      end
    end
  end
end