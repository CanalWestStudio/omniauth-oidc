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

        # Individual endpoint accessors - prefer configuration over discovery
        def issuer
          oidc_configuration['issuer']
        end

        def authorization_endpoint
          endpoint_with_fallback(:authorization_endpoint, 'authorization_endpoint')
        end

        def token_endpoint
          endpoint_with_fallback(:token_endpoint, 'token_endpoint')
        end

        def userinfo_endpoint
          endpoint_with_fallback(:userinfo_endpoint, 'userinfo_endpoint')
        end

        def jwks_uri
          endpoint_with_fallback(:jwks_uri, 'jwks_uri')
        end

        def end_session_endpoint
          endpoint_with_fallback(:end_session_endpoint, 'end_session_logout_endpoint')
        end

        # Configuration discovery accessors with defaults
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

          fetch_with_cache(cache_key, @@jwks_cache, JWKS_CACHE_TTL, 'JWKS') do
            fetch_jwks
          end
        end

        private

        def endpoint_with_fallback(config_method, discovery_key)
          configuration.send(config_method) || oidc_configuration[discovery_key]
        end

        def fetch_with_cache(cache_key, cache_store, ttl, log_name)
          if cache_store[cache_key] && cache_valid?(cache_store[cache_key], ttl)
            log_info("[OIDC Discovery] Using cached #{log_name}")
            return cache_store[cache_key][:data]
          end

          data = yield

          cache_store[cache_key] = {
            data: data,
            cached_at: Time.now
          }

          data
        end

        def cache_valid?(cache_entry, ttl)
          return false unless cache_entry

          Time.now - cache_entry[:cached_at] < ttl
        end

        def fetch_oidc_configuration
          fetch_with_timing(configuration.config_endpoint, 'configuration') do |endpoint|
            config_data = Http::Client.get(endpoint, timeout: 5)
            validate_configuration_response!(config_data)
            config_data
          end
        rescue => e
          raise OmniauthOidc::Errors::ConfigurationError, "Failed to fetch OIDC configuration: #{e.message}"
        end

        def fetch_jwks
          return nil unless jwks_uri

          fetch_with_timing(jwks_uri, 'JWKS') do |endpoint|
            jwks_data = Http::Client.get(endpoint, timeout: 5)
            validate_jwks_response!(jwks_data)
            jwks_data
          end
        rescue => e
          raise OmniauthOidc::Errors::VerificationError, "Failed to fetch JWKS: #{e.message}"
        end

        def fetch_with_timing(endpoint, description)
          log_info("[OIDC Discovery] Fetching #{description} from #{endpoint}")
          start_time = Time.now

          result = yield(endpoint)

          elapsed_time = ((Time.now - start_time) * 1000).round(2)
          log_info("[OIDC Discovery] #{description.capitalize} fetched in #{elapsed_time}ms")

          result
        rescue => e
          elapsed_time = ((Time.now - start_time) * 1000).round(2)
          log_error("[OIDC Discovery] #{description.capitalize} fetch failed after #{elapsed_time}ms: #{e.message}")
          raise
        end

        def validate_configuration_response!(config_data)
          unless config_data.is_a?(Hash)
            raise OmniauthOidc::Errors::ConfigurationError, "Invalid configuration response format"
          end

          validate_required_configuration!(config_data)
        end

        def validate_jwks_response!(jwks_data)
          unless jwks_data.is_a?(Hash) && jwks_data['keys']
            raise OmniauthOidc::Errors::VerificationError, "Invalid JWKS response format"
          end
        end

        def validate_required_configuration!(config)
          required_fields = %w[issuer authorization_endpoint token_endpoint]
          missing_fields = required_fields.select { |field| config[field].nil? || config[field].empty? }

          if missing_fields.any?
            raise OmniauthOidc::Errors::ConfigurationError,
                  "Missing required configuration fields: #{missing_fields.join(', ')}"
          end

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
          cache_valid?(@@jwks_cache[cache_key], JWKS_CACHE_TTL)
        end

        def config_cache_valid?(cache_key)
          cache_valid?(@@config_cache[cache_key], CACHE_TTL)
        end

        def log_info(message)
          logger&.info(message)
        end

        def log_error(message)
          logger&.error(message)
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