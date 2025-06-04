# frozen_string_literal: true

require_relative 'http/client'

module OmniAuth
  module Strategies
    class Oidc
      # OIDC Discovery service - handles configuration and JWKS fetching
      class Discovery
        CACHE_TTL = 3600 # 1 hour cache for configuration
        JWKS_CACHE_TTL = 300 # 5 minutes cache for JWKS

        attr_reader :configuration

        def initialize(configuration)
          @configuration = configuration
        end

        # Get OIDC configuration from discovery endpoint
        def oidc_configuration
          @oidc_configuration ||= fetch_oidc_configuration
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
          return @jwks if @jwks && jwks_cache_valid?

          @jwks = fetch_jwks
          @jwks_cached_at = Time.now
          @jwks
        end

        private

        def fetch_oidc_configuration
          endpoint = configuration.config_endpoint

          log_info("[OIDC Discovery] Fetching configuration from #{endpoint}")

          config_data = Http::Client.get(endpoint, timeout: 10)

          unless config_data.is_a?(Hash)
            raise OmniauthOidc::Errors::ConfigurationError, "Invalid configuration response format"
          end

          validate_required_configuration!(config_data)

          log_info("[OIDC Discovery] Configuration fetched successfully")
          config_data
        rescue => e
          log_error("[OIDC Discovery] Configuration fetch failed: #{e.message}")
          raise OmniauthOidc::Errors::ConfigurationError, "Failed to fetch OIDC configuration: #{e.message}"
        end

        def fetch_jwks
          return nil unless jwks_uri

          log_info("[OIDC Discovery] Fetching JWKS from #{jwks_uri}")

          jwks_data = Http::Client.get(jwks_uri, timeout: 10)

          unless jwks_data.is_a?(Hash) && jwks_data['keys']
            raise OmniauthOidc::Errors::VerificationError, "Invalid JWKS response format"
          end

          log_info("[OIDC Discovery] JWKS fetched successfully")
          jwks_data
        rescue => e
          log_error("[OIDC Discovery] JWKS fetch failed: #{e.message}")
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

        def jwks_cache_valid?
          return false unless @jwks_cached_at

          Time.now - @jwks_cached_at < JWKS_CACHE_TTL
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