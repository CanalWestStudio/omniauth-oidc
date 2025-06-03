require_relative 'http_client'

module OmniAuth
  module Strategies
    class Oidc
      # Optimized discovery document service with caching and performance monitoring
      class DiscoveryService
        CACHE_TTL = 300 # 5 minutes - OIDC configs rarely change
        FALLBACK_TIMEOUT = 2 # seconds

        class << self
          def fetch_configuration(endpoint_url)
            return nil unless endpoint_url

            cache_key = "oidc_discovery:#{endpoint_url}"

            log_timing("Discovery document fetch") do
              config_data = HttpClient.get(
                endpoint_url,
                timeout: FALLBACK_TIMEOUT,
                cache_key: cache_key
              )

              if config_data.is_a?(Hash)
                OpenStruct.new(config_data)
              else
                log_error("Invalid discovery document format from #{endpoint_url}")
                nil
              end
            end
          rescue => e
            log_error("Failed to fetch discovery document from #{endpoint_url}: #{e.message}")
            nil
          end

          def fetch_jwks(jwks_uri)
            return nil unless jwks_uri

            cache_key = "oidc_jwks:#{jwks_uri}"

            log_timing("JWKS fetch") do
              HttpClient.get(
                jwks_uri,
                timeout: FALLBACK_TIMEOUT,
                cache_key: cache_key
              )
            end
          rescue => e
            log_error("Failed to fetch JWKS from #{jwks_uri}: #{e.message}")
            nil
          end

          private

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