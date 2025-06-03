# frozen_string_literal: true

module OmniAuth
  module Strategies
    class Oidc
      # Centralized configuration for performance settings
      class Configuration
        class << self
          # HTTP Timeout Settings
          def discovery_timeout
            @discovery_timeout ||= ENV.fetch('OIDC_DISCOVERY_TIMEOUT', '2').to_i
          end

          def discovery_timeout=(value)
            @discovery_timeout = value.to_i
          end

          def token_timeout
            @token_timeout ||= ENV.fetch('OIDC_TOKEN_TIMEOUT', '5').to_i
          end

          def token_timeout=(value)
            @token_timeout = value.to_i
          end

          def userinfo_timeout
            @userinfo_timeout ||= ENV.fetch('OIDC_USERINFO_TIMEOUT', '3').to_i
          end

          def userinfo_timeout=(value)
            @userinfo_timeout = value.to_i
          end

          def jwks_timeout
            @jwks_timeout ||= ENV.fetch('OIDC_JWKS_TIMEOUT', '2').to_i
          end

          def jwks_timeout=(value)
            @jwks_timeout = value.to_i
          end

          def connect_timeout
            @connect_timeout ||= ENV.fetch('OIDC_CONNECT_TIMEOUT', '2').to_i
          end

          def connect_timeout=(value)
            @connect_timeout = value.to_i
          end

          # Cache Settings
          def cache_ttl
            @cache_ttl ||= ENV.fetch('OIDC_CACHE_TTL', '300').to_i
          end

          def cache_ttl=(value)
            @cache_ttl = value.to_i
          end

          def cache_enabled?
            @cache_enabled ||= ENV.fetch('OIDC_CACHE_ENABLED', 'true') == 'true'
          end

          def cache_enabled=(value)
            @cache_enabled = !!value
          end

          # Connection Settings
          def connection_pool_size
            @connection_pool_size ||= ENV.fetch('OIDC_CONNECTION_POOL_SIZE', '5').to_i
          end

          def connection_pool_size=(value)
            @connection_pool_size = value.to_i
          end

          def keep_alive_timeout
            @keep_alive_timeout ||= ENV.fetch('OIDC_KEEP_ALIVE_TIMEOUT', '30').to_i
          end

          def keep_alive_timeout=(value)
            @keep_alive_timeout = value.to_i
          end

          # Retry Settings
          def max_retries
            @max_retries ||= ENV.fetch('OIDC_MAX_RETRIES', '1').to_i
          end

          def max_retries=(value)
            @max_retries = value.to_i
          end

          def retry_delay
            @retry_delay ||= ENV.fetch('OIDC_RETRY_DELAY', '0.1').to_f
          end

          def retry_delay=(value)
            @retry_delay = value.to_f
          end

          # Logging Settings
          def performance_logging_enabled?
            @performance_logging ||= ENV.fetch('OIDC_PERFORMANCE_LOGGING', 'true') == 'true'
          end

          def performance_logging_enabled=(value)
            @performance_logging = !!value
          end

          def debug_logging_enabled?
            @debug_logging ||= ENV.fetch('OIDC_DEBUG_LOGGING', 'false') == 'true'
          end

          def debug_logging_enabled=(value)
            @debug_logging = !!value
          end

          # Security Settings
          def verify_ssl?
            @verify_ssl ||= ENV.fetch('OIDC_VERIFY_SSL', 'true') == 'true'
          end

          def verify_ssl=(value)
            @verify_ssl = !!value
          end

          # Provider-specific optimizations
          def intuit_optimizations?
            @intuit_optimizations ||= ENV.fetch('OIDC_INTUIT_OPTIMIZATIONS', 'false') == 'true'
          end

          def intuit_optimizations=(value)
            @intuit_optimizations = !!value
          end

          # Configuration helpers
          def configure
            yield self if block_given?
          end

          def reset!
            instance_variables.each do |var|
              remove_instance_variable(var)
            end
          end

          def to_h
            {
              discovery_timeout: discovery_timeout,
              token_timeout: token_timeout,
              userinfo_timeout: userinfo_timeout,
              jwks_timeout: jwks_timeout,
              connect_timeout: connect_timeout,
              cache_ttl: cache_ttl,
              cache_enabled: cache_enabled?,
              connection_pool_size: connection_pool_size,
              keep_alive_timeout: keep_alive_timeout,
              max_retries: max_retries,
              retry_delay: retry_delay,
              performance_logging_enabled: performance_logging_enabled?,
              debug_logging_enabled: debug_logging_enabled?,
              verify_ssl: verify_ssl?,
              intuit_optimizations: intuit_optimizations?
            }
          end

          # Apply Intuit-specific optimizations
          def apply_intuit_optimizations!
            self.discovery_timeout = 2
            self.token_timeout = 3
            self.userinfo_timeout = 2
            self.jwks_timeout = 2
            self.connect_timeout = 1
            self.cache_ttl = 600 # 10 minutes for Intuit configs
            self.cache_enabled = true
            self.max_retries = 2
            self.intuit_optimizations = true

            puts "[OIDC CONFIG] Applied Intuit-specific optimizations"
          end

          # Apply aggressive performance optimizations
          def apply_aggressive_optimizations!
            self.discovery_timeout = 1
            self.token_timeout = 2
            self.userinfo_timeout = 1
            self.jwks_timeout = 1
            self.connect_timeout = 1
            self.cache_ttl = 900 # 15 minutes
            self.cache_enabled = true
            self.max_retries = 0 # No retries for maximum speed

            puts "[OIDC CONFIG] Applied aggressive performance optimizations (use with caution)"
          end
        end
      end
    end
  end
end