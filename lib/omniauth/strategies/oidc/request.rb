# frozen_string_literal: true

require_relative 'discovery_service'

module OmniAuth
  module Strategies
    class Oidc
      # Optimized request phase with performance monitoring
      module Request
        def request_phase
          log_timing("[OIDC REQUEST] Full request phase") do
            @identifier = client_options.identifier
            @secret = secret

            set_client_options_for_request_phase

            auth_uri = authorize_uri
            log_info("[OIDC REQUEST] Redirecting to authorization endpoint: #{auth_uri[0..100]}...")
            redirect auth_uri
          end
        rescue => e
          log_error("[OIDC REQUEST] Request phase failed: #{e.message}")
          raise
        end

        def authorize_uri # rubocop:disable Metrics/AbcSize
          log_timing("[OIDC REQUEST] Building authorization URI") do
            client.redirect_uri = redirect_uri
            opts = serialized_request_options

            opts.merge!(options.extra_authorize_params) unless options.extra_authorize_params.empty?

            options.allow_authorize_params.each do |key|
              opts[key] = request.params[key.to_s] unless opts.key?(key)
            end

            # Add environment to the request if it is set
            opts[:environment] = client_options.environment if client_options.environment

            if options.pkce
              verifier = options.pkce_verifier ? options.pkce_verifier.call : SecureRandom.hex(64)

              opts.merge!(pkce_authorize_params(verifier))
              session["omniauth.pkce.verifier"] = verifier
              log_info("[OIDC REQUEST] PKCE enabled with code challenge")
            end

            final_uri = client.authorization_uri(opts.reject { |_k, v| v.nil? })
            log_info("[OIDC REQUEST] Authorization URI built successfully")
            final_uri
          end
        end

        private

        def new_state
          log_timing("[OIDC REQUEST] Generating state parameter") do
            state = if options.state.respond_to?(:call)
                      if options.state.arity == 1
                        options.state.call(env)
                      else
                        options.state.call
                      end
            end

            generated_state = state || SecureRandom.hex(16)
            session["omniauth.state"] = generated_state
            log_debug("[OIDC REQUEST] State parameter generated")
            generated_state
          end
        end

        # Parse response from OIDC endpoint and set client options for request phase
        def set_client_options_for_request_phase # rubocop:disable Metrics/AbcSize
          log_timing("[OIDC REQUEST] Setting client options") do
            client_options.host = host
            client_options.authorization_endpoint = config.authorization_endpoint
            client_options.token_endpoint = config.token_endpoint
            client_options.userinfo_endpoint = config.userinfo_endpoint
            client_options.jwks_uri = config.jwks_uri

            if config.respond_to?(:end_session_endpoint)
              client_options.end_session_endpoint = config.end_session_endpoint
            end

            log_info("[OIDC REQUEST] Client options configured successfully")
          end
        end

        # Performance logging helpers
        def log_timing(description, &block)
          start_time = Time.now
          result = yield
          duration = ((Time.now - start_time) * 1000).round(1)
          log_info("#{description} completed in #{duration}ms")
          result
        end

        def log_info(message)
          logger.info(message) if logger
        end

        def log_debug(message)
          logger.debug(message) if logger
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
