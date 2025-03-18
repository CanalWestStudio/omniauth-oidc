# frozen_string_literal: true

module OmniAuth
  module Strategies
    class Oidc
      # Code request phase
      module Request
        def request_phase
          @identifier = client_options.identifier
          @secret = secret

          set_client_options_for_request_phase
          redirect authorize_uri
        end

        def authorize_uri # rubocop:disable Metrics/AbcSize
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
          end

          client.authorization_uri(opts.reject { |_k, v| v.nil? })
        end

        private

        def new_state
          state = if options.state.respond_to?(:call)
                    if options.state.arity == 1
                      options.state.call(env)
                    else
                      options.state.call
                    end
          end
          session["omniauth.state"] = state || SecureRandom.hex(16)
        end

        # Parse response from OIDC endpoint and set client options for request phase
        def set_client_options_for_request_phase # rubocop:disable Metrics/AbcSize
          client_options.host = host
          client_options.authorization_endpoint = config.authorization_endpoint
          client_options.token_endpoint = config.token_endpoint
          client_options.userinfo_endpoint = config.userinfo_endpoint
          client_options.jwks_uri = config.jwks_uri

          return unless config.respond_to?(:end_session_endpoint)

          client_options.end_session_endpoint = config.end_session_endpoint
        end
      end
    end
  end
end
