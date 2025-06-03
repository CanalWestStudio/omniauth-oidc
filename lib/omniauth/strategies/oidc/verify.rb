# frozen_string_literal: true

require_relative 'discovery_service'

module OmniAuth
  module Strategies
    class Oidc
      # Token verification phase - Optimized for performance
      module Verify # rubocop:disable Metrics/ModuleLength
        def secret
          base64_decoded_jwt_secret || client_options.secret
        end

        # https://tools.ietf.org/html/rfc7636#appendix-A
        def pkce_authorize_params(verifier)
          {
            code_challenge: options.pkce_options[:code_challenge].call(verifier),
            code_challenge_method: options.pkce_options[:code_challenge_method]
          }
        end

        # Looks for key defined in omniauth initializer, if none is defined
        # falls back to using jwks_uri returned by OIDC config_endpoint
        def public_key
          @public_key ||= if configured_public_key
                            configured_public_key
          elsif config.jwks_uri
                            fetch_key_optimized
          end
        end

        private

        attr_reader :decoded_id_token

        # Optimized key fetching with caching
        def fetch_key_optimized
          log_timing("[OIDC VERIFY] JWKS fetch") do
            jwks_data = DiscoveryService.fetch_jwks(config.jwks_uri)
            if jwks_data
              parse_jwk_key(jwks_data)
            else
              log_error("[OIDC VERIFY] Failed to fetch JWKS, falling back to original method")
              fetch_key
            end
          end
        end

        # Legacy method - kept for fallback
        def fetch_key
          parse_jwk_key(jwks_key)
        end

        def jwks_key
          @_jwks_key ||= Transport.request('GET', config.jwks_uri, nil, nil, false)
        end

        def base64_decoded_jwt_secret
          return unless options.jwt_secret_base64

          Base64.decode64(options.jwt_secret_base64)
        end

        def verify_id_token!(id_token)
          return unless id_token

          log_timing("[OIDC VERIFY] ID token verification") do
            decode_id_token(id_token).verify!(issuer: config.issuer,
                                              client_id: client_options.identifier,
                                              nonce: params["nonce"].presence || stored_nonce)
          end
        end

        def decode_id_token(id_token)
          log_timing("[OIDC VERIFY] ID token decode") do
            decoded = JSON::JWT.decode(id_token, :skip_verification)
            algorithm = decoded.algorithm.to_sym

            validate_client_algorithm!(algorithm)

            keyset =
              case algorithm
              when :HS256, :HS384, :HS512
                secret
              else
                public_key
              end

            decoded.verify!(keyset)
            @decoded_id_token = ::OpenIDConnect::ResponseObject::IdToken.new(decoded)
          end
        rescue JSON::JWK::Set::KidNotFound
          # Workaround for https://github.com/nov/json-jwt/pull/92#issuecomment-824654949
          raise if decoded&.header&.key?("kid")

          log_timing("[OIDC VERIFY] Fallback key verification") do
            decoded = decode_with_each_key!(id_token, keyset)
            raise unless decoded
            @decoded_id_token = decoded
          end
        end

        # Check for jwt to match defined client_signing_alg
        def validate_client_algorithm!(algorithm)
          client_signing_alg = options.client_signing_alg&.to_sym

          return unless client_signing_alg
          return if algorithm == client_signing_alg

          reason = "Received JWT is signed with #{algorithm}, but client_singing_alg is \
            configured for #{client_signing_alg}"
          raise CallbackError, error: :invalid_jwt_algorithm, reason: reason, uri: params["error_uri"]
        end

        def decode!(id_token, key)
          ::OpenIDConnect::ResponseObject::IdToken.decode(id_token, key)
        end

        def decode_with_each_key!(id_token, keyset)
          return unless keyset.is_a?(JSON::JWK::Set)

          keyset.each do |key|
            begin
              decoded = decode!(id_token, key)
            rescue JSON::JWS::VerificationFailed, JSON::JWS::UnexpectedAlgorithm, JSON::JWK::UnknownAlgorithm
              next
            end

            return decoded if decoded
          end

          nil
        end

        def stored_nonce
          session.delete("omniauth.nonce")
        end

        def configured_public_key
          @configured_public_key ||= if options.client_jwk_signing_key
                                       parse_jwk_key(options.client_jwk_signing_key)
          elsif options.client_x509_signing_key
                                       parse_x509_key(options.client_x509_signing_key)
          end
        end

        def parse_x509_key(key)
          OpenSSL::X509::Certificate.new(key).public_key
        end

        def parse_jwk_key(key)
          json = key.is_a?(String) ? JSON.parse(key) : key
          return JSON::JWK::Set.new(json["keys"]) if json.key?("keys")

          JSON::JWK.new(json)
        end

        def decode(str)
          UrlSafeBase64.decode64(str).unpack1("B*").to_i(2).to_s
        end

        def id_token_raw_attributes
          decoded_id_token.raw_attributes
        end

        def user_info
          return @user_info if @user_info

          log_timing("[OIDC VERIFY] User info processing") do
            if id_token_raw_attributes
              merged_user_info = access_token.userinfo!.raw_attributes.merge(id_token_raw_attributes)

              @user_info = ::OpenIDConnect::ResponseObject::UserInfo.new(
                # transform keys to ensure valid UserInfo object
                merged_user_info.deep_transform_keys(&:underscore)
              )
            else
              @user_info = access_token.userinfo!
            end
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
