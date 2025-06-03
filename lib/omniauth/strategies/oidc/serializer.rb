# frozen_string_literal: true

module OmniAuth
  module Strategies
    class Oidc
      # Optimized serializer with fallback support
      module Serializer
        def serialized_user_info_auth_hash
          {
            provider: name,
            uid: uid,
            info: serialized_user_info,
            extra: serialized_extra,
            credentials: serialized_credentials
          }
        end

        def serialized_access_token_auth_hash
          {
            provider: name,
            uid: uid_from_token,
            info: serialized_info_from_token,
            extra: serialized_extra_from_token,
            credentials: serialized_credentials
          }
        end

        def serialized_user_info
          # Use fetched user info if available, otherwise fall back to legacy method
          if @fetched_user_info
            build_user_info_from_data(@fetched_user_info)
          elsif respond_to?(:user_info) && user_info
            build_user_info_from_object(user_info)
          else
            {}
          end
        end

        def serialized_extra
          extra_data = {}

          # Include ID token if available
          if @token_response&.id_token
            extra_data[:id_token] = @token_response.id_token
          elsif respond_to?(:decoded_id_token) && decoded_id_token
            extra_data[:id_token] = decoded_id_token.raw_attributes
          end

          # Include raw user info if available
          if @fetched_user_info
            extra_data[:raw_info] = @fetched_user_info
          elsif respond_to?(:user_info) && user_info
            extra_data[:raw_info] = user_info.raw_attributes
          end

          # Legacy claims support
          if respond_to?(:id_token_raw_attributes) && id_token_raw_attributes
            extra_data[:claims] = id_token_raw_attributes
          end

          extra_data[:scope] = scope
          extra_data
        end

        def serialized_credentials
          creds = {}

          if @token_response
            creds[:token] = @token_response.access_token
            creds[:refresh_token] = @token_response.refresh_token if @token_response.refresh_token
            creds[:expires_at] = calculate_expires_at(@token_response.expires_in) if @token_response.expires_in
            creds[:id_token] = @token_response.id_token if @token_response.id_token
            creds[:expires_in] = @token_response.expires_in if @token_response.expires_in
          elsif @access_token
            # Legacy fallback
            creds[:token] = @access_token.access_token if @access_token.respond_to?(:access_token)
            creds[:refresh_token] = @access_token.refresh_token if @access_token.respond_to?(:refresh_token)
            creds[:id_token] = @access_token.id_token if @access_token.respond_to?(:id_token)
            creds[:expires_in] = @access_token.expires_in if @access_token.respond_to?(:expires_in)
            creds[:scope] = @access_token.scope if @access_token.respond_to?(:scope)
          end

          creds
        end

        def serialized_request_options
          options_hash = {
            response_type: options.response_type,
            scope: scope,
            state: new_state,
            nonce: (new_nonce if options.send_nonce),
            hd: options.hd,
            prompt: options.prompt,
            ui_locales: options.ui_locales || params["ui_locales"],
            id_token_hint: options.id_token_hint,
            acr_values: options.acr_values,
            max_age: options.max_age,
            login_hint: params["login_hint"],
            claims_locales: params["claims_locales"]
          }.compact

          if options.response_mode
            options_hash[:response_mode] = options.response_mode
          end

          if options.display
            options_hash[:display] = options.display
          end

          options_hash
        end

        private

        def build_user_info_from_data(user_data)
          return {} unless user_data.is_a?(Hash)

          {
            sub: user_data['sub'],
            name: user_data['name'],
            email: user_data['email'],
            email_verified: user_data['email_verified'],
            first_name: user_data['given_name'],
            last_name: user_data['family_name'],
            phone: user_data['phone_number'],
            phone_verified: user_data['phone_number_verified'],
            picture: user_data['picture'],
            locale: user_data['locale'],
            address: user_data['address'],
            birthdate: user_data['birthdate'],
            gender: user_data['gender'],
            website: user_data['website'],
            zoneinfo: user_data['zoneinfo'],
            updated_at: user_data['updated_at']
          }.compact
        end

        def build_user_info_from_object(user_info_obj)
          return {} unless user_info_obj.respond_to?(:raw_attributes)

          attrs = user_info_obj.raw_attributes
          # Legacy format mapping
          {
            name: user_info_obj.name,
            email: user_info_obj.email,
            email_verified: user_info_obj.email_verified,
            first_name: user_info_obj.given_name,
            last_name: user_info_obj.family_name,
            phone: user_info_obj.phone_number,
            address: user_info_obj.address
          }.compact
        end

        def uid_from_token
          if @token_response&.id_token
            begin
              token_payload = JSON::JWT.decode(@token_response.id_token, :skip_verification)
              token_payload[options.uid_field.to_s] || token_payload['sub']
            rescue
              nil
            end
          end
        end

        def serialized_info_from_token
          if @token_response&.id_token
            begin
              token_payload = JSON::JWT.decode(@token_response.id_token, :skip_verification)
              build_user_info_from_data(token_payload)
            rescue
              {}
            end
          else
            {}
          end
        end

        def serialized_extra_from_token
          extra_data = {}

          if @token_response&.id_token
            extra_data[:id_token] = @token_response.id_token
            begin
              token_payload = JSON::JWT.decode(@token_response.id_token, :skip_verification)
              extra_data[:raw_info] = token_payload
              extra_data[:claims] = token_payload # Legacy support
            rescue
              # Ignore decode errors
            end
          end

          extra_data[:scope] = scope
          extra_data
        end

        def calculate_expires_at(expires_in)
          return nil unless expires_in
          Time.now.to_i + expires_in.to_i
        end

        def name
          options.name.to_s
        end
      end
    end
  end
end