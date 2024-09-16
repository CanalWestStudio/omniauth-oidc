module OmniAuth
  module Strategies
    class Oidc
      module Serializer

        def serialized_access_token_auth_hash
          {
            provider: name,
            credentials: serialized_credentials
          }
        end

        def serialized_credentials
          {
            id_token: @access_token.id_token,
            token: @access_token.access_token,
            refresh_token: @access_token.refresh_token,
            expires_in: @access_token.expires_in,
            scope: @access_token.scope
          }
        end

        def serialized_extra
          {
            claims: id_token_raw_attributes,
            scope: scope
          }
        end

        def serialized_request_options
          {
            response_type: options.response_type,
            response_mode: options.response_mode,
            scope: scope,
            state: new_state,
            login_hint: params["login_hint"],
            ui_locales: params["ui_locales"],
            claims_locales: params["claims_locales"],
            prompt: options.prompt,
            nonce: (new_nonce if options.send_nonce),
            hd: options.hd,
            acr_values: options.acr_values
          }
        end

        def serialized_user_info
          {
            name: user_info.name,
            email: user_info.email,
            email_verified: user_info.email_verified,
            first_name: user_info.given_name,
            last_name: user_info.family_name,
            phone: user_info.phone_number,
            address: user_info.address
          }
        end

        def serialized_user_info_auth_hash
          {
            provider: name,
            uid: user_info.sub,
            info: serialized_user_info,
            extra: serialized_extra,
            credentials: serialized_credentials
          }
        end
      end
    end
  end
end