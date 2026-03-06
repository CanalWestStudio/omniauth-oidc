# frozen_string_literal: true

module OmniauthOidc
  # Fetches and wraps the OIDC provider's discovery document, providing
  # method-based access to standard OpenID Connect configuration fields.
  class Config
    FIELDS = %i[
      issuer
      authorization_endpoint
      token_endpoint
      userinfo_endpoint
      jwks_uri
      end_session_endpoint
      scopes_supported
    ].freeze

    attr_reader(*FIELDS)

    def initialize(data)
      FIELDS.each do |field|
        instance_variable_set(:"@#{field}", data[field.to_s] || data[field])
      end
    end

    def self.fetch(endpoint_url)
      json = OmniAuth::Strategies::Oidc::Transport.fetch_json(endpoint_url)
      new(json)
    end
  end
end
