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

    DEFAULT_TTL = 3600 # 1 hour

    def self.fetch(endpoint_url, ttl: DEFAULT_TTL)
      now = Process.clock_gettime(Process::CLOCK_MONOTONIC)

      if (cached = cache[endpoint_url]) && (now - cached[:fetched_at] < ttl)
        return cached[:config]
      end

      json = OmniAuth::Strategies::Oidc::Transport.fetch_json(endpoint_url)
      config = new(json)
      cache[endpoint_url] = { config: config, fetched_at: now }
      config
    end

    def self.cache
      @cache ||= {}
    end

    def self.clear_cache!
      @cache = {}
    end
  end
end
