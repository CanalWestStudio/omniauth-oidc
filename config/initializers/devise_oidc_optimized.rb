# frozen_string_literal: true

# Enhanced Devise OIDC Configuration with Performance Optimizations
# Replace your existing OIDC configuration in devise.rb with this optimized version

Devise.setup do |config|
  # Your existing Jumpstart configuration with performance enhancements
  Jumpstart::Omniauth.enabled_providers.each do |provider, args|
    name = provider.to_s
    klass = OmniAuth.config.camelizations.fetch(name, name.classify)

    if Object.const_defined? "OmniAuth::Strategies::#{klass}"
      if provider == :oidc
        Jumpstart::Omniauth::OIDC_PROVIDERS.each do |oidc_provider, oidc_args|

          # Performance optimizations based on provider
          performance_config = build_performance_config(oidc_provider, args)

          config.omniauth provider, {
            name: oidc_provider,
            scope: oidc_args[:scope],
            response_type: "code",
            send_nonce: false,

            # 🚀 PERFORMANCE OPTIMIZATIONS
            fetch_user_info: performance_config[:fetch_user_info],
            send_scope_to_token_endpoint: performance_config[:send_scope_to_token_endpoint],
            require_state: performance_config[:require_state],

            client_options: {
              identifier: args[:public_key],
              secret: args[:private_key],
              config_endpoint: args[:options][:config_endpoint],
              environment: args[:options][:environment]
            }
          }
        end
      else
        config.omniauth provider, args[:public_key], args[:private_key], args[:options]
      end
    end
  end

  private

  # Build performance configuration based on provider type
  def self.build_performance_config(provider_name, args)
    config_endpoint = args.dig(:options, :config_endpoint) || ""

    # Intuit/QuickBooks specific optimizations
    if provider_name.to_s.include?('intuit') ||
       provider_name.to_s.include?('quickbooks') ||
       config_endpoint.include?('intuit.com')

      Rails.logger.info "[OIDC PERFORMANCE] Applying Intuit optimizations for #{provider_name}"
      {
        fetch_user_info: false,              # Skip user info call (saves 1-2 seconds)
        send_scope_to_token_endpoint: false, # Reduce payload size
        require_state: true                  # Keep security for production
      }

    # Generic optimizations for other providers
    else
      {
        fetch_user_info: true,               # Keep user info for other providers
        send_scope_to_token_endpoint: false, # Still optimize payload
        require_state: true                  # Maintain security
      }
    end
  end
end

# Log the optimization status
Rails.application.config.after_initialize do
  if OmniAuth::Strategies::Oidc::Configuration.intuit_optimizations?
    Rails.logger.info "[OIDC PERFORMANCE] ✅ Intuit optimizations active"
    Rails.logger.info "[OIDC PERFORMANCE] Token timeout: #{OmniAuth::Strategies::Oidc::Configuration.token_timeout}s"
    Rails.logger.info "[OIDC PERFORMANCE] Cache TTL: #{OmniAuth::Strategies::Oidc::Configuration.cache_ttl}s"
  end
end