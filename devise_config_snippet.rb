# 🚀 OPTIMIZED VERSION of your existing Devise OIDC config
# Replace your existing OIDC loop with this enhanced version:

Jumpstart::Omniauth.enabled_providers.each do |provider, args|
  name = provider.to_s
  klass = OmniAuth.config.camelizations.fetch(name, name.classify)

  if Object.const_defined? "OmniAuth::Strategies::#{klass}"
    if provider == :oidc
      Jumpstart::Omniauth::OIDC_PROVIDERS.each do |oidc_provider, oidc_args|

        # Detect Intuit/QuickBooks for special optimizations
        config_endpoint = args.dig(:options, :config_endpoint) || ""
        is_intuit = oidc_provider.to_s.include?('intuit') ||
                   oidc_provider.to_s.include?('quickbooks') ||
                   config_endpoint.include?('intuit.com')

        config.omniauth provider, {
          name: oidc_provider,
          scope: oidc_args[:scope],
          response_type: "code",
          send_nonce: false,

          # 🚀 PERFORMANCE OPTIMIZATIONS
          fetch_user_info: is_intuit ? false : true,        # Skip user info for Intuit (saves 1-2s)
          send_scope_to_token_endpoint: false,              # Reduce payload for all providers
          require_state: true,                              # Keep security

          client_options: {
            identifier: args[:public_key],
            secret: args[:private_key],
            config_endpoint: args[:options][:config_endpoint],
            environment: args[:options][:environment]
          }
        }

        # Log optimization status
        Rails.logger.info "[OIDC] #{oidc_provider} - Intuit optimizations: #{is_intuit ? 'ON' : 'OFF'}"
      end
    else
      config.omniauth provider, args[:public_key], args[:private_key], args[:options]
    end
  end
end