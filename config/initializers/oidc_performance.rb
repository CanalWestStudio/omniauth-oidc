# frozen_string_literal: true

# Apply OIDC performance optimizations for Jumpstart Pro
# This must load before Devise initializes

# Apply Intuit-specific optimizations for QuickBooks integration
OmniAuth::Strategies::Oidc::Configuration.apply_intuit_optimizations!

# Or configure manually for more control:
# OmniAuth::Strategies::Oidc::Configuration.configure do |config|
#   config.discovery_timeout = 2
#   config.token_timeout = 3
#   config.userinfo_timeout = 2
#   config.cache_ttl = 600 # 10 minutes for stable configs
#   config.performance_logging_enabled = true
#   config.intuit_optimizations = true
# end

Rails.logger.info "[OIDC PERFORMANCE] Applied performance optimizations for Jumpstart Pro"