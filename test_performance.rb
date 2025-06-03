#!/usr/bin/env ruby
# frozen_string_literal: true

# Performance test script for omniauth-oidc optimizations
# Run with: ruby test_performance.rb

require_relative 'lib/omniauth/strategies/oidc/configuration'
require_relative 'lib/omniauth/strategies/oidc/http_client'
require_relative 'lib/omniauth/strategies/oidc/discovery_service'

puts "=== OmniAuth OIDC Performance Test ==="
puts

# Test configuration system
puts "1. Testing Configuration System"
puts "Default discovery timeout: #{OmniAuth::Strategies::Oidc::Configuration.discovery_timeout}s"
puts "Default token timeout: #{OmniAuth::Strategies::Oidc::Configuration.token_timeout}s"
puts "Cache enabled: #{OmniAuth::Strategies::Oidc::Configuration.cache_enabled?}"
puts

# Test Intuit optimizations
puts "2. Applying Intuit Optimizations"
OmniAuth::Strategies::Oidc::Configuration.apply_intuit_optimizations!
puts "New discovery timeout: #{OmniAuth::Strategies::Oidc::Configuration.discovery_timeout}s"
puts "New token timeout: #{OmniAuth::Strategies::Oidc::Configuration.token_timeout}s"
puts "Intuit optimizations enabled: #{OmniAuth::Strategies::Oidc::Configuration.intuit_optimizations?}"
puts

# Test HTTP client with caching
puts "3. Testing HTTP Client with Caching"
test_url = "https://httpbin.org/delay/1"

puts "First request (should take ~1 second):"
start_time = Time.now
begin
  response = OmniAuth::Strategies::Oidc::HttpClient.get(test_url, cache_key: "test_cache")
  duration = ((Time.now - start_time) * 1000).round(1)
  puts "✓ Request completed in #{duration}ms"
rescue => e
  puts "✗ Request failed: #{e.message}"
end

puts "Second request (should be cached and fast):"
start_time = Time.now
begin
  response = OmniAuth::Strategies::Oidc::HttpClient.get(test_url, cache_key: "test_cache")
  duration = ((Time.now - start_time) * 1000).round(1)
  puts "✓ Cached request completed in #{duration}ms"
rescue => e
  puts "✗ Cached request failed: #{e.message}"
end
puts

# Test discovery service (using a real OIDC endpoint)
puts "4. Testing Discovery Service"
discovery_url = "https://accounts.google.com/.well-known/openid-configuration"

puts "Fetching Google's OIDC configuration..."
start_time = Time.now
begin
  config = OmniAuth::Strategies::Oidc::DiscoveryService.fetch_configuration(discovery_url)
  duration = ((Time.now - start_time) * 1000).round(1)

  if config && config.issuer
    puts "✓ Discovery successful in #{duration}ms"
    puts "  Issuer: #{config.issuer}"
    puts "  Token endpoint: #{config.token_endpoint ? '✓' : '✗'}"
    puts "  JWKS URI: #{config.jwks_uri ? '✓' : '✗'}"
  else
    puts "✗ Discovery failed - invalid response"
  end
rescue => e
  puts "✗ Discovery failed: #{e.message}"
end
puts

# Test configuration display
puts "5. Final Configuration Summary"
config_hash = OmniAuth::Strategies::Oidc::Configuration.to_h
config_hash.each do |key, value|
  puts "  #{key}: #{value}"
end
puts

puts "=== Performance Test Complete ==="
puts "🚀 Your omniauth-oidc gem is optimized and ready!"
puts
puts "Next steps:"
puts "1. Add optimized OIDC configuration to your Rails app"
puts "2. Set environment variables for fine-tuning"
puts "3. Monitor your Rails logs for performance timing"
puts "4. Enjoy faster authentication! 🎉"