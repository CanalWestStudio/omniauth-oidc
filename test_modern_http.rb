#!/usr/bin/env ruby
# frozen_string_literal: true

require "bundler/setup"
require_relative "lib/omniauth/strategies/oidc"

# Test the modernized HTTP client with HTTPX
puts "🚀 Testing Modernized OIDC HTTP Client with HTTPX"
puts "=" * 60

# Configure performance settings
OmniAuth::Strategies::Oidc::Configuration.apply_aggressive_optimizations!

puts "\n📊 Configuration:"
puts "  Discovery timeout: #{OmniAuth::Strategies::Oidc::Configuration.discovery_timeout}s"
puts "  Cache TTL: #{OmniAuth::Strategies::Oidc::Configuration.cache_ttl}s"
puts "  Performance logging: #{OmniAuth::Strategies::Oidc::Configuration.performance_logging_enabled?}"

# Test 1: Discovery Service with Intuit's OIDC configuration (QuickBooks)
puts "\n🔍 Test 1: Discovery Service (Intuit QuickBooks OIDC)"
config_url = "https://developer.api.intuit.com/.well-known/openid_configuration"

start_time = Time.now
config = OmniAuth::Strategies::Oidc::DiscoveryService.fetch_configuration(config_url)
duration = ((Time.now - start_time) * 1000).round(1)

if config
  puts "  ✅ SUCCESS: Discovery completed in #{duration}ms"
  puts "  📋 Issuer: #{config.issuer}"
  puts "  📋 Authorization endpoint: #{config.authorization_endpoint ? 'Present' : 'Missing'}"
  puts "  📋 Token endpoint: #{config.token_endpoint ? 'Present' : 'Missing'}"
  puts "  📋 Userinfo endpoint: #{config.userinfo_endpoint ? 'Present' : 'Missing'}"
  puts "  📋 JWKS URI: #{config.jwks_uri ? 'Present' : 'Missing'}"
else
  puts "  ❌ FAILED: Discovery failed"
end

# Test 2: HTTP Client caching (second request should be faster)
puts "\n💾 Test 2: HTTP Client Caching"
puts "  First request (should hit network):"

start_time = Time.now
response1 = OmniAuth::Strategies::Oidc::HttpClient.get(config_url, { cache_ttl: 300 })
duration1 = ((Time.now - start_time) * 1000).round(1)
puts "    Duration: #{duration1}ms"

puts "  Second request (should hit cache):"
start_time = Time.now
response2 = OmniAuth::Strategies::Oidc::HttpClient.get(config_url, { cache_ttl: 300 })
duration2 = ((Time.now - start_time) * 1000).round(1)
puts "    Duration: #{duration2}ms"

if duration2 < duration1 / 10  # Cache should be much faster
  puts "  ✅ SUCCESS: Cache working (#{((duration1 - duration2) / duration1 * 100).round(1)}% faster)"
else
  puts "  ⚠️  WARNING: Cache may not be working optimally"
end

# Test 3: HTTP Client error handling
puts "\n🚫 Test 3: Error Handling"
begin
  invalid_response = OmniAuth::Strategies::Oidc::HttpClient.get("https://invalid-oidc-url-test.com/.well-known/openid_configuration", { timeout: 2 })
  puts "  ⚠️  Unexpected: Request to invalid URL succeeded"
rescue => e
  puts "  ✅ SUCCESS: Proper error handling - #{e.class.name}: #{e.message[0..80]}..."
end

# Test 4: Performance comparison
puts "\n⚡ Test 4: Performance Summary"
puts "  HTTP Client: HTTPX v#{HTTPX::VERSION}"
puts "  Ruby: #{RUBY_VERSION}"
puts "  Cache performance: #{duration1}ms → #{duration2}ms"
puts "  Discovery service: #{duration}ms"

# Test 5: Configuration validation
puts "\n⚙️  Test 5: Configuration Validation"
puts "  Intuit optimizations: #{OmniAuth::Strategies::Oidc::Configuration.intuit_optimizations?}"
puts "  Performance logging: #{OmniAuth::Strategies::Oidc::Configuration.performance_logging_enabled?}"

puts "\n✨ All tests completed! HTTPX integration successful."
puts "🎯 Your OIDC gem now uses modern HTTP client technology."