#!/usr/bin/env ruby
# frozen_string_literal: true

require "bundler/setup"
require "httpx"
require "json"

puts "🧪 Testing Basic HTTPX Functionality"
puts "=" * 50

# Test 1: Simple HTTPX request
puts "\n🔍 Test 1: Basic HTTPX Request"
begin
  response = HTTPX.get("https://www.google.com")
  puts "  ✅ Status: #{response.status}"
  puts "  📊 Response class: #{response.class}"
  puts "  📏 Body size: #{response.body.bytesize} bytes"
rescue => e
  puts "  ❌ Error: #{e.class} - #{e.message}"
end

# Test 2: Intuit OIDC Discovery endpoint
puts "\n🔍 Test 2: Intuit OIDC Discovery (Direct HTTPX)"
begin
  response = HTTPX.get("https://developer.api.intuit.com/.well-known/openid_configuration")
  puts "  ✅ Status: #{response.status}"
  puts "  📊 Response class: #{response.class}"
  puts "  📏 Body size: #{response.body.bytesize} bytes"

  if response.status == 200
    config = JSON.parse(response.body)
    puts "  🔗 Issuer: #{config['issuer']}"
    puts "  🔗 Token endpoint: #{config['token_endpoint']}"
    puts "  🔗 Userinfo endpoint: #{config['userinfo_endpoint']}"
  end
rescue => e
  puts "  ❌ Error: #{e.class} - #{e.message}"
end

# Test 3: HTTPX with timeout options
puts "\n🔍 Test 3: HTTPX with Timeout Configuration"
begin
  client = HTTPX.with(timeout: { request_timeout: 5 })
  response = client.get("https://developer.api.intuit.com/.well-known/openid_configuration")
  puts "  ✅ Status: #{response.status}"
  puts "  📊 Response class: #{response.class}"
  puts "  📏 Body size: #{response.body.bytesize} bytes"
rescue => e
  puts "  ❌ Error: #{e.class} - #{e.message}"
end

puts "\n✨ Basic HTTPX test completed!"