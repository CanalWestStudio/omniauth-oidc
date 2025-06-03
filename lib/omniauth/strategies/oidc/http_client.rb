# frozen_string_literal: true

require "httpx"
require "json"
require "digest"
require 'logger'
require 'timeout'
require_relative 'configuration'

module OmniAuth
  module Strategies
    class Oidc
      # Modern HTTP client using HTTPX with connection pooling, caching, and performance optimizations
      class HttpClient
        USER_AGENT = "omniauth-oidc/3.0.0"

        class << self
          # Main get method with caching and performance monitoring
          def get(url, options = {})
            cache_key = generate_cache_key(url, options)
            cached_response = cache.get(cache_key)

            if cached_response
              log_info("[HTTP CLIENT] ✅ Cache hit for #{url} (#{cached_response[:size]} bytes)")
              return cached_response[:response]
            end

            start_time = current_time_ms

            begin
              # Use HTTPX directly with optional headers
              if options[:headers] && options[:headers].any?
                response = HTTPX.get(url, headers: options[:headers])
              else
                response = HTTPX.get(url)
              end

              execution_time = current_time_ms - start_time
              log_performance_metrics(url, execution_time, response)

              # Cache successful responses - check if it's a successful response
              if response.is_a?(HTTPX::Response) && response.status >= 200 && response.status < 300
                cache_response(cache_key, response, options[:cache_ttl])
              end

              response
            rescue => e
              execution_time = current_time_ms - start_time
              log_error("[HTTP CLIENT] ❌ Request failed after #{execution_time}ms: #{e.message}")
              raise
            end
          end

          # POST method for token exchanges and API calls
          def post(url, body: nil, headers: {}, timeout: nil)
            start_time = current_time_ms

            begin
              # Use HTTPX directly for POST requests
              if body && headers.any?
                response = HTTPX.post(url, body: body, headers: headers)
              elsif body
                response = HTTPX.post(url, body: body)
              else
                response = HTTPX.post(url, headers: headers)
              end

              execution_time = current_time_ms - start_time
              log_performance_metrics(url, execution_time, response, method: "POST")

              response
            rescue => e
              execution_time = current_time_ms - start_time
              log_error("[HTTP CLIENT] ❌ POST request failed after #{execution_time}ms: #{e.message}")
              raise
            end
          end

          # Clear cache for testing or when needed
          def clear_cache!
            @cache = nil
            log_info("[HTTP CLIENT] 🧹 Cache cleared")
          end

          private

          # Simple in-memory cache
          def cache
            @cache ||= Cache.new
          end

          def generate_cache_key(url, options)
            "oidc:#{Digest::SHA256.hexdigest("#{url}:#{options.to_s}")}"
          end

          def cache_response(cache_key, response, ttl = nil)
            return unless response.is_a?(HTTPX::Response) && response.status >= 200 && response.status < 300

            ttl ||= Configuration.cache_ttl

            cache.set(cache_key, {
              response: response,
              size: response.body.bytesize,
              cached_at: Time.now
            }, ttl)
          end

          def log_performance_metrics(url, execution_time, response, method: "GET")
            return unless Configuration.performance_logging_enabled?

            # Handle both HTTPX::Response and HTTPX::ErrorResponse
            if response.is_a?(HTTPX::Response)
              status = response.status
              size = response.body.bytesize
              log_debug("[HTTP CLIENT] HTTPX::Response - Status: #{status}, Body size: #{size}")
            else
              status = "ERROR"
              size = 0
              log_debug("[HTTP CLIENT] Non-Response object: #{response.class} - #{response.inspect}")
            end

            uri = URI.parse(url)
            host = uri.host

            if execution_time > 1000
              log_info("[HTTP CLIENT] 🐌 SLOW #{method} #{host} #{status} #{execution_time}ms (#{size} bytes)")
            else
              log_info("[HTTP CLIENT] ⚡ #{method} #{host} #{status} #{execution_time}ms (#{size} bytes)")
            end
          end

          def current_time_ms
            (Time.now.to_f * 1000).to_i
          end

          def log_info(message)
            logger.info(message) if logger
          end

          def log_error(message)
            logger.error(message) if logger
          end

          def log_debug(message)
            logger.debug(message) if logger
          end

          def logger
            @logger ||= defined?(Rails) ? Rails.logger : Logger.new(STDOUT)
          end
        end

        # Simple thread-safe cache implementation
        class Cache
          def initialize
            @store = {}
            @mutex = Mutex.new
          end

          def get(key)
            @mutex.synchronize do
              entry = @store[key]
              return nil unless entry
              return nil if expired?(entry)
              entry[:data]
            end
          end

          def set(key, data, ttl)
            @mutex.synchronize do
              @store[key] = {
                data: data,
                expires_at: Time.now + ttl
              }
            end
          end

          def clear
            @mutex.synchronize { @store.clear }
          end

          private

          def expired?(entry)
            entry[:expires_at] < Time.now
          end
        end
      end
    end
  end
end