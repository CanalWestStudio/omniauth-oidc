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
      # Modern HTTP client using HTTPX with connection pooling and caching
      class HttpClient
        USER_AGENT = "omniauth-oidc/3.0.0"

        class << self
          # GET request with caching and performance monitoring
          def get(url, options = {})
            cache_key = generate_cache_key(url, options)
            cached_response = cache.get(cache_key)

            if cached_response
              log_info("[HTTP CLIENT] ✅ Cache hit for #{url} (#{cached_response[:size]} bytes)")
              return cached_response[:response]
            end

            start_time = current_time_ms

            begin
              if options[:headers] && options[:headers].any?
                response = HTTPX.get(url, headers: options[:headers])
              else
                response = HTTPX.get(url)
              end

              execution_time = current_time_ms - start_time
              log_performance_metrics(url, execution_time, response)

              parsed_response = parse_response(response)

              # Cache successful responses
              if response.is_a?(HTTPX::Response) && response.status >= 200 && response.status < 300
                cache_response(cache_key, parsed_response, options[:cache_ttl])
              end

              parsed_response
            rescue => e
              execution_time = current_time_ms - start_time
              log_error("[HTTP CLIENT] ❌ Request failed after #{execution_time}ms: #{e.message}")
              raise
            end
          end

          # POST request for token exchanges and API calls
          def post(url, body: nil, headers: {}, timeout: nil)
            start_time = current_time_ms

            begin
              if body && headers.any?
                response = HTTPX.post(url, body: body, headers: headers)
              elsif body
                response = HTTPX.post(url, body: body)
              else
                response = HTTPX.post(url, headers: headers)
              end

              execution_time = current_time_ms - start_time
              log_performance_metrics(url, execution_time, response, method: "POST")

              parse_response(response)
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

          # Parse HTTP response and handle errors
          def parse_response(response)
            unless response.is_a?(HTTPX::Response)
              log_error("[HTTP CLIENT] Invalid response type: #{response.class}")
              raise "Invalid response type: #{response.class}"
            end

            # Check for HTTP errors
            unless response.status >= 200 && response.status < 300
              log_error("[HTTP CLIENT] HTTP #{response.status}: #{response.body[0..200]}")
              raise "HTTP #{response.status}: #{response.reason}"
            end

            # Parse JSON if content-type indicates JSON
            content_type = response.headers['content-type'] || ''
            body = response.body.to_s

            if content_type.include?('application/json')
              JSON.parse(body)
            else
              body
            end
          rescue JSON::ParserError => e
            log_error("[HTTP CLIENT] JSON parse error: #{e.message}, body: #{body[0..200]}")
            body
          end

          def cache
            @cache ||= Cache.new
          end

          def generate_cache_key(url, options)
            "oidc:#{Digest::SHA256.hexdigest("#{url}:#{options.to_s}")}"
          end

          def cache_response(cache_key, response, ttl = nil)
            ttl ||= Configuration.cache_ttl
            response_size = response.is_a?(String) ? response.bytesize : response.to_s.bytesize

            cache.set(cache_key, {
              response: response,
              size: response_size,
              cached_at: Time.now
            }, ttl)
          end

          def log_performance_metrics(url, execution_time, response, method: "GET")
            return unless Configuration.performance_logging_enabled?

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

        # Thread-safe cache implementation
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