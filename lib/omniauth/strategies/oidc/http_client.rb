require 'net/http'
require 'uri'
require 'json'
require 'logger'

module OmniAuth
  module Strategies
    class Oidc
      # High-performance HTTP client with connection pooling and caching
      class HttpClient
        DEFAULT_TIMEOUT = 3 # Aggressive timeout for OIDC calls
        CONNECT_TIMEOUT = 2 # TCP connection timeout
        MAX_REDIRECTS = 3
        CACHE_TTL = 300 # 5 minutes for discovery documents

        class << self
          def get(url, headers: {}, timeout: DEFAULT_TIMEOUT, cache_key: nil)
            log_timing("GET #{url}") do
              if cache_key && cached_response = cache_get(cache_key)
                log_debug("Cache HIT for #{cache_key}")
                return cached_response
              end

              response = with_retries(1) do
                perform_request(:get, url, nil, headers, timeout)
              end

              if cache_key && response
                cache_set(cache_key, response, CACHE_TTL)
                log_debug("Cache SET for #{cache_key}")
              end

              response
            end
          end

          def post(url, body: nil, headers: {}, timeout: DEFAULT_TIMEOUT)
            log_timing("POST #{url}") do
              with_retries(1) do
                perform_request(:post, url, body, headers, timeout)
              end
            end
          end

          private

          def perform_request(method, url, body, headers, timeout)
            uri = URI(url)

            http = get_http_client(uri)
            http.read_timeout = timeout
            http.open_timeout = CONNECT_TIMEOUT

            request = build_request(method, uri, body, headers)

            log_debug("#{method.upcase} #{url} (timeout: #{timeout}s)")

            response = http.request(request)

            if response.is_a?(Net::HTTPRedirection) && response['location']
              return handle_redirect(response['location'], method, body, headers, timeout)
            end

            if response.is_a?(Net::HTTPSuccess)
              parse_response(response)
            else
              log_error("HTTP #{response.code}: #{response.body[0..200]}")
              raise "HTTP #{response.code}: #{response.message}"
            end
          rescue Net::TimeoutError, Timeout::Error => e
            log_error("Request timeout for #{url}: #{e.message}")
            raise ::Timeout::Error, "OIDC request timeout (#{timeout}s): #{url}"
          rescue SocketError, Net::HTTPBadResponse, EOFError => e
            log_error("Network error for #{url}: #{e.message}")
            raise ::SocketError, "OIDC network error: #{e.message}"
          end

          def get_http_client(uri)
            # Simple connection reuse by host
            @http_clients ||= {}
            key = "#{uri.host}:#{uri.port}"

            unless @http_clients[key]&.started?
              http = Net::HTTP.new(uri.host, uri.port)
              http.use_ssl = uri.scheme == 'https'
              http.verify_mode = OpenSSL::SSL::VERIFY_PEER

              # Performance optimizations
              http.keep_alive_timeout = 30
              if http.respond_to?(:max_retries)
                http.max_retries = 0 # Disable internal retries, we handle them
              end

              http.start
              @http_clients[key] = http
            end

            @http_clients[key]
          rescue => e
            log_error("Failed to create HTTP client: #{e.message}")
            # Fallback to new connection
            http = Net::HTTP.new(uri.host, uri.port)
            http.use_ssl = uri.scheme == 'https'
            http.verify_mode = OpenSSL::SSL::VERIFY_PEER
            http
          end

          def build_request(method, uri, body, headers)
            case method
            when :get
              request = Net::HTTP::Get.new(uri)
            when :post
              request = Net::HTTP::Post.new(uri)
              request.body = body if body
            end

            # Default headers
            request['User-Agent'] = OmniauthOidc::USER_AGENT
            request['Accept'] = 'application/json'
            request['Connection'] = 'keep-alive'

            # Custom headers
            headers.each { |k, v| request[k] = v }

            request
          end

          def parse_response(response)
            content_type = response['content-type'] || ''

            if content_type.include?('application/json')
              JSON.parse(response.body)
            else
              response.body
            end
          rescue JSON::ParserError => e
            log_error("JSON parse error: #{e.message}, body: #{response.body[0..200]}")
            response.body
          end

          def handle_redirect(location, method, body, headers, timeout, redirects = 0)
            if redirects >= MAX_REDIRECTS
              raise "Too many redirects (#{MAX_REDIRECTS})"
            end

            log_debug("Following redirect to #{location}")
            perform_request(method, location, body, headers, timeout)
          end

          def with_retries(max_retries, &block)
            retries = 0
            begin
              yield
            rescue Net::TimeoutError, SocketError, EOFError => e
              retries += 1
              if retries <= max_retries
                log_debug("Retrying request (#{retries}/#{max_retries}): #{e.message}")
                sleep(0.1 * retries) # Brief exponential backoff
                retry
              else
                raise
              end
            end
          end

          def cache_get(key)
            return nil unless @cache
            entry = @cache[key]
            return nil unless entry
            return nil if entry[:expires_at] < Time.now
            entry[:data]
          end

          def cache_set(key, data, ttl)
            @cache ||= {}
            @cache[key] = {
              data: data,
              expires_at: Time.now + ttl
            }

            # Simple cache cleanup every 100 sets
            @cache_sets = (@cache_sets || 0) + 1
            if @cache_sets % 100 == 0
              cleanup_cache
            end
          end

          def cleanup_cache
            return unless @cache
            now = Time.now
            @cache.reject! { |_, entry| entry[:expires_at] < now }
            log_debug("Cache cleanup completed, #{@cache.size} entries remaining")
          end

          def log_timing(description, &block)
            start_time = Time.now
            result = yield
            duration = ((Time.now - start_time) * 1000).round(1)
            log_info("[OIDC TIMING] #{description} completed in #{duration}ms")
            result
          end

          def log_info(message)
            logger.info(message) if logger
          end

          def log_debug(message)
            logger.debug(message) if logger
          end

          def log_error(message)
            logger.error(message) if logger
          end

          def logger
            @logger ||= defined?(Rails) ? Rails.logger : Logger.new(STDOUT)
          end
        end
      end
    end
  end
end