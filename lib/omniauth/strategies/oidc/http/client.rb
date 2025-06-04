# frozen_string_literal: true

require 'net/http'
require 'uri'
require 'timeout'
require_relative 'response'

module OmniAuth
  module Strategies
    class Oidc
      module Http
        # HTTP client for OIDC operations
        class Client
          DEFAULT_TIMEOUT = 10
          DEFAULT_HEADERS = {
            'User-Agent' => 'omniauth-oidc-gem',
            'Accept' => 'application/json'
          }.freeze

          class << self
            def get(url, headers: {}, timeout: DEFAULT_TIMEOUT)
              execute_request(:get, url, headers: headers, timeout: timeout)
            end

            def post(url, body: nil, headers: {}, timeout: DEFAULT_TIMEOUT)
              execute_request(:post, url, body: body, headers: headers, timeout: timeout)
            end

            private

            def execute_request(method, url, body: nil, headers: {}, timeout: DEFAULT_TIMEOUT)
              uri = URI.parse(url)
              request_headers = DEFAULT_HEADERS.merge(headers)

              log_request(method, url)

              Timeout.timeout(timeout) do
                Net::HTTP.start(uri.host, uri.port, use_ssl: uri.scheme == 'https') do |http|
                  http.read_timeout = timeout
                  http.open_timeout = timeout

                  request = build_request(method, uri, body, request_headers)
                  raw_response = http.request(request)

                  response = Response.new(raw_response)
                  log_response(response)

                  handle_response(response)
                end
              end
            rescue Timeout::Error => e
              raise OmniauthOidc::Errors::TokenError, "Request timeout: #{e.message}"
            rescue Net::HTTPError, SocketError => e
              raise OmniauthOidc::Errors::TokenError, "Network error: #{e.message}"
            rescue StandardError => e
              raise OmniauthOidc::Errors::TokenError, "HTTP request failed: #{e.message}"
            end

            def build_request(method, uri, body, headers)
              request_class = case method
                              when :get
                                Net::HTTP::Get
                              when :post
                                Net::HTTP::Post
                              else
                                raise ArgumentError, "Unsupported HTTP method: #{method}"
                              end

              request = request_class.new(uri.request_uri)

              headers.each { |key, value| request[key] = value }
              request.body = body if body && method == :post

              request
            end

            def handle_response(response)
              if response.success?
                if response.json?
                  response.parsed_body
                else
                  response.body
                end
              else
                raise OmniauthOidc::Errors::TokenError, "HTTP #{response.status}: #{response.error_message}"
              end
            end

            def log_request(method, url)
              return unless logger

              logger.info("[OIDC HTTP] #{method.upcase} #{url}")
            end

            def log_response(response)
              return unless logger

              status_text = response.success? ? "SUCCESS" : "ERROR"
              logger.info("[OIDC HTTP] Response: #{response.status} #{status_text}")

              if response.error?
                logger.error("[OIDC HTTP] Error: #{response.error_message}")
              end
            end

            def logger
              @logger ||= begin
                if defined?(Rails) && Rails.respond_to?(:logger) && Rails.logger
                  Rails.logger
                elsif defined?(Logger)
                  Logger.new(STDOUT)
                end
              end
            end
          end
        end
      end
    end
  end
end