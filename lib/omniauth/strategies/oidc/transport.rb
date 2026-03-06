# frozen_string_literal: true

require "faraday"
require "faraday/net_http_persistent"
require "faraday/retry"

module OmniAuth
  module Strategies
    class Oidc
      # HTTP transport layer using Faraday
      module Transport
        module_function

        def connection
          @connection ||= Faraday.new do |f|
            f.request :retry, max: 2, interval: 0.5, backoff_factor: 2
            f.headers["User-Agent"] = OmniauthOidc::USER_AGENT
            f.ssl.min_version = OpenSSL::SSL::TLS1_2_VERSION
            f.adapter :net_http_persistent
          end
        end

        def get(url, headers: {})
          connection.get(url) do |req|
            req.headers.merge!(headers)
          end
        end

        def post(url, headers: {}, body: nil)
          connection.post(url) do |req|
            req.headers.merge!(headers)
            req.body = body
          end
        end

        def fetch_json(url, headers: {})
          response = get(url, headers: headers)
          JSON.parse(response.body)
        end
      end
    end
  end
end
