require 'base64'
require 'active_support/all'
require 'cgi'
require 'openssl'

module OmniAuth
  module Strategies
    class Utils
      def self.get_auth_header(client_id, client_secret)
        encoded = Base64.strict_encode64("#{client_id}:#{client_secret}")
        "Basic #{encoded}"
      end

      def self.generate_random_string(length=20)
        Array.new(length){[*'A'..'Z', *'0'..'9', *'a'..'z'].sample}.join
      end

      def self.format_string_delimiter(params, delimiter, with_quotes=false)
        if with_quotes
          return params.map { |k, v| "#{k}=\"#{v}\"" }.join(delimiter)
        end
        params.map { |k, v| "#{k}=#{v}" }.join(delimiter)
      end

      def self.build_response_object(response)
        url = response.request.last_uri.to_s
        if url['openid_sandbox_configuration'] || url['openid_configuration'] || url['openid_connect/userinfo']
          response
        else
          raise Error
        end
      end
    end
  end
end