require 'uri'
require 'json'
require 'httparty'
require_relative './utils'

module OmniAuth
  module Strategies
    class Transport
      include HTTParty
      ssl_version :TLSv1_2

      def self.request(method, url, headers=nil, body=nil, isBuildResponse=true)
        uri = URI(url)

        user_agent_header = {
          'User-Agent': OmniauthOidc::USER_AGENT
        }
        req_headers = headers.nil? ? user_agent_header : user_agent_header.merge!(headers)

        if method == 'GET'
          response = get(url,
            headers: req_headers
          )

        elsif method == 'POST'
          response = post(url,
            headers: req_headers,
            body: body
          )
        end

        if isBuildResponse == true
          Utils.build_response_object(response)
        else
          response
        end
      end
    end
  end
end