# Copyright (c) 2018 Intuit
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#  http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

require 'base64'
require 'active_support/all'
require 'cgi'
require 'openssl'
require_relative './response'

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
          ClientResponse.new(response)
        end
      end
    end
  end
end