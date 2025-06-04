# frozen_string_literal: true

require 'json'

module OmniAuth
  module Strategies
    class Oidc
      module Http
        # HTTP response wrapper for consistent response handling
        class Response
          attr_reader :status, :body, :headers, :raw_response

          def initialize(raw_response)
            @raw_response = raw_response
            @status = extract_status
            @body = extract_body
            @headers = extract_headers
          end

          def success?
            status >= 200 && status < 300
          end

          def client_error?
            status >= 400 && status < 500
          end

          def server_error?
            status >= 500
          end

          def error?
            !success?
          end

          def json?
            content_type&.include?('application/json')
          end

          def parsed_body
            @parsed_body ||= parse_response_body
          end

          def error_message
            return nil if success?

            if json? && parsed_body.is_a?(Hash)
              parsed_body['error_description'] || parsed_body['error'] || "HTTP #{status}"
            else
              "HTTP #{status}: #{body}"
            end
          end

          private

          def extract_status
            case @raw_response
            when Net::HTTPResponse
              @raw_response.code.to_i
            when Hash
              @raw_response[:status] || @raw_response['status'] || 200
            else
              200 # Default for successful responses that don't include status
            end
          end

          def extract_body
            case @raw_response
            when Net::HTTPResponse
              @raw_response.body
            when Hash
              @raw_response.to_json
            when String
              @raw_response
            else
              @raw_response.to_s
            end
          end

          def extract_headers
            case @raw_response
            when Net::HTTPResponse
              @raw_response.to_hash
            when Hash
              @raw_response[:headers] || {}
            else
              {}
            end
          end

          def content_type
            headers['content-type']&.first || headers['Content-Type']&.first
          end

          def parse_response_body
            return nil if body.nil? || body.empty?

            if json?
              JSON.parse(body)
            else
              body
            end
          rescue JSON::ParserError
            body
          end
        end
      end
    end
  end
end