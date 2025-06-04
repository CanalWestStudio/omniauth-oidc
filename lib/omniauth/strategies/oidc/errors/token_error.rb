# frozen_string_literal: true

module OmniauthOidc
  module Errors
    # Token exchange and handling errors
    class TokenError < StandardError
      def initialize(message)
        super("[OIDC Token Error] #{message}")
      end
    end

    # Missing code in authorization response
    class MissingCodeError < TokenError
      def initialize(error_description = nil)
        message = "Authorization code not found in callback"
        message += ": #{error_description}" if error_description
        super(message)
      end
    end

    # Missing ID token in response
    class MissingIdTokenError < TokenError
      def initialize(error_description = nil)
        message = "ID token not found in response"
        message += ": #{error_description}" if error_description
        super(message)
      end
    end
  end
end