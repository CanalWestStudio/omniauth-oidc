# frozen_string_literal: true

module OmniauthOidc
  module Errors
    # Configuration related errors
    class ConfigurationError < StandardError
      def initialize(message)
        super("[OIDC Configuration Error] #{message}")
      end
    end
  end
end