# frozen_string_literal: true

module OmniauthOidc
  module Errors
    # ID token and signature verification errors
    class VerificationError < StandardError
      def initialize(message)
        super("[OIDC Verification Error] #{message}")
      end
    end

    # JWT signature verification failed
    class SignatureVerificationError < VerificationError
      def initialize(message = "JWT signature verification failed")
        super(message)
      end
    end

    # JWT algorithm mismatch
    class AlgorithmMismatchError < VerificationError
      def initialize(expected, actual)
        super("Algorithm mismatch: expected #{expected}, got #{actual}")
      end
    end

    # Nonce validation failed
    class NonceValidationError < VerificationError
      def initialize(message = "Nonce validation failed")
        super(message)
      end
    end
  end
end