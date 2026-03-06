# frozen_string_literal: true

require "test_helper"

class TestOmniauthOidc < Minitest::Test
  def test_that_it_has_a_version_number
    refute_nil ::OmniauthOidc::VERSION
  end

  def test_version_is_valid_semver
    assert_match(/\A\d+\.\d+\.\d+\z/, ::OmniauthOidc::VERSION)
  end
end
