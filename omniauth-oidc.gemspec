# frozen_string_literal: true

require_relative "lib/omniauth/oidc/version"

Gem::Specification.new do |spec|
  spec.name = "omniauth-oidc"
  spec.version = OmniauthOidc::VERSION
  spec.authors = [ 'mc' ]
  spec.email = [ 'test@example.com' ]

  spec.summary = "Omniauth strategy to authenticate and retrieve user data using OpenID Connect (OIDC)"
  spec.description = "Omniauth strategy to authenticate and retrieve user data as a client using OpenID Connect (OIDC)
    suited for multiple OIDC providers."
  spec.homepage = "https://github.com/CanalWestStudio/omniauth-oidc"
  spec.license = "MIT"
  spec.required_ruby_version = ">= 2.7.0"

  spec.metadata["homepage_uri"] = spec.homepage
  spec.metadata["source_code_uri"] = "https://github.com/msuliq/omniauth-oidc"
  spec.metadata["changelog_uri"] = "https://github.com/CanalWestStudio/omniauth-oidc/blob/main/CHANGELOG.md"

  # Specify which files should be added to the gem when it is released.
  # The `git ls-files -z` loads the files in the RubyGem that have been added into git.
  spec.files = Dir.chdir(__dir__) do
    `git ls-files -z`.split("\x0").reject do |f|
      (File.expand_path(f) == __FILE__) ||
        f.start_with?(*%w[bin/ test/ spec/ features/ .git .github appveyor Gemfile])
    end
  end
  spec.bindir = "exe"
  spec.executables = spec.files.grep(%r{\Aexe/}) { |f| File.basename(f) }
  spec.require_paths = [ "lib" ]

  # Modern dependencies
  spec.add_dependency "httpx", "~> 1.0"              # Modern HTTP client with connection pooling
  spec.add_dependency "omniauth", "~> 2.0"
  spec.add_dependency "openid_config_parser", "~> 0.1"
  spec.add_dependency "openid_connect", "~> 2.0"

  # For more information and examples about making a new gem, check out our
  # guide at: https://bundler.io/guides/creating_gem.html
end
