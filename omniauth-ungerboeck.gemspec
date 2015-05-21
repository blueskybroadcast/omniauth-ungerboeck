# coding: utf-8
lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'omniauth-ungerboeck/version'

Gem::Specification.new do |spec|
  spec.name          = "omniauth-ungerboeck"
  spec.version       = Omniauth::Ungerboeck::VERSION
  spec.authors       = ["Timm Liu"]
  spec.email         = ["tliu@blueskybroadcast.com"]
  spec.summary       = %q{UNGERBOECK SSO}
  spec.description   = %q{UNGERBOECK SSO}
  spec.homepage      = ""
  spec.license       = "MIT"

  spec.files         = `git ls-files -z`.split("\x0")
  spec.executables   = spec.files.grep(%r{^bin/}) { |f| File.basename(f) }
  spec.test_files    = spec.files.grep(%r{^(test|spec|features)/})
  spec.require_paths = ["lib"]

  spec.add_dependency 'omniauth', '~> 1.0'
  spec.add_dependency 'omniauth-oauth2', '~> 1.0'
  spec.add_dependency 'rest-client'

  spec.add_development_dependency "bundler", "~> 1.6"
  spec.add_development_dependency "rake"
end
