# -*- encoding: utf-8 -*-
$:.push File.expand_path("../lib", __FILE__)
require "openssl_rsa_pss_verify/version"

Gem::Specification.new do |s|
  s.name        = "openssl_rsa_pss_verify"
  s.version     = OpenSSL_RSA_PSS_Verify::VERSION
  s.platform    = Gem::Platform::RUBY
  s.authors     = ["Jon Distad"]
  s.email       = ["jon.distad@gmail.com"]
  s.homepage    = "https://github.com/jondistad/openssl_rsa_pss_verify"
  s.summary     = %q{Adds support for verifying RSA signatures using the Probabilistic Signature Scheme (PSS)}
  s.description = %q{Adds support for verifying RSA signatures using the Probabilistic Signature Scheme (PSS)}

  s.rubyforge_project = "openssl_rsa_pss_verify"

  s.files         = `git ls-files`.split("\n")
  s.test_files    = `git ls-files -- {test,spec,features}/*`.split("\n")
  s.executables   = `git ls-files -- bin/*`.split("\n").map{ |f| File.basename(f) }
  s.require_paths = ["lib", "ext"]
  s.extensions = %w{ext/openssl_rsa_pss_verify/extconf.rb}

  #s.add_development_dependency "rspec", "~> 2.11.0"
  s.add_development_dependency 'rake-compiler', "~> 0.8.3"
end
