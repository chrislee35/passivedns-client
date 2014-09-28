# coding: utf-8
lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'passivedns/client/version'

Gem::Specification.new do |spec|
	spec.name          = "passivedns-client"
	spec.version       = PassiveDNS::Client::VERSION
	spec.authors       = ["chrislee35"]
	spec.email         = ["rubygems@chrislee.dhs.org"]
	spec.description   = %q{This provides interfaces to various passive DNS databases to do the query and to normalize the responses.  The query tool also allows for recursive queries, using an SQLite3 database to keep state.}
	spec.summary       = %q{Query passive DNS databases}
	spec.homepage      = "https://github.com/chrislee35/passivedns-client"
	spec.license       = "MIT"

	spec.files         = `git ls-files`.split($/)
	spec.executables   = spec.files.grep(%r{^bin/}) { |f| File.basename(f) }
	spec.test_files    = spec.files.grep(%r{^(test|spec|features)/})
	spec.require_paths = ["lib"]

	spec.add_runtime_dependency 'json', '>= 1.4.3'
	spec.add_runtime_dependency 'sqlite3', '>= 1.3.3'
	spec.add_runtime_dependency 'structformatter', '~> 0.0.1'
  spec.add_runtime_dependency 'configparser', '~> 0.1.3'
	spec.add_development_dependency "bundler", "~> 1.3"
	spec.add_development_dependency "rake"

	#spec.signing_key   = "#{File.dirname(__FILE__)}/../gem-private_key.pem"
	#spec.cert_chain    = ["#{File.dirname(__FILE__)}/../gem-public_cert.pem"]
end
