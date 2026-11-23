# frozen_string_literal: true

require_relative 'lib/passivedns/client/version'

Gem::Specification.new do |spec|
  spec.name          = 'passivedns-client'
  spec.version       = PassiveDNS::Client::VERSION
  spec.authors       = ['chrislee35']
  spec.email         = ['rubygems@chrislee.dhs.org']
  spec.description   = 'This provides interfaces to various passive DNS databases to do the query and to normalize the responses. ' \
                       'The query tool also allows for recursive queries, using an SQLite3 database to keep state.'
  spec.summary       = 'Query passive DNS databases'
  spec.homepage      = 'https://github.com/chrislee35/passivedns-client'
  spec.license       = 'MIT'

  spec.metadata = {
    'source_code_uri' => spec.homepage,
    'bug_tracker_uri' => "#{spec.homepage}/issues",
    'changelog_uri' => "#{spec.homepage}/blob/master/CHANGELOG.md",
    'documentation_uri' => 'https://chrislee35.github.io/passivedns-client/',
    'rubygems_mfa_required' => 'true'
  }

  spec.files         = Dir['lib/**/*.rb', 'bin/*', 'LICENSE.txt', 'README.md', 'CHANGELOG.md']
  spec.bindir        = 'bin'
  spec.executables   = spec.files.grep(%r{^bin/}) { |f| File.basename(f) }
  spec.require_paths = ['lib']
  spec.required_ruby_version = '>= 3.2'

  spec.add_dependency 'getoptlong'
  spec.add_dependency 'iniparse', '~> 1.5'
  spec.add_dependency 'sqlite3', '>= 1.4'
  spec.add_dependency 'structformatter'

  spec.add_development_dependency 'minitest', '~> 6.0'
  spec.add_development_dependency 'rake', '~> 13.0'
  spec.add_development_dependency 'rubocop', '~> 1.0'
  spec.add_development_dependency 'rubocop-performance', '~> 1.0'
end
