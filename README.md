# PassiveDNS::Client

This rubygem queries 5 major Passive DNS databases: BFK, CERTEE, DNSParse, ISC, and VirusTotal.
Passive DNS is a technique where IP to hostname mappings are made by recording the answers of other people's queries.  

There is a tool included, pdnstool, that wraps a lot of the functionality that you would need.

Please note that use of any passive DNS database is subject to the terms of use of that passive DNS database.  Use of this script in violation of their terms is strongly discouraged.  Also, please do not add any obfuscation to try to work around their terms of service.  If you need special services, ask the providers for help/permission.  Remember, these passive DNS operators are my friends.  I don't want to have a row with them because some jerk used this library to abuse them.

If you like this library, please buy the Passive DNS operators a round of beers.

## Installation

Add this line to your application's Gemfile:

    gem 'passivedns-client'

And then execute:

    $ bundle

Or install it yourself as:

    $ gem install passivedns-client

## Usage

	require 'passivedns-client'
	
	c = PassiveDNS::Client.new(['bfk','dnsdb']) # providers: bfk, dnsparse, certee, dnsdb, virustotal
	results = c.query("example.com")
	
Or use the included tool!

	Usage: bin/pdnstool [-a|-b|-e|-d|-i|-V] [-c|-x|-y|-j|-t] [-s <sep>] [-f <file>] [-r#|-w#|-l] <ip|domain|cidr>
	  -a uses all of the available passive dns databases
	  -b only use BFK
	  -e only use CERT-EE
	  -d only use DNSParse (default)
	  -i only use DNSDB (formerly ISC)
	  -V only use VirusTotal

	  -g outputs a link-nodal GDF visualization definition
	  -v outputs a link-nodal graphviz visualization definition
	  -m output a link-nodal graphml visualization definition
	  -c outputs CSV
	  -x outputs XML
	  -y outputs YAML
	  -j outputs JSON
	  -t outputs ASCII text (default)
	  -s <sep> specifies a field separator for text output, default is tab

	  -f[file] specifies a sqlite3 database used to read the current state - useful for large result sets and generating graphs of previous runs.
	  -r# specifies the levels of recursion to pull. **WARNING** This is quite taxing on the pDNS servers, so use judiciously (never more than 3 or so) or find yourself blocked!
	  -w# specifies the amount of time to wait, in seconds, between queries (Default: 0)
	  -l outputs debugging information

## Contributing

1. Fork it
2. Create your feature branch (`git checkout -b my-new-feature`)
3. Commit your changes (`git commit -am 'Add some feature'`)
4. Push to the branch (`git push origin my-new-feature`)
5. Create new Pull Request
