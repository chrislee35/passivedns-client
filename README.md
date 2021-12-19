# PassiveDNS::Client

This rubygem queries the following Passive DNS databases:

* CIRCL
* DNSDB (FarSight)
* OpenSource Context (OSC)
* PassiveTotal
* RiskIQ
* VirusTotal

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

## Configuration

From version 2.0.0 on, all configuration keys for passive DNS providers are in one configuration file.  By default the location of the file is $HOME/.passivedns-client .  The syntax of this file is as follows:

	[dnsdb]
	APIKEY = 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
	[virustotal]
	APIKEY = 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
	[passivetotal]
	USERNAME = tom@example.com
	APIKEY = 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
	[circl]
	USERNAME = circl_user
	PASSWORD = circl_pass
	[riskiq]
	API_TOKEN = 0123456789abcdef
	API_PRIVATE_KEY = 01234567890abcdefghijklmnopqrstu
  [osc]
  APIKEY = 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef

CIRCL also can use and authorization token.  In that case, you should drop the USERNAME and PASSWORD options and change the section to something like the following:

	[circl]
	AUTH_TOKEN = 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef

## Getting Access
* CIRCL : https://www.circl.lu/services/passive-dns/
* DNSDB (Farsight Security) : https://api.dnsdb.info/
* OSC: https://oscontext.com/
* PassiveTotal : https://www.passivetotal.org
* RiskIQ : https://github.com/RiskIQ/python_api/blob/master/LICENSE
* VirusTotal : https://www.virustotal.com

## Usage

	require 'passivedns/client'

	c = PassiveDNS::Client.new(['riskiq','dnsdb'])
	results = c.query("example.com")


Or use the included tool...

    Usage: bin/pdnstool [-d [cdprv]] [-g|-v|-m|-c|-x|-y|-j|-t] [-os <sep>] [-f <file>] [-r#|-w#|-v] [-l <count>] [--config <file>] <ip|domain|cidr>
    Passive DNS Providers
      -dcdprv uses all of the available passive dns database
      -dc use CIRCL
      -dd use DNSDB
      -dp use PassiveTotal
      -dr use RiskIQ
      -dv use VirusTotal
      -dvr uses VirusTotal and RiskIQ (for example)

    Output Formatting
      -g link-nodal GDF visualization definition
      -z link-nodal graphviz visualization definition
      -m link-nodal graphml visualization definition
      -c CSV
      -x XML
      -y YAML
      -j JSON
      -t ASCII text (default)
      -s <sep> specifies a field separator for text output, default is tab

    State and Recursion
      -f[file] specifies a sqlite3 database used to read the current state - useful for large result sets and generating graphs of previous runs.
      -r# specifies the levels of recursion to pull. **WARNING** This is quite taxing on the pDNS servers, so use judiciously (never more than 3 or so) or find yourself blocked!
      -w# specifies the amount of time to wait, in seconds, between queries (Default: 0)
      -l <count> limits the number of records returned per passive dns database queried.

    Specifying a Configuration File
      --config <file> specifies a config file. default: /home/chris/.passivedns-client

    Getting Help
      -h hello there.  This option produces this helpful help information on how to access help.
      -v debugging information

## Writing Your Own Database Adaptor

  module PassiveDNS #:nodoc: don't document this
    # The Provider module contains all the Passive DNS provider client code
    module Provider
      # Queries OSContext's passive DNS database
      class MyDatabaseAdaptor < PassiveDB
        # Sets the modules self-reported name to "OSC"
		    def self.name
		      "MyPerfectDNS" # short, proper label
		    end
		    #override
		    def self.config_section_name
		      "perfect" # very short label to use in the configuration file
		    end
		    #override
		    def self.option_letter
		      "p" # single letter to specify the option for the command line tool
		    end

		    attr_accessor :debug

  			def initialize(options={})
  			  @debug = options[:debug] || false
  			  # please include a way to change the base URL, HOST, etc., so that people can test
  			  # against a test/alternate version of your service
  		      @base = options["URL"] || "http://myperfectdns.example.com/pdns.cgi?query="
  			  @apikey = options["APIKEY"] || raise("APIKEY option required for #{self.class}")
  			end

  			# override
  			def lookup(label, limit=nil)
  				$stderr.puts "DEBUG: #{self.class.name}.lookup(#{label})" if @debug
  				recs = []
  				Timeout::timeout(240) {
  					t1 = Time.now
  					# TODO: your code goes here to fetch the data from your service
  					# TODO: don't forget to impose the limit either during the fetch or during the parse phase
  					response_time = Time.now - t1
  					# TODO: parse your data and add PDNSResult objects to recs array
  					recs << PDNSResult.new(self.class.name, response_time, rrname ,
  						rdata, rrtype, ttl, first_seen, last_seen, count )
  				}
  				recs
  			rescue Timeout::Error => e # using the implied "begin/try" from the beginning of the function
  				$stderr.puts "#{self.class.name} lookup timed out: #{label}"
  			end
      end
		end
	end

## Passive DNS - Common Output Format

There is an RFC, <a href='http://tools.ietf.org/html/draft-dulaunoy-kaplan-passive-dns-cof-01'>Passive DNS - Common Output Format</a>, and a proof of concept implementation, <a href='https://github.com/adulau/pdns-qof-server'>pdns-qof-server</a>, that describes a recommened JSON format for passive DNS data.  passivedns-client is very close to supporting it, but since I've never enteracted with a true implementation of this RFC, I can't attest that I could correctly parse it.  I think they way that they can encode multiple results into one record would actually break what I have right now.

Right now, I'm in a wait and see mode with how this progresses before I start supporting yet another format or request that other providers start to adhere to a common output format.  If you have thoughts on the matter, I would love to discuss.

## Contributing

1. Fork it
2. Create your feature branch (`git checkout -b my-new-feature`)
3. Commit your changes (`git commit -am 'Add some feature'`)
4. Push to the branch (`git push origin my-new-feature`)
5. Create new Pull Request

<a href='mailto:github@chrisleephd[dot]us[stop here]xxx'><img src='http://chrisleephd.us/images/github-email.png?passivedns-client'></a>
