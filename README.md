# PassiveDNS::Client

This rubygem queries 7 major Passive DNS databases: BFK, CERTEE, DNSParse, DNSDB, VirusTotal, PassiveDNS.cn, and Mnemonic.
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

From version 2.0.0 on, all configuration keys for passive DNS providers are in one configuration file.  By default the location of the file is $HOME/.passivedns-client .  The synt

### DNSDB (Farsight Security)

The DNSDB configuration file is located at $HOME/.dnsdb-query.conf by default. The format for its configuration file only requires one line in the following format:

  APIKEY="0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

To request an API Key, please read https://api.dnsdb.info/.

### CERTEE

CERT-EE does not require any configuration.

### BFK.de

BFK.de does not require any configuration. However, please read and abide by their usage policy at BFK.de. Currently, it just says not to perform automated queries.

### VirusTotal

VirusTotal's  (https://www.virustotal.com) passive DNS database requires an apikey in $HOME/.virustotal.  It is a 64 character hexstring on a single line.

  01234567890abcdef01234567890abcdef01234567890abcdef01234567890abcdef


### TCPIPUtils

TCPIPUtils's (http://www.tcpiputils.com/premium-access) passive DNS database requires and apikey in $HOME/.tcpiputils.  It is a 64 character hexstring on a single line.

  01234567890abcdef01234567890abcdef01234567890abcdef01234567890abcdef


### PassiveDNS.cn from 360.cn

PassiveDNS.cn (http://www.passivedns.cn) requires an API ID and and API KEY, which is obtainable by creating an account and sending an email to request an API key.  

The configuration file can be in /etc/flint.conf (flint is the name of their tool, which is available at <a href='https://github.com/360netlab/flint'>https://github.com/360netlab/flint</a>) or in $HOME/.flint.conf (which is my preference).

The file must have three lines and looks like:

	API = http://some.web.address.for.their.api
	API_ID = a username that is given when you register
	API_KEY = a long and random password of sorts that is used along with the page request to generate a per page API key

### Mnemonic

Mnemonic requires an API KEY in $HOME/.mnemonic, which may be requested by making an inquiry to mss @ mnemonic.no. It is a 40 character hexstring on a single line. 

  01234567890abcdef01234567890abcdef012345

Mnemonic requests that API access and automated query be approved by them first. Please abide this request.


## Usage

	require 'passivedns/client'
	
	c = PassiveDNS::Client.new(['bfk','dnsdb']) # providers: bfk, tcpiputils, certee, dnsdb, virustotal, passivedns.cn, mnemonic
	results = c.query("example.com")
	
Or use the included tool!

	Usage: bin/pdnstool [-d [bedvt3m]] [-g|-v|-m|-c|-x|-y|-j|-t] [-os <sep>] [-f <file>] [-r#|-w#|-v] [-l <count>] <ip|domain|cidr>
	  -dbedvt3m uses all of the available passive dns databases
	  -db use BFK
	  -de use CERT-EE (default)
	  -dd use DNSDB (formerly ISC)
	  -dv use VirusTotal
	  -dt use TCPIPUtils
	  -d3 use 360.cn (www.passivedns.cn)
	  -dm uses Mnemonic (passivedns.mnemonic.no)
	  -dvt uses VirusTotal and TCPIPUtils (for example)

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
	  -v outputs debugging information
	  -l <count> limits the number of records returned per passive dns database queried.

## Passive DNS - Common Output Format

There is an RFC, <a href='http://tools.ietf.org/html/draft-dulaunoy-kaplan-passive-dns-cof-01'>Passive DNS - Common Output Format</a>, and a proof of concept implementation, <a href='https://github.com/adulau/pdns-qof-server'>pdns-qof-server</a>, that describes a recommened JSON format for passive DNS data.  passivedns-client is very close to supporting it, but since I've never enteracted with a true implementation of this RFC, I can't attest that I could correctly parse it.  I think they way that they can encode multiple results into one record would actually break what I have right now.

Right now, I'm in a wait and see mode with how this progresses before I start supporting yet another format or request that other providers start to adhere to a common output format.  If you have thoughts on the matter, I would love to discuss.

## Contributing

1. Fork it
2. Create your feature branch (`git checkout -b my-new-feature`)
3. Commit your changes (`git commit -am 'Add some feature'`)
4. Push to the branch (`git push origin my-new-feature`)
5. Create new Pull Request

<a href='mailto:github@chrislee[dot]dhs[dot]org[stop here]xxx'><img src='http://chrisleephd.us/images/github-email.png?passivedns-client'></a>
