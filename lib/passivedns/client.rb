require "passivedns/client/version"
# DESCRIPTION: queries passive DNS databases 
# This code is released under the LGPL: http://www.gnu.org/licenses/lgpl-3.0.txt
# Please note that use of any passive dns database is subject to the terms of use of that passive dns database.  Use of this script in violation of their terms is not encouraged in any way.  Also, please do not add any obfuscation to try to work around their terms of service.  If you need special services, ask the providers for help/permission.
# Remember, these passive DNS operators are my friends.  I don't want to have a row with them because some asshat used this library to abuse them.
require 'passivedns/client/bfk.rb'
require 'passivedns/client/certee.rb'
require 'passivedns/client/dnsparse.rb'
require 'passivedns/client/dnsdb.rb'
require 'passivedns/client/virustotal.rb'
require 'passivedns/client/state.rb'

module PassiveDNS

	class PDNSResult < Struct.new(:source, :response_time, :query, :answer, :rrtype, :ttl, :firstseen, :lastseen, :count); end

	class Client
		def initialize(pdns=['bfk','certee','dnsparse','dnsdb','virustotal'])
			@pdnsdbs = []
			pdns.uniq.each do |pd|
				case pd
				when 'bfk'
					@pdnsdbs << PassiveDNS::BFK.new
				when 'certee'
					@pdnsdbs << PassiveDNS::CERTEE.new
				when 'dnsparse'
					@pdnsdbs << PassiveDNS::DNSParse.new
				when 'dnsdb'
					@pdnsdbs << PassiveDNS::DNSDB.new
				when 'isc'
					@pdnsdbs << PassiveDNS::DNSDB.new
				when 'virustotal'
					@pdnsdbs << PassiveDNS::VirusTotal.new
				else
					raise "Unknown Passive DNS provider: #{pd}"
				end
			end
		end #initialize
		
		def debug=(d)
			@pdnsdbs.each do |pdnsdb|
				pdnsdb.debug = d
			end
		end
		
		def query(item)
			threads = []
			@pdnsdbs.each do |pdnsdb|
				threads << Thread.new(item) do |q|
					pdnsdb.lookup(q)
				end
			end
				
			results = []
			threads.each do |thr|
				rv = thr.join.value
				if rv
					rv.each do |r|
						if ["A","AAAA","NS","CNAME","PTR"].index(r.rrtype)
							results << r
						end
					end
				end
			end
			
			return results
		end #query
		
	end # Client
end # PassiveDNS
