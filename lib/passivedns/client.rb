require "passivedns/client/version"
# DESCRIPTION: queries passive DNS databases 
# This code is released under the LGPL: http://www.gnu.org/licenses/lgpl-3.0.txt
# Please note that use of any passive dns database is subject to the terms of use of that passive dns database.  Use of this script in violation of their terms is not encouraged in any way.  Also, please do not add any obfuscation to try to work around their terms of service.  If you need special services, ask the providers for help/permission.
# Remember, these passive DNS operators are my friends.  I don't want to have a row with them because some asshat used this library to abuse them.
require 'passivedns/client/state'
require 'passivedns/client/passivedb'

require 'passivedns/client/bfk'
require 'passivedns/client/certee'
require 'passivedns/client/circl'
require 'passivedns/client/cn360'
require 'passivedns/client/dnsdb'
require 'passivedns/client/mnemonic'
require 'passivedns/client/passivetotal'
require 'passivedns/client/tcpiputils'
require 'passivedns/client/virustotal'

require 'configparser'
require 'pp'

module PassiveDNS

	class PDNSResult < Struct.new(:source, :response_time, :query, :answer, :rrtype, :ttl, :firstseen, :lastseen, :count); end

	class Client
		def initialize(pdns=['bfk','certee','dnsdb','virustotal','tcpiputils','cn360','mnemonic','passivetotal','CIRCL'], configfile="#{ENV['HOME']}/.passivedns-client")
      cp = ConfigParser.new(configfile)
      # this creates a map of all the PassiveDNS provider names and their classes
      class_map = {}
      PassiveDNS.constants.each do |const|
        if PassiveDNS.const_get(const).is_a?(Class) and PassiveDNS.const_get(const).superclass == PassiveDNS::PassiveDB
          class_map[PassiveDNS.const_get(const).config_section_name] = PassiveDNS.const_get(const)
        end
      end
      
			@pdnsdbs = []
      pdns.uniq.each do |pd|
        if class_map[pd]
          @pdnsdbs << class_map[pd].new(cp[pd] || {})
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
		
		def query(item, limit=nil)
			threads = []
			@pdnsdbs.each do |pdnsdb|
				threads << Thread.new(item) do |q|
					pdnsdb.lookup(q, limit)
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
