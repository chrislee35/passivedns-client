require "passivedns/client/version"
# DESCRIPTION: queries passive DNS databases 
# This code is released under the LGPL: http://www.gnu.org/licenses/lgpl-3.0.txt
# Please note that use of any passive dns database is subject to the terms of use of that passive dns database.  Use of this script in violation of their terms is not encouraged in any way.  Also, please do not add any obfuscation to try to work around their terms of service.  If you need special services, ask the providers for help/permission.
# Remember, these passive DNS operators are my friends.  I don't want to have a row with them because some asshat used this library to abuse them.
require 'passivedns/client/state'
require 'passivedns/client/passivedb'

# load all the providers
$passivedns_providers = Array.new
provider_path = File.dirname(__FILE__)+"/client/provider/*.rb"
Dir.glob(provider_path).each do |provider|
  name = File.basename(provider, '.rb')
  require "passivedns/client/provider/#{name}.rb"
  $passivedns_providers << name
end

require 'configparser'

module PassiveDNS # :nodoc:
  # struct to contain the results from a PassiveDNS lookup
	class PDNSResult < Struct.new(:source, :response_time, :query, :answer, :rrtype, :ttl, :firstseen, :lastseen, :count); end

  # coodinates the lookups accross all configured PassiveDNS providers
	class Client
    
    # instantiate and configure all specified PassiveDNS providers
    # pdns        array of passivedns provider names, e.g., ["dnsdb","virustotal"]
    # configfile  filename of the passivedns-client configuration (this should probably be abstracted)
		def initialize(pdns=$passivedns_providers, configfile="#{ENV['HOME']}/.passivedns-client")
      cp = ConfigParser.new(configfile)
      # this creates a map of all the PassiveDNS provider names and their classes
      class_map = {}
      PassiveDNS::Provider.constants.each do |const|
        if PassiveDNS::Provider.const_get(const).is_a?(Class) and PassiveDNS::Provider.const_get(const).superclass == PassiveDNS::PassiveDB
          class_map[PassiveDNS::Provider.const_get(const).config_section_name] = PassiveDNS::Provider.const_get(const)
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
		
    # set the debug flag
		def debug=(d)
			@pdnsdbs.each do |pdnsdb|
				pdnsdb.debug = d
			end
		end
		
    # perform the query lookup accross all configured PassiveDNS providers
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
