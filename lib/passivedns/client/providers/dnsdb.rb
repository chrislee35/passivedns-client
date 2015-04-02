# DESCRIPTION: this is a module for pdns.rb, primarily used by pdnstool.rb, to query the Farsight Security passive DNS database
# details on the API are at https://api.dnsdb.info/
# to request an API key, please email dnsdb-api at farsightsecurity dot com.
require 'net/http'
require 'net/https'

module PassiveDNS
	class DNSDB < PassiveDB
    # override
    def self.name
      "DNSDB"
    end
    #override
    def self.config_section_name
      "dnsdb"
    end
    #override
    def self.option_letter
      "d"
    end
    
    attr_accessor :debug
		def initialize(options={})
			@debug = options[:debug] || false
      @key = options["APIKEY"] || raise("APIKEY option required for #{self.class}")
      @base = options["URL"] || "https://api.dnsdb.info/lookup"
		end

		def parse_json(page,response_time)
			res = []
			raise "Error: unable to parse request" if page =~ /Error: unable to parse request/
			# need to remove the json_class tag or the parser will crap itself trying to find a class to align it to
			rows = page.split(/\n/)
			rows.each do |row|
				record = JSON.parse(row)
				record['rdata'] = [record['rdata']] if record['rdata'].class == String
				record['rdata'].each do |rdata|
					if record['time_first']
						res << PDNSResult.new(self.class.name,response_time,record['rrname'],rdata,record['rrtype'],0,Time.at(record['time_first'].to_i).utc.strftime("%Y-%m-%dT%H:%M:%SZ"),Time.at(record['time_last'].to_i).utc.strftime("%Y-%m-%dT%H:%M:%SZ"),record['count'])
					else
						res << PDNSResult.new(self.class.name,response_time,record['rrname'],rdata,record['rrtype'])
					end
				end
			end
			res
		rescue Exception => e
			$stderr.puts "#{self.class.name} Exception: #{e}"
			$stderr.puts page
			raise e
		end

		def lookup(label, limit=nil)
			$stderr.puts "DEBUG: #{self.class.name}.lookup(#{label})" if @debug
			Timeout::timeout(240) {
				url = nil
				if label =~ /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(\/\d{1,2})?$/
					label = label.gsub(/\//,',')
					url = "#{@base}/rdata/ip/#{label}"
				else
					url = "#{@base}/rrset/name/#{label}"
				end
				url = URI.parse url
				http = Net::HTTP.new(url.host, url.port)
				http.use_ssl = (url.scheme == 'https')
				http.verify_mode = OpenSSL::SSL::VERIFY_NONE
				http.verify_depth = 5
        path = url.path
        if limit
          path << "?limit=#{limit}"
        end
				request = Net::HTTP::Get.new(path)
				request.add_field("User-Agent", "Ruby/#{RUBY_VERSION} passivedns-client rubygem v#{PassiveDNS::Client::VERSION}")
				request.add_field("X-API-Key", @key)
				request.add_field("Accept", "application/json")
				t1 = Time.now
				response = http.request(request)
				t2 = Time.now
				$stderr.puts response.body if @debug
				parse_json(response.body,t2-t1)
			}
		rescue Timeout::Error => e
			$stderr.puts "#{self.class.name} lookup timed out: #{label}"
		end
	end
end