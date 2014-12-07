# DESCRIPTION: this is a module for pdns.rb, primarily used by pdnstool.rb, to query VirusTotal's passive DNS database
require 'net/http'
require 'net/https'
require 'openssl'

module PassiveDNS
	class VirusTotal < PassiveDB
    # override
    def self.name
      "VirusTotal"
    end
    #override
    def self.config_section_name
      "virustotal"
    end
     #override
    def self.option_letter
      "v"
    end
    
    attr_accessor :debug
		def initialize(options={})
      @debug = options[:debug] || false
      @apikey = options["APIKEY"] || raise("#{self.class.name} requires an APIKEY.  See README.md")
      @url = options["URL"] || "https://www.virustotal.com/vtapi/v2/"
    end

		def parse_json(page,query,response_time=0)
			res = []
			# need to remove the json_class tag or the parser will crap itself trying to find a class to align it to
			data = JSON.parse(page)
			if data['resolutions']
				data['resolutions'].each do |row|
					if row['ip_address']
						res << PDNSResult.new(self.class.name,response_time,query,row['ip_address'],'A',nil,nil,row['last_resolved'])
					elsif row['hostname']
						res << PDNSResult.new(self.class.name,response_time,row['hostname'],query,'A',nil,nil,row['last_resolved'])
					end
				end
			end
			res
		rescue Exception => e
			$stderr.puts "VirusTotal Exception: #{e}"
			raise e
		end

		def lookup(label, limit=nil)
			$stderr.puts "DEBUG: #{self.class.name}.lookup(#{label})" if @debug
			Timeout::timeout(240) {
				url = nil
				if label =~ /^[\d\.]+$/
					url = "#{@url}ip-address/report?ip=#{label}&apikey=#{@apikey}"
				else
					url = "#{@url}domain/report?domain=#{label}&apikey=#{@apikey}"
				end
				$stderr.puts "DEBUG: #{self.class.name} url = #{url}" if @debug
				url = URI.parse url
				http = Net::HTTP.new(url.host, url.port)
				http.use_ssl = (url.scheme == 'https')
				http.verify_mode = OpenSSL::SSL::VERIFY_NONE
				http.verify_depth = 5
				request = Net::HTTP::Get.new(url.path+"?"+url.query)
				request.add_field("User-Agent", "Ruby/#{RUBY_VERSION} passivedns-client rubygem v#{PassiveDNS::Client::VERSION}")
				t1 = Time.now
				response = http.request(request)
				t2 = Time.now
				recs = parse_json(response.body, label, t2-t1)
        if limit
          recs[0,limit]
        else
          recs
        end
			}
		rescue Timeout::Error => e
			$stderr.puts "#{self.class.name} lookup timed out: #{label}"
		end
	end
end