# DESCRIPTION: this is a module for pdns.rb, primarily used by pdnstool.rb, to query VirusTotal's passive DNS database
require 'net/http'
require 'net/https'
require 'openssl'

module PassiveDNS
	class VirusTotal
		attr_accessor :debug
		def initialize(config="#{ENV['HOME']}/.virustotal")
			if File.exist?(config)
				@apikey = File.open(config).read.split(/\n/)[0]
				$stderr.puts "DEBUG: VirusTotal#initialize(#{@apikey})" if @debug
			else
				raise "Configuration file for VirusTotal is required for intialization\nFormat of configuration file (default: #{ENV['HOME']}/.apikey) is:\n<url>\n<apikey>\n"
			end
		end

		def parse_json(page,query,response_time=0)
			res = []
			# need to remove the json_class tag or the parser will crap itself trying to find a class to align it to
			data = JSON.parse(page)
			if data['resolutions']
				data['resolutions'].each do |row|
					if row['ip_address']
						res << PDNSResult.new('VirusTotal',response_time,query,row['ip_address'],'A',nil,nil,row['last_resolved'])
					elsif row['hostname']
						res << PDNSResult.new('VirusTotal',response_time,row['hostname'],query,'A',nil,nil,row['last_resolved'])
					end
				end
			end
			res
		rescue Exception => e
			$stderr.puts "VirusTotal Exception: #{e}"
			raise e
		end

		def lookup(label)
			$stderr.puts "DEBUG: VirusTotal.lookup(#{label})" if @debug
			Timeout::timeout(240) {
				url = nil
				if label =~ /^[\d\.]+$/
					url = "https://www.virustotal.com/vtapi/v2/ip-address/report?ip=#{label}&apikey=#{@apikey}"
				else
					url = "https://www.virustotal.com/vtapi/v2/domain/report?domain=#{label}&apikey=#{@apikey}"
				end
				$stderr.puts "DEBUG: VirusTotal url = #{url}" if @debug
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
				parse_json(response.body, label, t2-t1)
			}
		rescue Timeout::Error => e
			$stderr.puts "VirusTotal lookup timed out: #{label}"
		end
	end
end