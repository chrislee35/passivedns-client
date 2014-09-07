# DESCRIPTION: this is a module for pdns.rb, primarily used by pdnstool.rb, to query Bojan Zdrnja's passive DNS database, DNSParse
require 'net/http'
require 'net/https'
require 'openssl'

module PassiveDNS
	class DNSParse
		attr_accessor :debug
		@@dns_rtypes = {1 => 'A', 2 => 'NS', 3 => 'MD', 4 => 'MF', 5 => 'CNAME', 6 => 'SOA', 7 => 'MB', 8 => 'MG', 9 => 'MR', 10 => 'NULL', 11 => 'WKS', 12 => 'PTR', 13 => 'HINFO', 14 => 'MINFO', 15 => 'MX', 16 => 'TXT', 17 => 'RP', 18 => 'AFSDB', 19 => 'X25', 20 => 'ISDN', 21 => 'RT', 22 => 'NSAP', 23 => 'NSAP-PTR', 24 => 'SIG', 25 => 'KEY', 26 => 'PX', 27 => 'GPOS', 28 => 'AAAA', 29 => 'LOC', 30 => 'NXT', 31 => 'EID', 32 => 'NIMLOC', 33 => 'SRV', 34 => 'ATMA', 35 => 'NAPTR', 36 => 'KX', 37 => 'CERT', 38 => 'A6', 39 => 'DNAME', 40 => 'SINK', 41 => 'OPT', 42 => 'APL', 43 => 'DS', 44 => 'SSHFP', 45 => 'IPSECKEY', 46 => 'RRSIG', 47 => 'NSEC', 48 => 'DNSKEY', 49 => 'DHCID', 55 => 'HIP', 99 => 'SPF', 100 => 'UINFO', 101 => 'UID', 102 => 'GID', 103 => 'UNSPEC', 249 => 'TKEY', 250 => 'TSIG', 251 => 'IXFR', 252 => 'AXFR', 253 => 'MAILB', 254 => 'MAILA', 255 => 'ALL'}
		def initialize(config="#{ENV['HOME']}/.dnsparse")
			if File.exist?(config)
				@base,@user,@pass = File.open(config).read.split(/\n/)
				$stderr.puts "DEBUG: DNSParse#initialize(#{@base}, #{@user}, #{@pass})" if @debug
			else
				raise "Configuration file for DNSParse is required for intialization\nFormat of configuration file (default: #{ENV['HOME']}/.dnsparse) is:\n<url>\n<username>\n<password>\n"
			end
		end

		def parse_json(page,response_time=0)
			res = []
			# need to remove the json_class tag or the parser will crap itself trying to find a class to align it to
			page = page.gsub(/\"json_class\"\:\"PDNSResult\"\,/,'')
			recs = JSON.parse(page)
			recs.each do |row|
				res << PDNSResult.new('DNSParse',response_time,row["query"],row["answer"],@@dns_rtypes[row["rrtype"].to_i],row["ttl"],row["firstseen"],row["lastseen"])
			end
			res
		rescue Exception => e
			$stderr.puts "DNSParse Exception: #{e}"
			raise e
		end

		def parse_html(page,response_time=0)
			rows = []
			line = page.split(/<table/).grep(/ id=\"dnsparse\"/)
			return [] unless line.length > 0
			line = line[0].gsub(/[\t\n]/,'').gsub(/<\/table.*/,'')
			rows = line.split(/<tr.*?>/)
			res = []
			rows.collect do |row|
				r = row.split(/<td>/).map{|x| x.gsub(/<.*?>/,'').gsub(/\&.*?;/,'').gsub(/[\t\n]/,'')}[1,1000]
				if r and r[0] =~ /\w/
					#TXT records screw up other functions and don't provide much without a lot of subparshing. Dropping for now.
					if r[2]!="TXT" then
						res << PDNSResult.new('DNSParse',response_time,r[0],r[1],r[2],r[3],r[4],r[5])
					end
				end
			end
			res
		rescue Exception => e
			$stderr.puts "DNSParse Exception: #{e}"
			raise e
		end

		def lookup(label, limit=nil)
			$stderr.puts "DEBUG: DNSParse.lookup(#{label})" if @debug
			Timeout::timeout(240) {
				year = Time.now.strftime("%Y").to_i
				month = Time.now.strftime("%m").to_i
        if month < 3
          year -= 1
        end
        year = 2013 # until I get some confirmation that the service is staying current
				url = "#{@base}#{label}&year=#{year}"
				if label =~ /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\d{1,2}$/
					url.gsub!(/query\.php/,'cidr.php')
				elsif label =~ /\*$/
					url.gsub!(/query\.php/,'wildcard.php')
				end
				$stderr.puts "DEBUG: DNSParse url = #{url}" if @debug
				url = URI.parse url
				http = Net::HTTP.new(url.host, url.port)
				http.use_ssl = (url.scheme == 'https')
				http.verify_mode = OpenSSL::SSL::VERIFY_NONE
				http.verify_depth = 5
				request = Net::HTTP::Get.new(url.path+"?"+url.query)
				request.add_field("User-Agent", "Ruby/#{RUBY_VERSION} passivedns-client rubygem v#{PassiveDNS::Client::VERSION}")
				request.basic_auth @user, @pass
				t1 = Time.now
				response = http.request(request)
				t2 = Time.now
        recs = []
				if @base =~ /format=json/
					recs = parse_json(response.body,t2-t1)
				else
					recs = parse_html(response.body,t2-t1)
				end
        if limit
          recs[0,limit]
        else
          recs
        end
			}
		rescue Timeout::Error => e
			$stderr.puts "DNSParse lookup timed out: #{label}"
		end
	end
end