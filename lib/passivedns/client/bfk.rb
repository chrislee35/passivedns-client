require 'open-uri'

module PassiveDNS
	class BFK
		attr_accessor :debug
		def initialize
			@debug = false
		end
		@@base = "http://www.bfk.de/bfk_dnslogger.html?query="
		def parse(page,response_time)
			line = page.unpack('C*').pack('U*').split(/<table/).grep(/ id=\"logger\"/)
			return [] unless line.length > 0
			line = line[0].gsub(/[\t\n]/,'').gsub(/<\/table.*/,'')
			rows = line.split(/<tr.*?>/)
			res = []
			rows.collect do |row|
				r = row.split(/<td>/).map{|x| x.gsub(/<.*?>/,'').gsub(/\&.*?;/,'')}[1,1000]
				if r and r[0] =~ /\w/
					# BFK includes the MX weight in the answer response. First, find the MX records, then dump the weight to present a consistent record name to the collecting array. Otherwise the other repositories will present the same answer and your results will become cluttered with duplicates.
					if r[1] == "MX" then
						# MX lines look like "5 mx.domain.tld", so split on the space and assign r[2] (:answer) to the latter part.
						#s = r[2].split(/\w/).map{|x| x}[1,1000]
						#	r[2] = s[1]
						r[2] =~ /[0-9]+?\s(.+)/
						s=$1
						puts "DEBUG: == BFK: MX Parsing Strip: Answer: " + r[2] + " : mod: " + s if @debug
						r[2] = s
							
							######### FIX BLANKS FOR MX
							
					end
					res << PDNSResult.new('BFK',response_time,r[0],r[2],r[1])
				end
			end
			res
		rescue Exception => e
			$stderr.puts "BFKClient Exception: #{e}"
			raise e
		end

		def lookup(label, limit=nil)	
			$stderr.puts "DEBUG: BFKClient.lookup(#{label})" if @debug
			Timeout::timeout(240) {
				t1 = Time.now
				open(
					@@base+label,
					"User-Agent" => "Ruby/#{RUBY_VERSION} passivedns-client rubygem v#{PassiveDNS::Client::VERSION}",
					:http_basic_authentication => [@user,@pass]
				) do |f|
					t2 = Time.now
					recs = parse(f.read,t2-t1)
          if limit
            recs[0,limit]
          else
            recs
          end
				end
			}
		rescue Timeout::Error => e
			$stderr.puts "BFK lookup timed out: #{label}"      
		end
	end
end