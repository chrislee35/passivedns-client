require 'net/http'
require 'net/https'
require 'openssl'
require 'json'
require 'digest/md5'
require 'configparser'
require 'pp'

# Please read http://www.tcpiputils.com/terms-of-service under automated requests

module PassiveDNS
  class CN360
    attr_accessor :debug
        
    def initialize(configfile="#{ENV["HOME"]}/.flint.conf")
      @debug = false
      if not File.exist?(configfile)
        if not File.exist?("/etc/flint.conf")
          raise "Cannot find a configuration file at #{configfile} or /etc/flint.conf"
        end
        configfile = "/etc/flint.conf"
      end
      
      @cp = ConfigParser.new(configfile)
      if not @cp["API"]
        raise "Field, API, is required in the configuration file.  It should specify the URL of the JSON Web API."
      end
      if not @cp["API_ID"]
        raise "Field, API_ID, is required in the configuration file.  It should specify the user ID for the API key."
      end
      if not @cp["API_KEY"]
        raise "Field, API_KEY, is required in the configuration file.  It should specify the API key."
      end
    end
    
    def parse_json(page,query,response_time=0)
			res = []
			# need to remove the json_class tag or the parser will crap itself trying to find a class to align it to
			data = JSON.parse(page)
      data.each do |row|
        time_first = (row["time_first"]) ? Time.at(row["time_first"].to_i) : nil
        time_last = (row["time_last"]) ? Time.at(row["time_last"].to_i) : nil
        count = row["count"] || 0
        res << PDNSResult.new('cn360', response_time, row["rrname"], row["rdata"], row["rrtype"], time_first, time_last, count)
			end
			res
		rescue Exception => e
			$stderr.puts "360.cn Exception: #{e}"
			raise e
    end
    
    def lookup(label, limit=10000)
      table = "rrset"
      if label =~ /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/ or label =~ /^[0-9a-fA-F]+:[0-9a-fA-F:]+[0-9a-fA-F]$/
        table = "rdata"
      end
      limit ||= 10000
      path = "/api/#{table}/keyword/#{label}/count/#{limit}/"
      url = @cp["API"]+path
			url = URI.parse url
			http = Net::HTTP.new(url.host, url.port)
			http.use_ssl = (url.scheme == 'https')
			http.verify_mode = OpenSSL::SSL::VERIFY_NONE
			http.verify_depth = 5
			request = Net::HTTP::Get.new(url.path)
			request.add_field("User-Agent", "Ruby/#{RUBY_VERSION} passivedns-client rubygem v#{PassiveDNS::Client::VERSION}")
      request.add_field('Accept', 'application/json')
      request.add_field("X-BashTokid", @cp["API_ID"])
      token = Digest::MD5.hexdigest(path+@cp["API_KEY"])
			$stderr.puts "DEBUG: cn360 url = #{url} token = #{token}" if @debug
      request.add_field("X-BashToken", token)
			t1 = Time.now
			response = http.request(request)
			t2 = Time.now
			recs = parse_json(response.body, label, t2-t1)
      if limit
        recs[0,limit]
      else
        recs
      end
    end
  end
end
