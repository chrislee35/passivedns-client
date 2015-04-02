require 'net/http'
require 'net/https'
require 'openssl'
require 'json'
require 'digest/md5'

module PassiveDNS
  class CN360 < PassiveDB
    # override
    def self.name
      "360.cn"
    end
    #override
    def self.config_section_name
      "cn360"
    end
    #override
    def self.option_letter
      "3"
    end
    
    attr_accessor :debug
    def initialize(options={})
      @debug = options[:debug] || false
      ["API", "API_ID", "API_KEY"].each do |opt|
        if not options[opt]
          raise "Field #{opt} is required.  See README.md"
        end
      end
      @cp = options
    end
    
    def parse_json(page,query,response_time=0)
			res = []
			# need to remove the json_class tag or the parser will crap itself trying to find a class to align it to
			data = JSON.parse(page)
      data.each do |row|
        time_first = (row["time_first"]) ? Time.at(row["time_first"].to_i) : nil
        time_last = (row["time_last"]) ? Time.at(row["time_last"].to_i) : nil
        count = row["count"] || 0
        res << PDNSResult.new(self.class.name, response_time, row["rrname"], row["rdata"], row["rrtype"], time_first, time_last, count)
			end
			res
		rescue Exception => e
			$stderr.puts "#{self.class.name} Exception: #{e}"
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
			http.verify_mode = OpenSSL::SSL::VERIFY_NONE # I hate doing this
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
