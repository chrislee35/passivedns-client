require 'net/http'
require 'net/https'
require 'openssl'
require 'json'
require 'digest/md5'

module PassiveDNS #:nodoc: don't document this
  # The Provider module contains all the Passive DNS provider client code
  module Provider
    # Queries 360.cn's passive DNS database
    class CN360 < PassiveDB
      # Sets the modules self-reported name to "360.cn"
      def self.name
        "360.cn"
      end
      # Sets the configuration section name to "cn360"
      def self.config_section_name
        "cn360"
      end
      # Sets the command line database argument to "3"
      def self.option_letter
        "3"
      end
    
      # :debug enables verbose logging to standard output
      attr_accessor :debug
      # === Options
      # * :debug       Sets the debug flag for the module
      # * "API"        REQUIRED: http://some.web.address.for.their.api
      # * "API_ID"     REQUIRED: a username that is given when you register
      # * "API_KEY"    REQUIRED: a long and random password of sorts that is used along with the page request to generate a per page API key
      #
      # === Example Instantiation
      #
      #   options = {
      #     :debug => true,
      #     "API" => "http://some.web.address.for.their.api",
      #     "API_ID" => "360user",
      #     "API_KEY" => "360apikey"
      #   }
      #
      #   PassiveDNS::Provider::CN360.new(options)
      #
      def initialize(options={})
        @debug = options[:debug] || false
        ["API", "API_ID", "API_KEY"].each do |opt|
          if not options[opt]
            raise "Field #{opt} is required.  See README.md"
          end
        end
        @cp = options
      end
    
      # Takes a label (either a domain or an IP address) and returns
      # an array of PassiveDNS::PDNSResult instances with the answers to the query
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
      
      private
      
      # parses the response of 360.cn's JSON reply to generate an array of PDNSResult
      def parse_json(page,query,response_time=0)
  			res = []
  			# need to remove the json_class tag or the parser will crap itself trying to find a class to align it to
  			data = JSON.parse(page)
        data.each do |row|
          time_first = (row["time_first"]) ? Time.at(row["time_first"].to_i) : nil
          time_last = (row["time_last"]) ? Time.at(row["time_last"].to_i) : nil
          count = row["count"] || 0
          query = row["rrname"]
          answers = row["rdata"].gsub(/;$/,'').split(/;/)
          rrtype = row["rrtype"]
          answers.each do |answer|
            res << PDNSResult.new(self.class.name, response_time, query, answer, rrtype, time_first, time_last, count)
          end
  			end
  			res
  		rescue Exception => e
  			$stderr.puts "#{self.class.name} Exception: #{e}"
  			raise e
      end
    end
  end
end