# DESCRIPTION: Module to query PassiveTotal's passive DNS repository

require 'net/http'
require 'net/https'
require 'openssl'

module PassiveDNS #:nodoc: don't document this
  # The Provider module contains all the Passive DNS provider client code
  module Provider
    # Queries PassiveTotal's passive DNS database
  	class PassiveTotal < PassiveDB
      # Sets the modules self-reported name to "PassiveTotal"
      def self.name
        "PassiveTotal"
      end
      # Sets the configuration section name to "passivetotal"
      def self.config_section_name
        "passivetotal"
      end
      # Sets the command line database argument to "p"
      def self.option_letter
        "p"
      end
    
      # :debug enables verbose logging to standard output
      attr_accessor :debug
      # === Options
      # * :debug       Sets the debug flag for the module
      # * "APIKEY"     REQUIRED: The API key associated with PassiveTotal
      # * "URL"      Alternate url for testing.  Defaults to "https://www.passivetotal.org/api/passive"
      #
      # === Example Instantiation
      #
      #   options = {
      #     :debug => true,
      #     "APIKEY" => "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
      #     "URL" => "https://www.passivetotal.org/api/passive"
      #   }
      #
      #   PassiveDNS::Provider::PassiveTotal.new(options)
      #
  		def initialize(options={})
        @debug = options[:debug] || false
        @apikey = options["APIKEY"] || raise("#{self.class.name} requires an APIKEY")
        @url = options["URL"] || "https://www.passivetotal.org/api/passive"
  		end

      # Takes a label (either a domain or an IP address) and returns
      # an array of PassiveDNS::PDNSResult instances with the answers to the query
  		def lookup(label, limit=nil)
  			$stderr.puts "DEBUG: #{self.class.name}.lookup(#{label})" if @debug
  			Timeout::timeout(240) {
  				url = @url
  				$stderr.puts "DEBUG: #{self.class.name} url = #{url}" if @debug
  				url = URI.parse url
  				http = Net::HTTP.new(url.host, url.port)
  				http.use_ssl = (url.scheme == 'https')
  				http.verify_mode = OpenSSL::SSL::VERIFY_NONE
  				http.verify_depth = 5
  				request = Net::HTTP::Post.new(url.request_uri)
  				request.add_field("User-Agent", "Ruby/#{RUBY_VERSION} passivedns-client rubygem v#{PassiveDNS::Client::VERSION}")
          request.set_form_data({"apikey" => @apikey, "value" => label})
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
    
      private
    
      # parses the response of passivetotals's JSON reply to generate an array of PDNSResult
  		def parse_json(page,query,response_time=0)
   			res = []
  			# need to remove the json_class tag or the parser will crap itself trying to find a class to align it to
  			data = JSON.parse(page)
  			if data['results']
          query = data['results']['value']
  				data['results']['resolutions'].each do |row|
            first_seen = row['firstSeen']
            last_seen = row['lastSeen']
            value = row['value']
            source = row['source'].join(",")
  					res << PDNSResult.new(self.class.name+"/"+source,response_time,
              query, value, "A", 0, first_seen, last_seen)
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