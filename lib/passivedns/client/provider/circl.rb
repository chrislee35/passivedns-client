# DESCRIPTION: Module to query PassiveTotal's passive DNS repository

require 'net/http'
require 'net/https'
require 'openssl'

module PassiveDNS #:nodoc: don't document this
  # The Provider module contains all the Passive DNS provider client code
  module Provider
    # Queries CIRCL.LU's passive DNS database
    # Circl is aliased by CIRCL
  	class Circl < PassiveDB
      # Sets the modules self-reported name to "CIRCL"
      def self.name
        "CIRCL"
      end
      # Sets the configuration section name to "circl"
      def self.config_section_name
        "circl"
      end
      # Sets the command line database argument to "c"
      def self.option_letter
        "c"
      end
    
      # :debug enables verbose logging to standard output
      attr_accessor :debug
      # === Options
      # * :debug       Sets the debug flag for the module
      # * "USERNAME"   User name associated with your CIRCL account
      # * "PASSWORD"   Password associated with your CIRCL account
      # * "AUTH_TOKEN" Authorization token associated with your CIRCL account
      # * "URL"      Alternate url for testing.  Defaults to "https://www.circl.lu/pdns/query"
      
      # You should either have a username+password or an authorization token to use this service
      #
      # === Example Instantiation
      #
      #   options = {
      #     :debug => true,
      #     "USERNAME" => "circl_user",
      #     "PASSWORD" => "circl_pass",
      #     "URL" => "https://www.circl.lu/pdns/query"
      #   }
      #
      #   PassiveDNS::Provider::CIRCL.new(options)
      #
  		def initialize(options={})
        @debug = options[:debug] || false
        @username = options["USERNAME"]
        @password = options["PASSWORD"]
        @auth_token = options["AUTH_TOKEN"]
        @url = options["URL"] || "https://www.circl.lu/pdns/query"
  		end

      # Takes a label (either a domain or an IP address) and returns
      # an array of PassiveDNS::PDNSResult instances with the answers to the query
  		def lookup(label, limit=nil)
  			$stderr.puts "DEBUG: #{self.class.name}.lookup(#{label})" if @debug
  			Timeout::timeout(240) {
  				url = @url+"/"+label
  				$stderr.puts "DEBUG: #{self.class.name} url = #{url}" if @debug
  				url = URI.parse url
  				http = Net::HTTP.new(url.host, url.port)
  				http.use_ssl = (url.scheme == 'https')
  				http.verify_mode = OpenSSL::SSL::VERIFY_NONE
  				http.verify_depth = 5
  				request = Net::HTTP::Get.new(url.request_uri)
  				request.add_field("User-Agent", "Ruby/#{RUBY_VERSION} passivedns-client rubygem v#{PassiveDNS::Client::VERSION}")
          if @username
            request.basic_auth(@username, @password)
          end
          if @auth_token
            request.add_field("Authorization", @auth_token)
          end
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

      # parses the response of circl's JSON reply to generate an array of PDNSResult
  		def parse_json(page,query,response_time=0)
   			res = []
  			# need to remove the json_class tag or the parser will crap itself trying to find a class to align it to
        page.split(/\n/).each do |line|
          row = JSON.parse(line)
  				res << PDNSResult.new(self.class.name,response_time,
            row['rrname'], row['rdata'], row['rrtype'], 0, 
            row['time_first'], row['time_last'], row['count'])
        end
  			res
  		rescue Exception => e
  			$stderr.puts "#{self.class.name} Exception: #{e}"
  			raise e
  		end

  	end
    CIRCL = PassiveDNS::Provider::Circl
  end
end