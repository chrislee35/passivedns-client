# DESCRIPTION: Module to query PassiveTotal's passive DNS repository

require 'net/http'
require 'net/https'
require 'openssl'
require 'pp'

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
      # * "USERNAME"   REQUIRED: The username for the associated API key
      # * "APIKEY"     REQUIRED: The API key associated with PassiveTotal
      # * "URL"      Alternate url for testing.  Defaults to "https://api.passivetotal.org/v2/dns/passive"
      #
      # === Example Instantiation
      #
      #   options = {
      #     :debug => true,
      #     "USERNAME" => "tom@example.com",
      #     "APIKEY" => "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
      #     "URL" => "https://api.passivetotal.org/v2/dns/passive"
      #   }
      
      #   or
      #
      #   options = {
      #     :debug => true,
      #     "USERNAME" => "tom@example.com"
      #     "APIKEY" => "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
      #   }
      #
      #   then
      #
      #   PassiveDNS::Provider::PassiveTotal.new(options)
      #
      def initialize(options={})
        @debug = options[:debug] || false
        @timeout = options[:timeout] || 20
        @username = options["USERNAME"] || raise("#{self.class.name} requires a USERNAME")
        @apikey = options["APIKEY"] || raise("#{self.class.name} requires an APIKEY")
        @url = options["URL"] || "https://api.passivetotal.org/v2/dns/passive"
      end

      # Takes a label (either a domain or an IP address) and returns
      # an array of PassiveDNS::PDNSResult instances with the answers to the query
      def lookup(label, limit=nil)
        $stderr.puts "DEBUG: #{self.class.name}.lookup(#{label})" if @debug
        Timeout::timeout(@timeout) {
          url = @url+"?query=#{label}"
          $stderr.puts "DEBUG: #{self.class.name} url = #{url}" if @debug
          url = URI.parse url
          http = Net::HTTP.new(url.host, url.port)
          http.use_ssl = (url.scheme == 'https')
          http.verify_mode = OpenSSL::SSL::VERIFY_NONE
          http.verify_depth = 5
          request = Net::HTTP::Get.new(url.request_uri)
          request.basic_auth(@username, @apikey)
          request.add_field("User-Agent", "Ruby/#{RUBY_VERSION} passivedns-client rubygem v#{PassiveDNS::Client::VERSION}")
          #request.set_form_data({"api_key" => @apikey, "query" => label})
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
      rescue Timeout::Error
        $stderr.puts "#{self.class.name} lookup timed out: #{label}"
      end
    
      private
    
      # parses the response of passivetotals's JSON reply to generate an array of PDNSResult
      def parse_json(page,query,response_time=0)
        res = []
        data = JSON.parse(page)
        pp data
        if data['message']
          raise "#{self.class.name} Error: #{data['message']}"
        end
        query = data['queryValue']
        if data['results']
          data['results'].each do |row|
            first_seen = (row['firstSeen'] == "None") ? nil : Time.parse(row['firstSeen']+" +0000")
            last_seen = (row['lastSeen'] == "None") ? nil : Time.parse(row['lastSeen']+" +0000")
            value = row['resolve']
            source = row['source'].join(",")
            res << PDNSResult.new(self.class.name+"/"+source,response_time,
              query, value, "A", 0, first_seen, last_seen, 'yellow')
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
