# DESCRIPTION: Module to query Mnemonic's passive DNS repository
# CONTRIBUTOR: Drew Hunt (pinowudi@yahoo.com)
require 'net/http'
require 'net/https'
require 'openssl'

module PassiveDNS #:nodoc: don't document this
  # The Provider module contains all the Passive DNS provider client code
  module Provider
    # Queries Mnemonic's passive DNS database
    class Mnemonic < PassiveDB
      # Sets the modules self-reported name to "Mnemonic"
      def self.name
        "Mnemonic"
      end
      # Sets the configuration section name to "mnemonic"
      def self.config_section_name
        "mnemonic"
      end
      # Sets the command line database argument to "m"
      def self.option_letter
        "m"
      end
    
      # :debug enables verbose logging to standard output
      attr_accessor :debug
      # === Options
      # * :debug       Sets the debug flag for the module
      # * "APIKEY"     The API key associated with Mnemonic for doing automated queries
      # * "URL"        Alternate url for testing.  Defaults to "https://api.mnemonic.no/pdns/v3/"
      #
      # === Example Instantiation
      #
      #   options = {
      #     :debug => true,
      #     "APIKEY" => "01234567890abcdef01234567890abcdef012345",
      #     "URL" => "https://api.mnemonic.no/pdns/v3/"
      #   }
      #
      #   PassiveDNS::Provider::Mnemonic.new(options)
      #
      def initialize(options={})
        @debug = options[:debug] || false
        @timeout = options[:timeout] || 20
        @apikey = options["APIKEY"]
        @url = options["URL"] || "https://api.mnemonic.no/pdns/v3/"
        if @url == "https://passivedns.mnemonic.no/api1/?apikey="
          @url = "https://api.mnemonic.no/pdns/v3/"
        end
      end

      # Takes a label (either a domain or an IP address) and returns
      # an array of PassiveDNS::PDNSResult instances with the answers to the query
      def lookup(label, limit=nil)
        $stderr.puts "DEBUG: #{self.class.name}.lookup(#{label})" if @debug
        Timeout::timeout(@timeout) {
          url = "#{@url}#{label}"
          $stderr.puts "DEBUG: #{self.class.name} url = #{url}" if @debug
          url = URI.parse url
          http = Net::HTTP.new(url.host, url.port)
          http.use_ssl = (url.scheme == 'https')
          http.verify_mode = OpenSSL::SSL::VERIFY_NONE
          http.verify_depth = 5
          request = Net::HTTP::Get.new(url.path)
          request.add_field("User-Agent", "Ruby/#{RUBY_VERSION} passivedns-client rubygem v#{PassiveDNS::Client::VERSION}")
          if @apikey
            request.add_field("Argus-API-Key", @apikey)
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
      rescue Timeout::Error
        $stderr.puts "#{self.class.name} lookup timed out: #{label}"
      end
    
      private
    
      # parses the response of mnemonic's JSON reply to generate an array of PDNSResult
      def parse_json(page,query,response_time=0)
        res = []
        data = JSON.parse(page)
        if data['data']
          data['data'].each do |row|
            if row['query']
              query = row['query']
              answer = row['answer']
              rrtype = row['rrtype'].upcase
              ttl = row['maxTtl'].to_i
              firstseen = Time.at(row['firstSeenTimestamp'].to_i / 1000)
              lastseen = Time.at(row['lastSeenTimestamp'].to_i / 1000)
              tlp = row['tlp']
              r = PDNSResult.new(self.class.name,response_time, query, answer, rrtype, ttl, firstseen, lastseen, tlp)
              res << r
            end
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
