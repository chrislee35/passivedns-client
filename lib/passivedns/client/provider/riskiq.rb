# DESCRIPTION: Module to query PassiveTotal's passive DNS repository

require 'net/http'
require 'net/https'
require 'openssl'
require 'pp'

module PassiveDNS #:nodoc: don't document this
  # The Provider module contains all the Passive DNS provider client code
  module Provider
    # Queries RiskIQ's passive DNS database
    class RiskIQ < PassiveDB
      # Sets the modules self-reported name to "RiskIQ"
      def self.name
        "RiskIQ"
      end
      # Sets the configuration section name to "riskiq"
      def self.config_section_name
        "riskiq"
      end
      # Sets the command line database argument to "r"
      def self.option_letter
        "r"
      end
    
      # :debug enables verbose logging to standard output
      attr_accessor :debug
      # === Options
      # * :debug            Sets the debug flag for the module
      # * "API_TOKEN"       REQUIRED: User name associated with your RiskIQ account
      # * "API_PRIVATE_KEY" REQUIRED: Password associated with your RiskIQ account
      # * "API_SERVER"      Alternate server for testing.  Defaults to "ws.riskiq.net"
      # * "API_VERSION"     Alternate version of the API to test.  Defaults to "V1"
      #
      # === Example Instantiation
      #
      #   options = {
      #     :debug => true,
      #     "API_TOKEN" => "riskiq_token",
      #     "API_PRIVATE_KEY" => "riskiq_private_key",
      #     "API_SERVER" => "ws.riskiq.net",
      #     "API_VERSION" => "v1"
      #   }
      #
      #   PassiveDNS::Provider::RiskIQ.new(options)
      #
      def initialize(options={})
        @debug = options[:debug] || false
        @token = options["API_TOKEN"] || raise("#{self.class.name} requires an API_TOKEN")
        @privkey = options["API_PRIVATE_KEY"] || raise("#{self.class.name} requires an API_PRIVATE_KEY")
        @server = options["API_SERVER"] || "ws.riskiq.net"
        @version = options["API_VERSION"] || "v1"
        @url = "https://#{@server}/#{@version}"
      end

      # Takes a label (either a domain or an IP address) and returns
      # an array of PassiveDNS::PDNSResult instances with the answers to the query
      def lookup(label, limit=nil)
        $stderr.puts "DEBUG: #{self.class.name}.lookup(#{label})" if @debug
        Timeout::timeout(240) {
          url = nil
          params = {"rrType" => "", "maxResults" => limit || 1000}
        
          if label =~ /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/
            url = @url+"/dns/data"
            params["ip"] = label 
          else
            url = @url+"/dns/name"
            params["name"] = label
          end
          url << "?"
          params.each do |k,v|
            url << "#{k}=#{v}&"
          end
          url.gsub!(/\&$/,"")
        
          $stderr.puts "DEBUG: #{self.class.name} url = #{url}" if @debug
          url = URI.parse url
          http = Net::HTTP.new(url.host, url.port)
          http.use_ssl = (url.scheme == 'https')
          http.verify_mode = OpenSSL::SSL::VERIFY_NONE
          http.verify_depth = 5
          request = Net::HTTP::Get.new(url.request_uri)
          request.add_field("User-Agent", "Ruby/#{RUBY_VERSION} passivedns-client rubygem v#{PassiveDNS::Client::VERSION}")
          request.add_field('Accept', 'Application/JSON')
          request.add_field('Content-Type', 'Application/JSON')
          request.basic_auth(@token, @privkey)
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
    
      # parses the response of riskiq's JSON reply to generate an array of PDNSResult
      def parse_json(page,query,response_time=0)
         res = []
        data = JSON.parse(page)
        if data['records']
          data['records'].each do |record|
            name = record['name'].gsub!(/\.$/,'')
            type = record['rrtype']
            last_seen = Time.parse(record['lastSeen'])
            first_seen = Time.parse(record['firstSeen'])
            count = record['count']
            record['data'].each do |datum|
              datum.gsub!(/\.$/,'')
              res << PDNSResult.new(self.class.name,response_time,
                name, datum, type, 0, first_seen, last_seen, count)
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
