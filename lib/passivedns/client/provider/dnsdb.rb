# frozen_string_literal: true

# DESCRIPTION: this is a module for pdns.rb, primarily used by pdnstool.rb, to query the Farsight Security passive DNS database
# details on the API are at https://api.dnsdb.info/
# to request an API key, please email dnsdb-api at farsightsecurity dot com.
require 'json'
require 'net/http'
require 'openssl'
require 'time'
require 'timeout'
require 'uri'

module PassiveDNS # :nodoc: don't document this
  # The Provider module contains all the Passive DNS provider client code
  module Provider
    # Queries FarSight's passive DNS database
    class DNSDB < PassiveDB
      # Sets the modules self-reported name to "DNSDB"
      def self.name
        'DNSDB'
      end

      # Sets the configuration section name to "dnsdb"
      def self.config_section_name
        'dnsdb'
      end

      # Sets the command line database argument to "d"
      def self.option_letter
        'd'
      end

      # :debug enables verbose logging to standard output
      attr_accessor :debug

      # === Options
      # * :debug       Sets the debug flag for the module
      # * "APIKEY"     REQUIRED: The API key associated with DNSDB
      # * "URL"      Alternate url for testing.  Defaults to "https://api.dnsdb.info/lookup"
      #
      # === Example Instantiation
      #
      #   options = {
      #     :debug => true,
      #     "APIKEY" => "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
      #     "URL" => "https://api.dnsdb.info/lookup"
      #   }
      #
      #   PassiveDNS::Provider::DNSDB.new(options)
      #
      def initialize(config = {})
        super()
        @debug = config[:debug] || false
        @timeout = config[:timeout] || 20
        @key = config['APIKEY'] || raise("APIKEY option required for #{self.class}")
        @base = config['URL'] || 'https://api.dnsdb.info/lookup'
      end

      # Takes a label (either a domain or an IP address) and returns
      # an array of PassiveDNS::PDNSResult instances with the answers to the query
      def lookup(label, limit = nil)
        warn "DEBUG: #{self.class.name}.lookup(#{label})" if @debug
        Timeout.timeout @timeout do
          url = nil
          if %r{^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(/\d{1,2})?$}.match? label
            label = label.tr '/', ','
            url = "#{@base}/rdata/ip/#{label}"
          else
            url = "#{@base}/rrset/name/#{label}"
          end
          url = URI.parse url
          http = Net::HTTP.new url.host, url.port
          http.use_ssl = (url.scheme == 'https')
          http.verify_depth = 5
          path = url.path
          path = "#{path}?limit=#{limit}" if limit
          request = Net::HTTP::Get.new path
          request.add_field 'User-Agent', "Ruby/#{RUBY_VERSION} passivedns-client rubygem v#{PassiveDNS::Client::VERSION}"
          request.add_field 'X-API-Key', @key
          request.add_field 'Accept', 'application/json'
          t1 = Time.now
          response = http.request request
          if response.code.to_i == 404
            warn 'DEBUG: empty response from server' if @debug
            return
          end
          check_response response
          t2 = Time.now
          warn response.body if @debug
          parse_json response.body, t2 - t1
        end
      rescue Timeout::Error
        warn "#{self.class.name} lookup timed out: #{label}"
      end

      private

      # parses the response of DNSDB's JSON reply to generate an array of PDNSResult
      def parse_json(page, response_time)
        res = []
        raise 'Error: unable to parse request' if page.include? 'Error: unable to parse request'

        rows = page.split "\n"
        rows.each do |row|
          record = JSON.parse row
          answers = record['rdata']
          answers = [record['rdata']] if record['rdata'].instance_of? String
          query = record['rrname'].delete_suffix '.'
          rrtype = record['rrtype']
          firstseen = Time.at record['time_first'].to_i
          lastseen = Time.at record['time_last'].to_i
          count = record['count']

          answers.each do |answer|
            answer = answer.delete_suffix '.'
            res << if record['time_first']
                     PDNSResult.new(self.class.name, response_time, query, answer, rrtype,
                                    0, firstseen, lastseen, count, 'yellow')
                   else
                     PDNSResult.new self.class.name, response_time, query, answer, rrtype
                   end
          end
        end
        res
      rescue StandardError => e
        warn "#{self.class.name} Exception: #{e}"
        warn page
        raise e
      end
    end
  end
end
