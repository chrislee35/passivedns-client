# frozen_string_literal: true

# DESCRIPTION: this is a module for pdns.rb, primarily used by pdnstool.rb, to query VirusTotal's passive DNS database
require 'json'
require 'net/http'
require 'openssl'
require 'time'
require 'timeout'
require 'uri'

module PassiveDNS # :nodoc: don't document this
  # The Provider module contains all the Passive DNS provider client code
  module Provider
    # Queries VirusTotal's passive DNS database
    class VirusTotal < PassiveDB
      # Sets the modules self-reported name to "VirusTotal"
      def self.name
        'VirusTotal'
      end

      # Sets the configuration section name to "virustotal"
      def self.config_section_name
        'virustotal'
      end

      # Sets the command line database argument to "v"
      def self.option_letter
        'v'
      end

      # :debug enables verbose logging to standard output
      attr_accessor :debug

      # === Options
      # * :debug     Sets the debug flag for the module
      # * "APIKEY"   Mandatory.  API Key associated with your VirusTotal account
      # * "URL"      Alternate url for testing.  Defaults to https://www.virustotal.com/api/v3/
      #
      # === Example Instantiation
      #
      #   options = {
      #     :debug => true,
      #     "APIKEY" => "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
      #     "URL" => "https://www.virustotal.com/api/v3/"
      #   }
      #
      #   PassiveDNS::Provider::VirusTotal.new(options)
      #
      def initialize(config = {})
        super()
        @debug = config[:debug] || false
        @timeout = config[:timeout] || 20
        @apikey = config['APIKEY'] || raise("#{self.class.name} requires an APIKEY.  See README.md")
        @url = config['URL'] || 'https://www.virustotal.com/api/v3/'
        @url += '/' unless @url.end_with? '/'
      end

      # the most resolutions that VirusTotal returns in one response
      MAX_LIMIT = 40

      # Takes a label (either a domain or an IP address) and returns
      # an array of PassiveDNS::PDNSResult instances with the answers to the query.
      # VirusTotal returns at most MAX_LIMIT resolutions per query.
      def lookup(label, limit = nil)
        warn "DEBUG: #{self.class.name}.lookup(#{label})" if @debug
        Timeout.timeout @timeout do
          kind = /^[\d.]+$|:/.match?(label) ? 'ip_addresses' : 'domains'
          count = [limit || MAX_LIMIT, MAX_LIMIT].min
          url = "#{@url}#{kind}/#{URI.encode_uri_component label}/resolutions?limit=#{count}"
          warn "DEBUG: #{self.class.name} url = #{url}" if @debug
          begin
            url = URI.parse url
          rescue URI::InvalidURIError
            warn "ERROR: Invalid address: #{url}"
            return
          end
          http = Net::HTTP.new url.host, url.port
          http.use_ssl = (url.scheme == 'https')
          http.verify_depth = 5
          request = Net::HTTP::Get.new url.request_uri
          request.add_field 'User-Agent', "Ruby/#{RUBY_VERSION} passivedns-client rubygem v#{PassiveDNS::Client::VERSION}"
          request.add_field 'Accept', 'application/json'
          request.add_field 'x-apikey', @apikey
          t1 = Time.now
          response = http.request request
          t2 = Time.now
          if response.code.to_i == 404
            warn 'DEBUG: empty response from server' if @debug
            return
          end
          recs = parse_json response.body, label, t2 - t1
          limit ? recs[0, limit] : recs
        end
      rescue Timeout::Error
        warn "#{self.class.name} lookup timed out: #{label}"
      end

      private

      # parses the response of virustotal's v3 JSON reply to generate an array of PDNSResult
      def parse_json(page, query, response_time = 0)
        res = []
        return res unless page

        data = JSON.parse page
        raise "#{self.class.name} Error: #{data['error']['message']}" if data['error']

        data['data']&.each do |row|
          attributes = row['attributes'] || {}
          lastseen = Time.at attributes['date'].to_i
          if attributes['ip_address']
            res << PDNSResult.new(self.class.name, response_time, query, attributes['ip_address'], 'A', nil, nil, lastseen, nil, 'yellow')
          elsif attributes['host_name']
            res << PDNSResult.new(self.class.name, response_time, attributes['host_name'], query, 'A', nil, nil, lastseen, nil, 'yellow')
          end
        end
        res
      rescue StandardError => e
        warn "VirusTotal Exception: #{e}"
        raise e
      end
    end
  end
end
