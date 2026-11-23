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
      # * "URL"      Alternate url for testing.  Defaults to https://www.virustotal.com/vtapi/v2/
      #
      # === Example Instantiation
      #
      #   options = {
      #     :debug => true,
      #     "APIKEY" => "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
      #     "URL" => "https://www.virustotal.com/vtapi/v2/"
      #   }
      #
      #   PassiveDNS::Provider::VirusTotal.new(options)
      #
      def initialize(config = {})
        super()
        @debug = config[:debug] || false
        @timeout = config[:timeout] || 20
        @apikey = config['APIKEY'] || raise("#{self.class.name} requires an APIKEY.  See README.md")
        @url = config['URL'] || 'https://www.virustotal.com/vtapi/v2/'
      end

      # Takes a label (either a domain or an IP address) and returns
      # an array of PassiveDNS::PDNSResult instances with the answers to the query
      def lookup(label, limit = nil)
        warn "DEBUG: #{self.class.name}.lookup(#{label})" if @debug
        Timeout.timeout @timeout do
          url = if /^[\d.]+$/.match?(label)
                  "#{@url}ip-address/report?ip=#{label}&apikey=#{@apikey}"
                else
                  "#{@url}domain/report?domain=#{label}&apikey=#{@apikey}"
                end
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
          request = Net::HTTP::Get.new "#{url.path}?#{url.query}"
          request.add_field 'User-Agent', "Ruby/#{RUBY_VERSION} passivedns-client rubygem v#{PassiveDNS::Client::VERSION}"
          t1 = Time.now
          response = http.request request
          if response.code.to_i == 204
            warn 'DEBUG: empty response from server' if @debug
            return
          end
          t2 = Time.now
          recs = parse_json response.body, label, t2 - t1
          if limit
            recs[0, limit]
          else
            recs
          end
        end
      rescue Timeout::Error
        warn "#{self.class.name} lookup timed out: #{label}"
      end

      private

      # parses the response of virustotal's JSON reply to generate an array of PDNSResult
      def parse_json(page, query, response_time = 0)
        res = []
        return res unless page

        data = JSON.parse page
        data['resolutions']&.each do |row|
          lastseen = Time.parse "#{row['last_resolved']} +0000"
          if row['ip_address']
            res << PDNSResult.new(self.class.name, response_time, query, row['ip_address'], 'A', nil, nil, lastseen, nil, 'yellow')
          elsif row['hostname']
            res << PDNSResult.new(self.class.name, response_time, row['hostname'], query, 'A', nil, nil, lastseen, nil, 'yellow')
          end
        end
        warn "DEBUG: server returned error: #{data['verbose_msg']}" if data['response_code'].zero? && @debug
        res
      rescue StandardError => e
        warn "VirusTotal Exception: #{e}"
        raise e
      end
    end
  end
end
