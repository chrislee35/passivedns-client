# frozen_string_literal: true

# DESCRIPTION: this is a module for Open Source Context's PassiveDNS archive.
require 'json'
require 'net/http'
require 'openssl'
require 'time'
require 'timeout'
require 'uri'

module PassiveDNS # :nodoc: don't document this
  # The Provider module contains all the Passive DNS provider client code
  module Provider
    # Queries OSContext's passive DNS database
    class OSC < PassiveDB
      # Sets the modules self-reported name to "OSC"
      def self.name
        'OSC'
      end

      # Sets the configuration section name to "osc"
      def self.config_section_name
        'osc'
      end

      # Sets the command line database argument to "d"
      def self.option_letter
        'o'
      end

      # :debug enables verbose logging to standard output
      attr_accessor :debug

      # === Options
      # * :debug       Sets the debug flag for the module
      # * "APIKEY"     REQUIRED: The API key associated with OSC
      # * "URL"      Alternate url for testing.  Defaults to "https://api.oscontext.com/api/v2/domainsquery"
      #
      # === Example Instantiation
      #
      #   options = {
      #     :debug => true,
      #     "APIKEY" => "0123456789abcdef0123456789abcdef01234567",
      #     "URL" => "https://api.oscontext.com/api/v2/domainsquery"
      #   }
      #
      #   PassiveDNS::Provider::OSC.new(options)
      #
      def initialize(config = {})
        super()
        @debug = config[:debug] || false
        @timeout = config[:timeout] || 20
        @token = config['APIKEY'] || raise("APIKEY option required for #{self.class}")
        @url = config['URL'] || 'https://api.oscontext.com/api/v2/domainsquery'
      end

      # Takes a label (either a domain or an IP address) and returns
      # an array of PassiveDNS::PDNSResult instances with the answers to the query
      def lookup(label, _limit = nil)
        warn "DEBUG: #{self.class.name}.lookup(#{label})" if @debug
        Timeout.timeout @timeout do
          url = if %r{^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(/\d{1,2})?$}.match? label
                  @url + "?q=value_ip:#{label}&size=250&token=#{@token}"
                else
                  @url + "?q=qname%3A#{label}&size=250&token=#{@token}"
                end

          url = URI.parse url

          warn "--DEBUG: #{self.class.name} url = #{url}" if @debug

          http = Net::HTTP.new url.host, url.port
          http.use_ssl = (url.scheme == 'https')
          http.verify_depth = 5

          request = Net::HTTP::Get.new url
          request.add_field 'content-type', 'application/x-www-form-urlencoded'
          request.add_field 'referer', 'clitool'
          t1 = Time.now
          response = http.request request
          if response.code.to_i == 404
            warn 'DEBUG: empty response from server' if @debug
            return
          end
          check_response response
          t2 = Time.now
          # $stderr.puts response.body if @debug
          parse_json response.body, t2 - t1
        end
      rescue Timeout::Error
        warn "#{self.class.name} lookup timed out: #{label}"
      end

      private

      # parses the response of OSC's JSON reply to generate an array of PDNSResult
      def parse_json(page, response_time)
        res = []
        raise 'Error: unable to parse request' if page.include? 'Error: unable to parse request'

        data = JSON.parse page
        data['results']&.each do |row|
          if row['qtype'].to_i == 1
            firstseen = Time.parse row['date']
            lastseen = (Time.parse row['last_seen'] if row['last_seen'])
            res << PDNSResult.new(
              self.class.name,
              response_time,
              row['domain'],
              row['value'],
              'A',
              nil,
              firstseen,
              lastseen,
              nil,
              'amber'
            )
          elsif row['type'] == 'soa_email'
            firstseen = Time.parse row['date']

            lastseen = (Time.parse row['last_seen'] if row['last_seen'])

            res << PDNSResult.new(
              self.class.name,
              response_time,
              row['domain'],
              row['value'],
              'SOA',
              nil,
              firstseen,
              lastseen,
              nil,
              'amber'
            )

          end
        end

        res
      rescue StandardError => e
        warn "#{self.class.name} Exception: #{e}"
        #        $stderr.puts page
        raise e
      end
    end
  end
end
