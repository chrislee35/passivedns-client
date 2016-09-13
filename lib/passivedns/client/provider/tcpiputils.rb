require 'net/http'
require 'net/https'
require 'openssl'
require 'json'

# Please read http://www.tcpiputils.com/terms-of-service under automated requests

module PassiveDNS #:nodoc: don't document this
  # The Provider module contains all the Passive DNS provider client code
  module Provider
    # Queries TCPIPUtils's passive DNS database
    class TCPIPUtils < PassiveDB
      # Sets the modules self-reported name to "TCPIPUtils"
      def self.name
        "TCPIPUtils"
      end
      # Sets the configuration section name to "tcpiputils"
      def self.config_section_name
        "tcpiputils"
      end
      # Sets the command line database argument to "t"
      def self.option_letter
        "t"
      end

      # :debug enables verbose logging to standard output
      attr_accessor :debug
      # === Options
      # * :debug       Sets the debug flag for the module
      # * "APIKEY"     REQUIRED: The API key associated with TCPIPUtils
      # * "URL"      Alternate url for testing.  Defaults to  "https://www.utlsapi.com/api.php?version=1.0&apikey="
      #
      # === Example Instantiation
      #
      #   options = {
      #     :debug => true,
      #     "APIKEY" => "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
      #     "URL" =>  "https://www.utlsapi.com/api.php?version=1.0&apikey="
      #   }
      #
      #   PassiveDNS::Provider::TCPIPUtils.new(options)
      #
      def initialize(options={})
        @debug = options[:debug] || false
        @apikey = options["APIKEY"] || raise("#{self.class.name} requires an APIKEY.  See README.md")
        @url = options["URL"] || "https://www.utlsapi.com/api.php?version=1.0&apikey="
      end
    
      # Takes a label (either a domain or an IP address) and returns
      # an array of PassiveDNS::PDNSResult instances with the answers to the query
      def lookup(label, limit=nil)
        $stderr.puts "DEBUG: #{self.class.name}.lookup(#{label})" if @debug
        type = (label.match(/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/)) ? "domainneighbors" : "domainipdnshistory"
        url = "#{@url}#{@apikey}&type=#{type}&q=#{label}"
        recs = []
        Timeout::timeout(240) {
          url = URI.parse url
          http = Net::HTTP.new(url.host, url.port)
          http.use_ssl = (url.scheme == 'https')
          http.verify_mode = OpenSSL::SSL::VERIFY_NONE
          http.verify_depth = 5
          request = Net::HTTP::Get.new(url.path+"?"+url.query)
          request.add_field("User-Agent", "Ruby/#{RUBY_VERSION} passivedns-client rubygem v#{PassiveDNS::Client::VERSION}")
          t1 = Time.now
          response = http.request(request)
          delta = (Time.now - t1).to_f
          reply = JSON.parse(response.body)
          if reply["status"] and reply["status"] == "succeed"
            question = reply["data"]["question"]
            recs = format_recs(reply["data"], question, delta)
          elsif reply["status"] and reply["status"] == "error"
            raise "#{self.class.name}: error from web API: #{reply["data"]}"
          end
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
    
      # translates the data structure derived from of tcpiputils's JSON reply
      def format_recs(reply_data, question, delta)
        recs = []
        fieldname = nil
        rrtype = nil
        add_records = false
        reply_data.each do |key, data|
          case key
          when "ipv4"
            fieldname = "ip"
            rrtype = "A"
            add_records = true
          when "ipv6"
            fieldname = "ip"
            rrtype = "AAAA"
            add_records = true
          when "dns"
            fieldname = "dns"
            rrtype = "NS"
            add_records = true
          when "mx"
            fieldname = "dns"
            rrtype = "MX"
            add_records = true
          when "domains"
            data.each do |rec|
              lastseen = (rec["updatedate"]) ? Date.parse(rec["updatedate"]) : nil
              recs << PDNSResult.new(self.class.name, delta, rec, question, "A", nil, nil, nil, nil)
            end
          end
          if add_records
            data.each do |rec|
              lastseen = (rec["updatedate"]) ? Date.parse(rec["updatedate"]) : nil
              recs << PDNSResult.new(self.class.name, delta, question, rec[fieldname], rrtype, nil, nil, lastseen, nil)
            end
          end
        end
        recs
      end

    end
  end
end
