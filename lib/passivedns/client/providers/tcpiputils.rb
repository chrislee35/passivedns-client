require 'net/http'
require 'net/https'
require 'openssl'
require 'json'

# Please read http://www.tcpiputils.com/terms-of-service under automated requests

module PassiveDNS
  class TCPIPUtils < PassiveDB
    # override
    def self.name
      "TCPIPUtils"
    end
    #override
    def self.config_section_name
      "tcpiputils"
    end
    #override
    def self.option_letter
      "t"
    end

    attr_accessor :debug
    def initialize(options={})
      @debug = options[:debug] || false
      @apikey = options["APIKEY"] || raise("#{self.class.name} requires an APIKEY.  See README.md")
      @url = options["URL"] || "https://www.utlsapi.com/api.php?version=1.0&apikey="
    end
    
    def format_recs(reply_data, question, delta)
      recs = []
      reply_data.each do |key, data|
        case key
        when "ipv4"
          data.each do |rec|
            recs << PDNSResult.new(self.class.name, delta, question, rec["ip"], "A", nil, nil, rec["updatedate"], nil)
          end
        when "ipv6"
          data.each do |rec|
            recs << PDNSResult.new(self.class.name, delta, question, rec["ip"], "AAAA", nil, nil, rec["updatedate"], nil)
          end
        when "dns"
          data.each do |rec|
            recs << PDNSResult.new(self.class.name, delta, question, rec["dns"], "NS", nil, nil, rec["updatedate"], nil)
          end
        when "mx"
          data.each do |rec|
            recs << PDNSResult.new(self.class.name, delta, question, rec["dns"], "MX", nil, nil, rec["updatedate"], nil)
          end
        when "domains"
          data.each do |rec|
            recs << PDNSResult.new(self.class.name, delta, rec, question, "A", nil, nil, nil, nil)
          end
        end
      end
      recs
    end

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
  end
end