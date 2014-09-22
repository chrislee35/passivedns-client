require 'net/http'
require 'net/https'
require 'openssl'
require 'json'

# Please read http://www.tcpiputils.com/terms-of-service under automated requests

module PassiveDNS
  class TCPIPUtils
    attr_accessor :debug
    def initialize(config="#{ENV['HOME']}/.tcpiputils")
      @debug = false
			if File.exist?(config)
				@apikey = File.open(config).read.split(/\n/)[0]
				$stderr.puts "DEBUG: TCPIPUtils#initialize(#{@apikey})" if @debug
			else
				raise "Error: Configuration file for TCPIPUtils is required for intialization
Format of configuration file (default: #{ENV['HOME']}/.tcpiputils) is the 64 hex character apikey on one line.
To obtain an API Key, go to http://www.tcpiputils.com/premium-access and purchase premium API access."
			end
    end
    
    def format_recs(reply_data, question, delta)
      recs = []
      reply_data.each do |key, data|
        case key
        when "ipv4"
          data.each do |rec|
            recs << PDNSResult.new("tcpiputils", delta, question, rec["ip"], "A", nil, nil, rec["updatedate"], nil)
          end
        when "ipv6"
          data.each do |rec|
            recs << PDNSResult.new("tcpiputils", delta, question, rec["ip"], "AAAA", nil, nil, rec["updatedate"], nil)
          end
        when "dns"
          data.each do |rec|
            recs << PDNSResult.new("tcpiputils", delta, question, rec["dns"], "NS", nil, nil, rec["updatedate"], nil)
          end
        when "mx"
          data.each do |rec|
            recs << PDNSResult.new("tcpiputils", delta, question, rec["dns"], "MX", nil, nil, rec["updatedate"], nil)
          end
        end
      end
      recs
    end

    def lookup(label, limit=nil)
      $stderr.puts "DEBUG: TCPIPUtils.lookup(#{label})" if @debug
      url = "https://www.utlsapi.com/api.php?version=1.0&apikey=#{@apikey}&type=domainipdnshistory&q=#{label}"
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
          raise "TCPIPUtils: error from web API: #{reply["data"]}"
        end
        if limit
          recs[0,limit]
        else
          recs
        end
			}
		rescue Timeout::Error => e
			$stderr.puts "TCPIPUtils lookup timed out: #{label}"
		end
  end
end