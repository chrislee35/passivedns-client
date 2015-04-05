require 'open-uri'

module PassiveDNS #:nodoc: don't document this
  # The Provider module contains all the Passive DNS provider client code
  module Provider

    # Queries BFK.de's passive DNS database
  	class BFK < PassiveDB
      # Sets the modules self-reported name to "BFK.de"
      def self.name
        "BFK.de"
      end
      # Sets the configuration section name to "bfk"
      def self.config_section_name
        "bfk"
      end
      # Sets the command line database argument to "b"
      def self.option_letter
        "b"
      end
    
      # :debug enables verbose logging to standard output
      attr_accessor :debug
      # === Options
      # * :debug     Sets the debug flag for the module
      # * "URL"      Alternate url for testing.  Defaults to "http://www.bfk.de/bfk_dnslogger.html?query="
      #
      # === Example Instantiation
      #
      #   options = {
      #     :debug => true,
      #     "URL" => "http://www.bfk.de/bfk_dnslogger.html?query="
      #   }
      #
      #   PassiveDNS::Provider::BFK.new(options)
      #
      
  		def initialize(options={})
  			@debug = options[:debug] || false
        @base = options["URL"] || "http://www.bfk.de/bfk_dnslogger.html?query="
  		end
    
      # Takes a label (either a domain or an IP address) and returns
      # an array of PassiveDNS::PDNSResult instances with the answers to the query
   		def lookup(label, limit=nil)	
  			$stderr.puts "DEBUG: #{self.class.name}.lookup(#{label})" if @debug
  			Timeout::timeout(240) {
  				t1 = Time.now
  				open(
  					@base+label,
  					"User-Agent" => "Ruby/#{RUBY_VERSION} passivedns-client rubygem v#{PassiveDNS::Client::VERSION}"
  				) do |f|
  					t2 = Time.now
  					recs = parse(f.read,t2-t1)
            if limit
              recs[0,limit]
            else
              recs
            end
  				end
  			}
  		rescue Timeout::Error => e
  			$stderr.puts "#{self.class.name} lookup timed out: #{label}"      
  		end
    
      private
    
      # parses the webpage returned by BFK to generate an array of PDNSResult
  		def parse(page,response_time)
  			line = page.unpack('C*').pack('U*').split(/<table/).grep(/ id=\"logger\"/)
  			return [] unless line.length > 0
  			line = line[0].gsub(/[\t\n]/,'').gsub(/<\/table.*/,'')
  			rows = line.split(/<tr.*?>/)
  			res = []
  			rows.collect do |row|
  				r = row.split(/<td>/).map{|x| x.gsub(/<.*?>/,'').gsub(/\&.*?;/,'')}[1,1000]
  				if r and r[0] =~ /\w/
  					# BFK includes the MX weight in the answer response. First, find the MX records, then dump the weight to present a consistent record name to the collecting array. Otherwise the other repositories will present the same answer and your results will become cluttered with duplicates.
  					if r[1] == "MX" then
  						# MX lines look like "5 mx.domain.tld", so split on the space and assign r[2] (:answer) to the latter part.
  						#s = r[2].split(/\w/).map{|x| x}[1,1000]
  						#	r[2] = s[1]
  						r[2] =~ /[0-9]+?\s(.+)/
  						s=$1
  						puts "DEBUG: == BFK: MX Parsing Strip: Answer: " + r[2] + " : mod: " + s if @debug
  						r[2] = s
						
  							######### FIX BLANKS FOR MX
						
  					end
  					res << PDNSResult.new(self.class.name,response_time,r[0],r[2],r[1])
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