require 'socket'

module PassiveDNS
	class CERTEE
		@@host = "sim.cert.ee"
		attr_accessor :debug
		def initialize
		end
		def lookup(label, limit=nil)
			$stderr.puts "DEBUG: CERTEE.lookup(#{label})" if @debug
			recs = []
			begin
				t1 = Time.now
				s = TCPSocket.new(@@host,43)
				s.puts(label)
				s.each_line do |l|
          if l =~ /Traceback \(most recent call last\):/
            # there is a bug in the CERTEE lookup tool
            raise "CERTEE is currently offline"
          end
					(lbl,ans,fs,ls) = l.chomp.split(/\t/)
					rrtype = 'A'
					if ans =~ /^\d+\.\d+\.\d+\.\d+$/
						rrtype = 'A'
					elsif ans =~ /^ns/
						rrtype = 'NS'
					else
						rrtype = 'CNAME'
					end
					t2 = Time.now
					recs << PDNSResult.new('CERTEE',t2-t1,lbl,ans,rrtype,0,Time.parse(fs).utc.strftime("%Y-%m-%dT%H:%M:%SZ"),Time.parse(ls).utc.strftime("%Y-%m-%dT%H:%M:%SZ"))
				end
			rescue SocketError => e
				$stderr.puts e
			end
			return nil unless recs.length > 0
      if limit
        recs = recs[0,limit]
      else
        recs
      end
		end
	end
end