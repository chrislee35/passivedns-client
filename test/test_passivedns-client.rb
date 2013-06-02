unless Kernel.respond_to?(:require_relative)
	module Kernel
		def require_relative(path)
			require File.join(File.dirname(caller[0]), path.to_str)
		end
	end
end

require_relative 'helper'

class TestPassiveDnsQuery < Test::Unit::TestCase
	def test_instantiate_Nonexisting_Client
		assert_raise RuntimeError do
			PassiveDNS::Client.new(['doesnotexist'])
		end
	end

	def test_instantiate_BFK_Client
		assert_not_nil(PassiveDNS::BFK.new)
		assert_nothing_raised do
			PassiveDNS::Client.new(['bfk'])
		end
	end

	def test_instantiate_CERTEE_Client
		assert_not_nil(PassiveDNS::CERTEE.new)
		assert_nothing_raised do
			PassiveDNS::Client.new(['certee'])
		end
	end
	
	def test_instantiate_DNSParse_Client
		assert_not_nil(PassiveDNS::DNSParse.new)
		assert_nothing_raised do
			PassiveDNS::Client.new(['dnsparse'])
		end
	end
	
	def test_instantiate_ISC_Client
		assert_not_nil(PassiveDNS::ISC.new)
		assert_nothing_raised do
			PassiveDNS::Client.new(['isc'])
		end
	end
	
	def test_instantiate_VirusTotal_Client
		assert_not_nil(PassiveDNS::VirusTotal.new)
		assert_nothing_raised do
			PassiveDNS::Client.new(['virustotal'])
		end
	end

	def test_instantiate_All_Clients
		assert_nothing_raised do
			PassiveDNS::Client.new()
		end
	end
	
	def test_instantiate_Passive_DNS_State
		assert_not_nil(PassiveDNS::PDNSToolState.new)
	end
	
	def test_instantiate_Passive_DNS_State_database
		if File.exists?("test/test.sqlite3")
			File.unlink("test/test.sqlite3")
		end
		assert_not_nil(PassiveDNS::PDNSToolStateDB.new("test/test.sqlite3"))
		if File.exists?("test/test.sqlite3")
			File.unlink("test/test.sqlite3")
		end
	end
	
	def test_query_BFK
		rows = PassiveDNS::BFK.new.lookup("example.org")
		assert_not_nil(rows)
		assert_not_nil(rows.to_s)
		assert_not_nil(rows.to_xml)
		assert_not_nil(rows.to_json)
		assert_not_nil(rows.to_yaml)
	end
	
	def test_query_CERTEE
		rows = PassiveDNS::CERTEE.new.lookup("sim.cert.ee")
		assert_not_nil(rows)
		assert_not_nil(rows.to_s)
		assert_not_nil(rows.to_xml)
		assert_not_nil(rows.to_json)
		assert_not_nil(rows.to_yaml)
	end

	def test_query_DNSParse
		rows = PassiveDNS::DNSParse.new.lookup("example.org")
		assert_not_nil(rows)
		assert_not_nil(rows.to_s)
		assert_not_nil(rows.to_xml)
		assert_not_nil(rows.to_json)
		assert_not_nil(rows.to_yaml)
	end

	def test_query_ISC
		rows = PassiveDNS::ISC.new.lookup("example.org")
		assert_not_nil(rows)
		assert_not_nil(rows.to_s)
		assert_not_nil(rows.to_xml)
		assert_not_nil(rows.to_json)
		assert_not_nil(rows.to_yaml)
	end

	def test_query_VirusTotal
		rows = PassiveDNS::VirusTotal.new.lookup("sim.cert.ee")
		assert_not_nil(rows)
		assert_not_nil(rows.to_s)
		assert_not_nil(rows.to_xml)
		assert_not_nil(rows.to_json)
		assert_not_nil(rows.to_yaml)
	end

end
