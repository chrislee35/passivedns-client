unless Kernel.respond_to?(:require_relative)
	module Kernel
		def require_relative(path)
			require File.join(File.dirname(caller[0]), path.to_str)
		end
	end
end

require_relative 'helper'
require 'configparser'

class TestPassiveDnsQuery < Test::Unit::TestCase
  
  def setup
    configfile="#{ENV['HOME']}/.passivedns-client"
    @cp = ConfigParser.new(configfile)
    @class_map = {}
    PassiveDNS.constants.each do |const|
      if PassiveDNS.const_get(const).is_a?(Class) and PassiveDNS.const_get(const).superclass == PassiveDNS::PassiveDB
        @class_map[PassiveDNS.const_get(const).config_section_name] = PassiveDNS.const_get(const)
      end
    end
  end
    
	def test_instantiate_Nonexisting_Client
		assert_raise RuntimeError do
			PassiveDNS::Client.new(['doesnotexist'])
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
	
	def test_BFK
		assert_nothing_raised do
			PassiveDNS::Client.new(['bfk'])
		end
    d = PassiveDNS::BFK.new(@cp['bfk'] || {})
    assert_not_nil(d)
		rows = d.lookup("example.org",3)
		assert_not_nil(rows)
		assert_not_nil(rows.to_s)
		assert_not_nil(rows.to_xml)
		assert_not_nil(rows.to_json)
		assert_not_nil(rows.to_yaml)
    assert_equal(3, rows.length)
    rows = d.lookup("8.8.8.8")
    assert_not_nil(rows)
    assert_not_nil(rows.to_s)
    assert_not_nil(rows.to_xml)
    assert_not_nil(rows.to_json)
    assert_not_nil(rows.to_yaml)
	end
	
	def test_CERTEE
    assert(false, "CERTEE is still offline")
		assert_nothing_raised do
			PassiveDNS::Client.new(['certee'])
		end
    d = PassiveDNS::CERTEE.new(@cp['certee'] || {})
    assert_not_nil(d)
		rows = d.lookup("sim.cert.ee",3)
		assert_not_nil(rows)
		assert_not_nil(rows.to_s)
		assert_not_nil(rows.to_xml)
		assert_not_nil(rows.to_json)
		assert_not_nil(rows.to_yaml)
    assert_equal(3, rows.length)
    rows = d.lookup("8.8.8.8")
    assert_not_nil(rows)
    assert_not_nil(rows.to_s)
    assert_not_nil(rows.to_xml)
    assert_not_nil(rows.to_json)
    assert_not_nil(rows.to_yaml)
	end

	def test_DNSDB
		assert_nothing_raised do
			PassiveDNS::Client.new(['dnsdb'])
		end
    d = PassiveDNS::DNSDB.new(@cp['dnsdb'] || {})
    assert_not_nil(d)
		rows = d.lookup("example.org",3)
		assert_not_nil(rows)
		assert_not_nil(rows.to_s)
		assert_not_nil(rows.to_xml)
		assert_not_nil(rows.to_json)
		assert_not_nil(rows.to_yaml)
    assert_equal(3, rows.length) # this will fail since DNSDB has an off by one error
    rows = d.lookup("8.8.8.8")
    assert_not_nil(rows)
    assert_not_nil(rows.to_s)
    assert_not_nil(rows.to_xml)
    assert_not_nil(rows.to_json)
    assert_not_nil(rows.to_yaml)
	end

	def test_VirusTotal
		assert_nothing_raised do
			PassiveDNS::Client.new(['virustotal'])
		end
    d = PassiveDNS::VirusTotal.new(@cp['virustotal'] || {})
    assert_not_nil(d)
		rows = d.lookup("google.com",3)
		assert_not_nil(rows)
		assert_not_nil(rows.to_s)
		assert_not_nil(rows.to_xml)
		assert_not_nil(rows.to_json)
		assert_not_nil(rows.to_yaml)
    assert_equal(3, rows.length)
    rows = d.lookup("8.8.8.8")
    assert_not_nil(rows)
    assert_not_nil(rows.to_s)
    assert_not_nil(rows.to_xml)
    assert_not_nil(rows.to_json)
    assert_not_nil(rows.to_yaml)
	end
  
  def test_TCPIPUtils
    assert_nothing_raised do
      PassiveDNS::Client.new(['tcpiputils'])
    end
    d = PassiveDNS::TCPIPUtils.new(@cp['tcpiputils'] || {})
    assert_not_nil(d)
    rows = d.lookup("example.org")
    assert_not_nil(rows)
    assert_not_nil(rows.to_s)
    assert_not_nil(rows.to_xml)
    assert_not_nil(rows.to_json)
    assert_not_nil(rows.to_yaml)
    rows = d.lookup("example.org",3)
    assert_not_nil(rows)
    assert_not_nil(rows.to_s)
    assert_not_nil(rows.to_xml)
    assert_not_nil(rows.to_json)
    assert_not_nil(rows.to_yaml)
    assert_equal(3, rows.length)
    rows = d.lookup("8.8.8.8")
    assert_not_nil(rows)
    assert_not_nil(rows.to_s)
    assert_not_nil(rows.to_xml)
    assert_not_nil(rows.to_json)
    assert_not_nil(rows.to_yaml)
  end

  def test_cn360
    assert_nothing_raised do
      PassiveDNS::Client.new(['cn360'])
    end
    d = PassiveDNS::CN360.new(@cp['cn360'] || {})
    assert_not_nil(d)
    rows = d.lookup("example.org")
    assert_not_nil(rows)
    assert_not_nil(rows.to_s)
    assert_not_nil(rows.to_xml)
    assert_not_nil(rows.to_json)
    assert_not_nil(rows.to_yaml)
    rows = d.lookup("example.org",3)
    assert_not_nil(rows)
    assert_not_nil(rows.to_s)
    assert_not_nil(rows.to_xml)
    assert_not_nil(rows.to_json)
    assert_not_nil(rows.to_yaml)
    assert_equal(3, rows.length)
    rows = d.lookup("8.8.8.8")
    assert_not_nil(rows)
    assert_not_nil(rows.to_s)
    assert_not_nil(rows.to_xml)
    assert_not_nil(rows.to_json)
    assert_not_nil(rows.to_yaml)
	end
  
  def test_nmemonic
		assert_nothing_raised do
			PassiveDNS::Client.new(['mnemonic'])
		end
    d = PassiveDNS::Mnemonic.new(@cp['mnemonic'] || {})
    assert_not_nil(d)
		rows = d.lookup("example.org")
		assert_not_nil(rows)
		assert_not_nil(rows.to_s)
		assert_not_nil(rows.to_xml)
		assert_not_nil(rows.to_json)
		assert_not_nil(rows.to_yaml)
		rows = d.lookup("example.org",3)
		assert_not_nil(rows)
		assert_not_nil(rows.to_s)
		assert_not_nil(rows.to_xml)
		assert_not_nil(rows.to_json)
		assert_not_nil(rows.to_yaml)
		assert_equal(3, rows.length)
		rows = d.lookup("8.8.8.8")
		assert_not_nil(rows)
		assert_not_nil(rows.to_s)
		assert_not_nil(rows.to_xml)
		assert_not_nil(rows.to_json)
		assert_not_nil(rows.to_yaml)
	end
end
