unless Kernel.respond_to?(:require_relative)
  module Kernel
    def require_relative(path)
      require File.join(File.dirname(caller[0]), path.to_str)
    end
  end
end

require_relative 'helper'
require 'configparser'

class TestPassiveDnsQuery < Minitest::Test
  
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
    assert_raises RuntimeError do
      PassiveDNS::Client.new(['doesnotexist'])
    end
  end

  def test_instantiate_All_Clients
    PassiveDNS::Client.new()
  end
  
  def test_instantiate_Passive_DNS_State
    refute_nil(PassiveDNS::PDNSToolState.new)
  end
  
  def test_instantiate_Passive_DNS_State_database
    if File.exist?("test/test.sqlite3")
      File.unlink("test/test.sqlite3")
    end
    refute_nil(PassiveDNS::PDNSToolStateDB.new("test/test.sqlite3"))
    if File.exist?("test/test.sqlite3")
      File.unlink("test/test.sqlite3")
    end
  end
  
  def test_DNSDB
    PassiveDNS::Client.new(['dnsdb'])
    d = PassiveDNS::Provider::DNSDB.new(@cp['dnsdb'] || {})
    refute_nil(d)
    rows = d.lookup("example.org",3)
    refute_nil(rows)
    refute_nil(rows.to_s)
    refute_nil(rows.to_xml)
    refute_nil(rows.to_json)
    refute_nil(rows.to_yaml)
    assert_equal(3, rows.length) # this will fail since DNSDB has an off by one error
    rows = d.lookup("8.8.8.8")
    refute_nil(rows)
    refute_nil(rows.to_s)
    refute_nil(rows.to_xml)
    refute_nil(rows.to_json)
    refute_nil(rows.to_yaml)
  end

  def test_VirusTotal
    PassiveDNS::Client.new(['virustotal'])
    d = PassiveDNS::Provider::VirusTotal.new(@cp['virustotal'] || {})
    refute_nil(d)
    rows = d.lookup("google.com",3)
    refute_nil(rows)
    refute_nil(rows.to_s)
    refute_nil(rows.to_xml)
    refute_nil(rows.to_json)
    refute_nil(rows.to_yaml)
    assert_equal(3, rows.length)
    rows = d.lookup("8.8.8.8")
    refute_nil(rows)
    refute_nil(rows.to_s)
    refute_nil(rows.to_xml)
    refute_nil(rows.to_json)
    refute_nil(rows.to_yaml)
  end
  
  def test_passivetotal
    PassiveDNS::Client.new(['passivetotal'])
    d = PassiveDNS::Provider::PassiveTotal.new(@cp['passivetotal'] || {})
    refute_nil(d)
    rows = d.lookup("example.org")
    refute_nil(rows)
    refute_nil(rows.to_s)
    refute_nil(rows.to_xml)
    refute_nil(rows.to_json)
    refute_nil(rows.to_yaml)
    rows = d.lookup("example.org", 3)
    refute_nil(rows)
    refute_nil(rows.to_s)
    refute_nil(rows.to_xml)
    refute_nil(rows.to_json)
    refute_nil(rows.to_yaml)
    puts(rows)
    assert_equal(3, rows.length)
    rows = d.lookup("8.8.8.8")
    refute_nil(rows)
    refute_nil(rows.to_s)
    refute_nil(rows.to_xml)
    refute_nil(rows.to_json)
    refute_nil(rows.to_yaml)
  end
    
  def test_circl
    PassiveDNS::Client.new(['circl'])
    d = PassiveDNS::Provider::CIRCL.new(@cp['circl'] || {})
    refute_nil(d)
    rows = d.lookup("example.org")
    refute_nil(rows)
    refute_nil(rows.to_s)
    refute_nil(rows.to_xml)
    refute_nil(rows.to_json)
    refute_nil(rows.to_yaml)
    rows = d.lookup("example.org",3)
    refute_nil(rows)
    refute_nil(rows.to_s)
    refute_nil(rows.to_xml)
    refute_nil(rows.to_json)
    refute_nil(rows.to_yaml)
    assert_equal(3, rows.length)
    rows = d.lookup("8.8.8.8")
    refute_nil(rows)
    refute_nil(rows.to_s)
    refute_nil(rows.to_xml)
    refute_nil(rows.to_json)
    refute_nil(rows.to_yaml)
  end
  
  def test_riskiq
    PassiveDNS::Client.new(['riskiq'])
    d = PassiveDNS::Provider::RiskIQ.new(@cp['riskiq'] || {})
    refute_nil(d)
    rows = d.lookup("example.org")
    refute_nil(rows)
    refute_nil(rows.to_s)
    refute_nil(rows.to_xml)
    refute_nil(rows.to_json)
    refute_nil(rows.to_yaml)
    rows = d.lookup("example.org",3)
    refute_nil(rows)
    refute_nil(rows.to_s)
    refute_nil(rows.to_xml)
    refute_nil(rows.to_json)
    refute_nil(rows.to_yaml)
    assert_equal(3, rows.length)
    rows = d.lookup("8.8.8.8")
    refute_nil(rows)
    refute_nil(rows.to_s)
    refute_nil(rows.to_xml)
    refute_nil(rows.to_json)
    refute_nil(rows.to_yaml)
  end
end
