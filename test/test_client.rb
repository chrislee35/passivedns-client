# frozen_string_literal: true

require_relative 'helper'

class TestClient < Minitest::Test
  CONFIG = <<~INI
    [dnsdb]
    APIKEY = dnsdbkey
    [virustotal]
    APIKEY = vtkey
    [passivetotal]
      USERNAME = tom@example.com
      APIKEY = ptkey
    [circl]
    USERNAME = circl_user
    PASSWORD = circl_pass
    [osc]
    APIKEY = osckey
  INI

  def with_config(text)
    Dir.mktmpdir do |dir|
      file = File.join dir, 'config'
      File.write file, text
      yield file
    end
  end

  def test_provider_names
    assert_equal %w[circl dnsdb osc passivetotal virustotal], PassiveDNS::Client.provider_names
  end

  def test_load_config
    with_config CONFIG do |file|
      config = PassiveDNS::Client.load_config file
      assert_equal 'dnsdbkey', config['dnsdb']['APIKEY']
      assert_equal 'tom@example.com', config['passivetotal']['USERNAME']
      assert_equal 'tom@example.com', config['passivetotal']['USERNAME']
      assert_equal %w[circl dnsdb osc passivetotal virustotal], config.keys.sort
    end
  end

  def test_load_config_missing_file
    _out, err = capture_io do
      assert_empty PassiveDNS::Client.load_config('/nonexistent/passivedns-client')
    end
    assert_match(/Could not find config file/, err)
  end

  def test_load_config_empty_file
    with_config '' do |file|
      assert_empty PassiveDNS::Client.load_config(file)
    end
  end

  def test_load_config_unparseable_file
    with_config "this is not an ini file\n" do |file|
      error = assert_raises(RuntimeError) { PassiveDNS::Client.load_config file }
      assert_includes error.message, file
    end
  end

  def test_instantiate_all_clients
    with_config CONFIG do |file|
      refute_nil PassiveDNS::Client.new(PassiveDNS::Client.provider_names, file)
    end
  end

  def test_instantiate_unknown_provider
    with_config CONFIG do |file|
      error = assert_raises(RuntimeError) { PassiveDNS::Client.new ['doesnotexist'], file }
      assert_match(/Unknown Passive DNS provider/, error.message)
    end
  end

  def test_provider_without_credentials
    _out, _err = capture_io do
      assert_raises(RuntimeError) { PassiveDNS::Client.new ['dnsdb'], '/nonexistent/passivedns-client' }
    end
  end

  def test_debug_and_timeout_setters
    with_config CONFIG do |file|
      client = PassiveDNS::Client.new %w[dnsdb osc], file
      client.debug = true
      client.timeout = 5
      providers = client.instance_variable_get :@pdnsdbs
      assert(providers.all?(&:debug))
      assert(providers.all? { |provider| provider.timeout == 5 })
    end
  end

  def test_query_through_client
    server = FakeServer.new <<~JSON
      {"rrname":"example.org.","rrtype":"A","rdata":"93.184.216.34","time_first":1000000,"time_last":2000000,"count":7}
      {"rrname":"example.org.","rrtype":"TXT","rdata":["v=spf1 -all"],"time_first":1000000,"time_last":2000000,"count":2}
    JSON
    config = "[dnsdb]\nAPIKEY = k\nURL = #{server.url}/lookup\n"
    with_config config do |file|
      results = PassiveDNS::Client.new(['dnsdb'], file).query 'example.org'
      assert_equal 1, results.length # TXT records are filtered out
      assert_equal 'example.org', results.first.query
      assert_equal '93.184.216.34', results.first.answer
    end
  ensure
    server&.close
  end

  def test_tlp_security_control
    control = PassiveDNS::TLPSecurityControl.new 'Yellow'
    assert_equal 'yellow', control.to_s
    assert control.allow('red')
    assert control.allow('yellow')
    refute control.allow('green')
    assert_raises(RuntimeError) { control.allow 'purple' }
    assert_raises(RuntimeError) { PassiveDNS::TLPSecurityControl.new 'purple' }
  end
end
