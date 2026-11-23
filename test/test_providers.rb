# frozen_string_literal: true

require_relative 'helper'

class TestProviders < Minitest::Test
  def serve(body, status: 200)
    @server = FakeServer.new body, status: status
  end

  def teardown
    @server&.close
  end

  def test_dnsdb
    serve <<~JSON
      {"rrname":"example.org.","rrtype":"A","rdata":"93.184.216.34","time_first":1000000,"time_last":2000000,"count":7}
      {"rrname":"www.example.org","rrtype":"CNAME","rdata":"example.org.","time_first":1000000,"time_last":2000000,"count":2}
    JSON
    provider = PassiveDNS::Provider::DNSDB.new 'APIKEY' => 'secret', 'URL' => "#{@server.url}/lookup"
    rows = provider.lookup 'example.org', 5
    assert_equal 2, rows.length
    assert_equal 'example.org', rows[0].query
    assert_equal '93.184.216.34', rows[0].answer
    assert_equal 'A', rows[0].rrtype
    assert_equal 7, rows[0].count
    assert_equal 'yellow', rows[0].security
    assert_equal 'example.org', rows[1].answer
    request = @server.requests.first
    assert_match %r{\AGET /lookup/rrset/name/example.org\?limit=5 }, request.first
    assert(request.any? { |line| line.casecmp?('x-api-key: secret') })
  end

  def test_dnsdb_ip_lookup
    serve ''
    provider = PassiveDNS::Provider::DNSDB.new 'APIKEY' => 'secret', 'URL' => "#{@server.url}/lookup"
    provider.lookup '10.0.0.0/8'
    assert_match %r{\AGET /lookup/rdata/ip/10.0.0.0,8 }, @server.requests.first.first
  end

  def test_dnsdb_not_found
    serve '', status: 404
    provider = PassiveDNS::Provider::DNSDB.new 'APIKEY' => 'secret', 'URL' => "#{@server.url}/lookup"
    assert_nil provider.lookup('example.org')
  end

  def test_dnsdb_requires_key
    assert_raises(RuntimeError) { PassiveDNS::Provider::DNSDB.new }
  end

  def test_circl
    serve %({"rrname":"example.org","rrtype":"A","rdata":"93.184.216.34","time_first":1000000,"time_last":2000000,"count":4}\n)
    provider = PassiveDNS::Provider::CIRCL.new 'USERNAME' => 'user', 'PASSWORD' => 'pass', 'URL' => "#{@server.url}/pdns/query"
    rows = provider.lookup 'example.org'
    assert_equal 1, rows.length
    assert_equal 'example.org', rows[0].query
    assert_equal 4, rows[0].count
    assert(@server.requests.first.any? { |line| line.start_with?('Authorization: Basic ') })
  end

  def test_osc
    serve({ 'results' => [{ 'qtype' => 1, 'domain' => 'example.org', 'value' => '93.184.216.34',
                            'date' => '2020-01-02 03:04:05' }] }.to_json)
    provider = PassiveDNS::Provider::OSC.new 'APIKEY' => 'secret', 'URL' => "#{@server.url}/api/v2/domainsquery"
    rows = provider.lookup 'example.org'
    assert_equal 1, rows.length
    assert_equal 'A', rows[0].rrtype
    assert_equal '93.184.216.34', rows[0].answer
    assert_nil rows[0].count
    assert_equal 'amber', rows[0].security
    assert_includes @server.requests.first.first, 'q=qname%3Aexample.org'
  end

  def test_virustotal
    serve({ 'response_code' => 1,
            'resolutions' => [{ 'ip_address' => '93.184.216.34', 'last_resolved' => '2020-01-02 03:04:05' }] }.to_json)
    provider = PassiveDNS::Provider::VirusTotal.new 'APIKEY' => 'secret', 'URL' => "#{@server.url}/vtapi/v2/"
    rows = provider.lookup 'example.org'
    assert_equal 1, rows.length
    assert_equal '93.184.216.34', rows[0].answer
    assert_nil rows[0].count
    assert_equal 'yellow', rows[0].security
    assert_includes @server.requests.first.first, 'domain/report?domain=example.org&apikey=secret'
  end

  def test_passivetotal
    serve({ 'queryValue' => 'example.org',
            'results' => [{ 'resolve' => '93.184.216.34', 'firstSeen' => '2020-01-02 03:04:05', 'lastSeen' => '2020-02-02 03:04:05',
                            'source' => %w[a b] }] }.to_json)
    provider = PassiveDNS::Provider::PassiveTotal.new 'USERNAME' => 'u', 'APIKEY' => 'k', 'URL' => "#{@server.url}/v2/dns/passive"
    rows = provider.lookup 'example.org'
    assert_equal 1, rows.length
    assert_equal 'PassiveTotal/a,b', rows[0].source
    assert_equal '93.184.216.34', rows[0].answer
    assert_equal 'yellow', rows[0].security
  end

  def test_riskiq
    provider = PassiveDNS::Provider::RiskIQ.new 'API_TOKEN' => 't', 'API_PRIVATE_KEY' => 'p'
    body = { 'records' => [{ 'name' => 'example.org.', 'rrtype' => 'A', 'lastSeen' => '2020-02-02 03:04:05',
                             'firstSeen' => '2020-01-02 03:04:05', 'count' => 3, 'data' => ['93.184.216.34.'] }] }.to_json
    rows = provider.send :parse_json, body, 'example.org'
    assert_equal 1, rows.length
    assert_equal 'example.org', rows[0].query
    assert_equal '93.184.216.34', rows[0].answer
    assert_equal 3, rows[0].count
  end

  def test_providers_use_default_tls_verification
    sources = Dir[File.join(__dir__, '..', 'lib', 'passivedns', 'client', 'provider', '*.rb')]
    refute_empty sources
    sources.each { |file| refute_match(/VERIFY_NONE/, File.read(file), file) }
  end
end
