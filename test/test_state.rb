# frozen_string_literal: true

require_relative 'helper'

module StateTests
  def test_results_and_queue
    state.add_result make_result('example.org', '93.184.216.34')
    results = []
    state.next_result { |result| results << result }
    assert_equal 1, results.length
    assert_equal 'example.org', results.first.query
    assert_equal 'pending', state.get_state('93.184.216.34')
    assert_equal 'pending', state.get_state('example.org')
    refute state.get_state('unknown.example')
  end

  def test_each_query_marks_queried
    state.add_query 'example.org', 'pending', 0
    queried = []
    state.each_query { |query| queried << query }
    assert_equal ['example.org'], queried
    assert_equal 'queried', state.get_state('example.org')
  end

  def test_each_query_respects_max_level
    state.add_query 'example.org', 'pending', 5
    queried = []
    state.each_query(3) { |query| queried << query }
    assert_empty queried
  end

  def test_update_query
    state.add_query 'example.org', 'pending', 0
    state.update_query 'example.org', 'failed'
    assert_equal 'failed', state.get_state('example.org')
  end

  def test_duplicate_queries_are_ignored
    state.add_query 'example.org', 'pending', 0
    state.add_query 'example.org', 'failed', 3
    assert_equal 'pending', state.get_state('example.org')
  end

  def test_special_characters_in_data
    nasty = "o'brien'); drop table results; --.example"
    state.add_result make_result(nasty, 'x.example')
    results = []
    state.next_result { |result| results << result }
    assert_equal [nasty], results.map(&:query)
    assert_equal 'pending', state.get_state(nasty)
    state.update_query nasty, 'queried'
    assert_equal 'queried', state.get_state(nasty)
  end

  def test_output_formats
    state.add_result make_result('example.org', '93.184.216.34')
    assert_includes state.to_s, 'example.org'
    assert_includes state.to_xml, '<report>'
    assert_includes state.to_json, 'example.org'
    assert_includes state.to_yaml, 'example.org'
    assert_includes state.to_gdf, 'edgedef>'
    assert_includes state.to_graphviz, 'graph pdns'
    assert_includes state.to_graphml, '<graphml'
  end
end

class TestMemoryState < Minitest::Test
  include StateTests

  def state
    @state ||= PassiveDNS::PDNSToolState.new
  end
end

class TestDatabaseState < Minitest::Test
  include StateTests

  def setup
    @dir = Dir.mktmpdir
    @file = File.join @dir, 'state.sqlite3'
  end

  def teardown
    FileUtils.remove_entry @dir
  end

  def state
    @state ||= PassiveDNS::PDNSToolStateDB.new @file
  end

  def test_requires_a_database_file
    assert_raises(RuntimeError) { PassiveDNS::PDNSToolStateDB.new }
  end

  def test_state_persists
    state.add_query 'example.org', 'pending', 0
    state.add_result make_result('example.org', '93.184.216.34')
    reopened = PassiveDNS::PDNSToolStateDB.new @file
    assert_equal 'pending', reopened.get_state('example.org')
    results = []
    reopened.next_result { |result| results << result }
    assert_equal ['93.184.216.34'], results.map(&:answer)
  end
end
