# frozen_string_literal: true

require 'sqlite3'
require 'yaml'
require 'structformatter'

module PassiveDNS # :nodoc:
  # struct to hold pending entries for query
  PDNSQueueEntry = Struct.new :query, :state, :level

  # holds state in memory of the queue to be queried, records returned, and the level of recursion
  class PDNSToolState
    # :debug enables verbose logging to standard output
    attr_accessor :debug
    # :level is the recursion depth
    attr_reader :level

    # creates a new, blank PDNSToolState instance
    def initialize
      @queue = []
      @recs = []
      @level = 0
    end

    # returns the next record
    def next_result(&)
      @recs.each(&)
    end

    # adds the record to the list of records received and tries to add the answer and query back to the queue for future query
    def add_result(res)
      @recs << res
      add_query res.answer, 'pending'
      add_query res.query, 'pending'
    end

    # sets the state of a given query
    def update_query(query, state)
      @queue.each do |q|
        next unless q.query == query

        puts "update_query: #{query} (#{q.state}) -> (#{state})" if @debug
        q.state = state
        break
      end
    end

    # returns the state of a provided query
    def get_state(query)
      @queue.each do |q|
        return q.state if q.query == query
      end
      false
    end

    # adding a query to the queue of things to be queried, but only if the query isn't already queued or answered
    def add_query(query, state, level = @level + 1)
      query = query.split(/ /, 2)[1] if /^\d+ \w+\./.match?(query)
      return if get_state query

      puts "Adding query: #{query}, #{state}, #{level}" if @debug
      @queue << PDNSQueueEntry.new(query, state, level)
    end

    # returns each query waiting on the queue
    def each_query(max_level = 20)
      @queue.each do |q|
        next unless (q.state == 'pending') || (q.state == 'failed')

        @level = q.level
        q.state = 'queried'
        yield q.query if q.level < max_level
      end
    end

    # transforms a set of results into GDF syntax
    def to_gdf
      output = "nodedef> name,description VARCHAR(12),color,style\n"
      # IP "$node2,,white,1"
      # domain "$node2,,gray,2"
      # Struct.new(:query, :answer, :rrtype, :ttl, :firstseen, :lastseen)
      colors = { 'MX' => 'green', 'A' => 'blue', 'CNAME' => 'pink', 'NS' => 'red', 'SOA' => 'white', 'PTR' => 'purple', 'TXT' => 'brown' }
      nodes = {}
      edges = {}
      next_result do |i|
        if i
          nodes["#{i.query},,gray,2"] = true
          if /[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/.match?(i.answer)
            nodes["#{i.answer},,white,1"] = true
          else
            nodes["#{i.answer},,gray,2"] = true
          end
          color = colors[i.rrtype]
          color ||= 'blue'
          edges["#{i.query},#{i.answer},#{color}"] = true
        end
      end
      nodes.each_key do |i|
        output += "#{i}\n"
      end
      output += "edgedef> node1,node2,color\n"
      edges.each_key do |i|
        output += "#{i}\n"
      end
      output
    end

    # transforms a set of results into graphviz syntax
    def to_graphviz
      colors = { 'MX' => 'green', 'A' => 'blue', 'CNAME' => 'pink', 'NS' => 'red', 'SOA' => 'white', 'PTR' => 'purple', 'TXT' => 'brown' }
      output = "graph pdns {\n"
      nodes = {}
      next_result do |l|
        if l
          unless nodes[l.query]
            output += "  \"#{l.query}\" [shape=ellipse, style=filled, color=gray];\n"
            output += if /^\d{3}\.\d{3}\.\d{3}\.\d{3}$/.match?(l.answer)
                        "  \"#{l.answer}\" [shape=box, style=filled, color=white];\n"
                      else
                        "  \"#{l.answer}\" [shape=ellipse, style=filled, color=gray];\n"
                      end
            nodes[l.query] = true
          end
          output += "  \"#{l.query}\" -- \"#{l.answer}\" [color=#{colors[l.rrtype]}];\n"
        end
      end
      output += "}\n"
    end

    # transforms a set of results into graphml syntax
    def to_graphml
      output = '<?xml version="1.0" encoding="UTF-8"?>
<graphml xmlns="http://graphml.graphdrawing.org/xmlns"
    xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
    xsi:schemaLocation="http://graphml.graphdrawing.org/xmlns
     http://graphml.graphdrawing.org/xmlns/1.0/graphml.xsd">
  <graph id="G" edgedefault="directed">
'
      nodes = {}
      edges = {}
      next_result do |r|
        if r
          output += "    <node id='#{r.query}'/>\n" unless nodes[r.query.to_s]
          nodes[r.query] = true
          output += "    <node id='#{r.answer}'/>\n" unless nodes[r.answer.to_s]
          nodes[r.answer] = true
          output += "    <edge source='#{r.query}' target='#{r.answer}'/>\n" unless edges["#{r.query}|#{r.answer}"]
        end
      end
      output += "</graph></graphml>\n"
    end

    # transforms a set of results into XML
    def to_xml
      output = "<?xml version=\"1.0\" encoding=\"UTF-8\" ?>\n"
      output += "<report>\n"
      output += "  <results>\n"
      next_result do |rec|
        output += "    #{rec.to_xml}\n"
      end
      output += "  </results>\n"
      output += "</report>\n"
    end

    # transforms a set of results into YAML
    def to_yaml
      output = ''
      next_result do |rec|
        output += "#{rec.to_yaml}\n"
      end
      output
    end

    # transforms a set of results into JSON
    def to_json(*_args)
      output = "[\n"
      sep = ''
      next_result do |rec|
        output += sep
        output += rec.to_json
        sep = ",\n"
      end
      output += "\n]\n"
    end

    # transforms a set of results into a text string
    def to_s(sep = "\t")
      output = ''
      next_result do |rec|
        output += "#{rec.to_s sep}\n"
      end
      output
    end
  end

  # creates persistence to the tool state by leveraging SQLite3
  class PDNSToolStateDB < PDNSToolState
    attr_reader :level

    # creates an SQLite3-based Passive DNS Client state
    # only argument is the filename of the sqlite3 database
    def initialize(sqlitedb = nil)
      super()
      @debug = false
      puts "PDNSToolState  initialize  #{sqlitedb}" if @debug
      @level = 0
      @sqlitedb = sqlitedb
      raise 'Cannot use this class without a database file' unless @sqlitedb

      newdb = true unless File.exist? @sqlitedb
      @sqlitedbh = SQLite3::Database.new @sqlitedb
      create_tables if newdb
      res = @sqlitedbh.execute "select min(level) from queue where state = 'pending'"
      return unless res

      res.each do |row|
        @level = row[0].to_i
        puts "changed @level = #{@level}" if @debug
      end
    end

    # creates the sqlite3 tables needed to track the state of this tool as itqueries and recurses
    def create_tables
      puts 'creating tables' if @debug
      @sqlitedbh.execute 'create table results (query, answer, rrtype, ttl, firstseen, lastseen, ts REAL)'
      @sqlitedbh.execute 'create table queue (query, state, level INTEGER, ts REAL)'
      @sqlitedbh.execute 'create index residx on results (ts)'
      @sqlitedbh.execute 'create unique index queue_unique on queue (query)'
      @sqlitedbh.execute 'create index queue_level_idx on queue (level)'
      @sqlitedbh.execute 'create index queue_state_idx on queue (state)'
    end

    # returns the next record
    def next_result
      rows = @sqlitedbh.execute 'select query, answer, rrtype, ttl, firstseen, lastseen from results order by ts'
      rows.each do |row|
        # the database does not keep the source or the response time
        yield PDNSResult.new(nil, nil, *row)
      end
    end

    # adds the record to the list of records received and tries to add the answer and query back to the queue for future query
    def add_result(res)
      puts "adding result: #{res}" if @debug
      curtime = Time.now.to_f
      @sqlitedbh.execute('insert into results values (?, ?, ?, ?, ?, ?, ?)',
                         [res.query, res.answer, res.rrtype, res.ttl, res.firstseen, res.lastseen, curtime].map do |v|
                           v.nil? || v.is_a?(Float) ? v : v.to_s
                         end)

      add_query res.answer, 'pending'
      add_query res.query, 'pending'
    end

    # adding a query to the queue of things to be queried, but only if the query isn't already queued or answered
    def add_query(query, state, level = @level + 1)
      return if get_state query

      curtime = Time.now.to_f
      puts "add_query(#{query},#{state},level=#{level})" if @debug
      @sqlitedbh.execute 'insert into queue values (?, ?, ?, ?)', [query.to_s, state, level, curtime]
    rescue SQLite3::ConstraintException
      # the query is already queued
    end

    # sets the state of a given query
    def update_query(query, state)
      @sqlitedbh.execute 'update queue set state = ? where query = ?', [state, query.to_s]
    end

    # returns each query waiting on the queue
    def get_state(query)
      row = @sqlitedbh.get_first_row 'select state from queue where query = ?', [query.to_s]
      row ? row[0] : false
    end

    # returns each query waiting on the queue
    def each_query(max_level = 20)
      puts "each_query max_level=#{max_level} curlevel=#{@level}" if @debug
      row = @sqlitedbh.get_first_row "select query, state, level from queue where state = 'failed' or state = 'pending' " \
                                     'order by level limit 1'
      return unless row

      query, state, level = row
      puts "  #{query},#{state},#{level}" if @debug
      return unless level < max_level

      update_query query, 'queried'
      yield query
    end
  end
end
