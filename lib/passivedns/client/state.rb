require 'sqlite3'
require 'yaml'
require 'structformatter'

module PassiveDNS
	class PDNSQueueEntry < Struct.new(:query, :state, :level); end

	class PDNSToolState
		attr_accessor :debug
		attr_reader :level

		def initialize
			@queue = []
			@recs = []
			@level = 0
		end

		def next_result
			@recs.each do |rec|
				yield rec
			end
		end

		def add_result(res)
			@recs << res
			add_query(res.answer,'pending')
			add_query(res.query,'pending')
		end

		def update_query(query,state)
			@queue.each do |q|
				if q.query == query
					puts "update_query: #{query} (#{q.state}) -> (#{state})" if @debug
					q.state = state
					break
				end
			end
		end

		def get_state(query)
			@queue.each do |q|
				if q.query == query
					return q.state
				end
			end
			false
		end

		def add_query(query,state,level=@level+1)
			if query =~ /^\d+ \w+\./
				query = query.split(/ /,2)[1]
			end
			return if get_state(query)
			puts "Adding query: #{query}, #{state}, #{level}" if @debug
			@queue << PDNSQueueEntry.new(query,state,level)
		end

		def each_query(max_level=20)
			@queue.each do |q|
				if q.state == 'pending' or q.state == 'failed'
					@level = q.level
					q.state = 'queried'
					if q.level < max_level
						yield q.query
					end
				end
			end
		end

		def to_gdf
			output = "nodedef> name,description VARCHAR(12),color,style\n"
			# IP "$node2,,white,1"
			# domain "$node2,,gray,2"
			# Struct.new(:query, :answer, :rrtype, :ttl, :firstseen, :lastseen)
			colors = {"MX" => "green", "A" => "blue", "CNAME" => "pink", "NS" => "red", "SOA" => "white", "PTR" => "purple", "TXT" => "brown"}
			nodes = {}
			edges = {}
			next_result do |i|
				if i 
					nodes[i.query + ",,gray,2"] = true
					if i.answer =~ /[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/ then
						nodes[i.answer + ",,white,1"] = true
					else	
						nodes[i.answer + ",,gray,2"] = true
					end
					color = colors[i.rrtype]
					color ||= "blue"
					edges[i.query + "," + i.answer + "," + color] = true
				end
			end
			nodes.each do |i,j|
				output += i+"\n"
			end
			output += "edgedef> node1,node2,color\n"
			edges.each do |i,j|
				output += i+"\n"
			end
			output
		end

		def to_graphviz
			colors = {"MX" => "green", "A" => "blue", "CNAME" => "pink", "NS" => "red", "SOA" => "white", "PTR" => "purple", "TXT" => "brown"}
			output = "graph pdns {\n"
			nodes = {}
			next_result do |l|
				if l
					unless nodes[l.query]
						output += "  \"#{l.query}\" [shape=ellipse, style=filled, color=gray];\n"
						if l.answer =~ /^\d{3}\.\d{3}\.\d{3}\.\d{3}$/
							output += "  \"#{l.answer}\" [shape=box, style=filled, color=white];\n"
						else
							output += "  \"#{l.answer}\" [shape=ellipse, style=filled, color=gray];\n"
						end
						nodes[l.query] = true
					end
					output += "  \"#{l.query}\" -- \"#{l.answer}\" [color=#{colors[l.rrtype]}];\n"
				end
			end
			output += "}\n"
		end

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
					output += "    <node id='#{r.query}'/>\n" unless nodes["#{r.query}"]
					nodes[r.query] = true
					output += "    <node id='#{r.answer}'/>\n" unless nodes["#{r.answer}"]
					nodes[r.answer] = true
					output += "    <edge source='#{r.query}' target='#{r.answer}'/>\n" unless edges["#{r.query}|#{r.answer}"]
				end
			end
			output += '</graph></graphml>'+"\n"
		end

		def to_xml
			output = '<?xml version="1.0" encoding="UTF-8" ?>'+"\n"
			output +=  "<report>\n"
			output +=  "	<results>\n"
			next_result do |rec|
				output +=  "		"+rec.to_xml+"\n"
			end
			output +=  "	</results>\n"
			output +=  "</report>\n"
		end

		def to_yaml
			output = ""
			next_result do |rec|
				output += rec.to_yaml+"\n"
			end
			output
		end

		def to_json
			output = "[\n"
			sep = ""
			next_result do |rec|
				output += sep
				output += rec.to_json
				sep = ",\n"
			end
			output += "\n]\n"
		end

		def to_s(sep="\t")
			output = ""
			next_result do |rec|
				output += rec.to_s(sep)+"\n"
			end
			output
		end
	end # class PDNSToolState


	class PDNSToolStateDB < PDNSToolState
		attr_reader :level
		def initialize(sqlitedb=nil)
			puts "PDNSToolState  initialize  #{sqlitedb}" if @debug
			@level = 0
			@sqlitedb = sqlitedb
			raise "Cannot use this class without a database file" unless @sqlitedb
			unless File.exists?(@sqlitedb)
				newdb = true
			end
			@sqlitedbh = SQLite3::Database.new(@sqlitedb)
			if newdb
				create_tables
			end
			res = @sqlitedbh.execute("select min(level) from queue where state = 'pending'")
			if res
				res.each do |row|
					@level = row[0].to_i
					puts "changed @level = #{@level}" if @debug
				end
			end
		end

		def create_tables
			puts "creating tables" if @debug
			@sqlitedbh.execute("create table results (query, answer, rrtype, ttl, firstseen, lastseen, ts REAL)")
			@sqlitedbh.execute("create table queue (query, state, level INTEGER, ts REAL)")
			@sqlitedbh.execute("create index residx on results (ts)")
			@sqlitedbh.execute("create unique index queue_unique on queue (query)")
			@sqlitedbh.execute("create index queue_level_idx on queue (level)")
			@sqlitedbh.execute("create index queue_state_idx on queue (state)")
		end

		def next_result
			rows = @sqlitedbh.execute("select query, answer, rrtype, ttl, firstseen, lastseen from results order by ts")
			rows.each do |row|
				yield PDNSResult.new(*row)
			end
		end

		def add_result(res)
			puts "adding result: #{res.to_s}" if @debug
			curtime = Time.now().to_f
			@sqlitedbh.execute("insert into results values ('#{res.query}','#{res.answer}','#{res.rrtype}','#{res.ttl}','#{res.firstseen}','#{res.lastseen}',#{curtime})")

			add_query(res.answer,'pending')
			add_query(res.query,'pending')
		end

		def add_query(query,state,level=@level+1)
			return if get_state(query)
			curtime = Time.now().to_f
			begin
				puts "add_query(#{query},#{state},level=#{level})" if @debug
				@sqlitedbh.execute("insert into queue values ('#{query}','#{state}',#{level},#{curtime})")
			rescue
			end
		end

		def update_query(query,state)
			@sqlitedbh.execute("update queue set state = '#{state}' where query = '#{query}'")
		end

		def get_state(query)
			rows = @sqlitedbh.execute("select state from queue where query = '#{query}'")
			if rows
				rows.each do |row|
					return row[0]
				end
			end
			false
		end

		def each_query(max_level=20)
			puts "each_query max_level=#{max_level} curlevel=#{@level}" if @debug
			rows = @sqlitedbh.execute("select query, state, level from queue where state = 'failed' or state = 'pending' order by level limit 1")
			if rows
				rows.each do |row|
					query,state,level = row
					puts "  #{query},#{state},#{level}" if @debug
					if level < max_level
						update_query(query,'queried')
						yield query
					end
				end
			end
		end
	end # class PDNSToolStateDB
end