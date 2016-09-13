require 'getoptlong'
require 'structformatter'
require 'getoptlong'
require 'yaml'
require 'pp'

module PassiveDNS # :nodoc:
  # Handles all the command-line parsing, state tracking, and dispatching queries to the PassiveDNS::Client instance
  # CLInterface is aliased by CLI
  class CLInterface
    #  generates a mapping between the option letter for each PassiveDNS provider and the class
    def self.get_letter_map
      letter_map = {}
      mod = PassiveDNS::Provider
      mod.constants.each do |const|
        if mod.const_get(const).is_a?(Class) and mod.const_get(const).superclass == PassiveDNS::PassiveDB
          letter = mod.const_get(const).option_letter
          name = mod.const_get(const).name
          config_section_name = mod.const_get(const).config_section_name
          letter_map[letter] = [name, config_section_name]
        end
      end
      letter_map      
    end
    
    # parses the command line and yields an options hash
    # === Default Options
    #      options = {
    #        :pdnsdbs => [],     # passive dns providers to query
    #        :format => "text",  # output format
    #        :sep => "\t",       # field separator for text format
    #        :recursedepth => 1, # recursion depth
    #        :wait => 0,         # wait period between recursions
    #        :res => nil,        # unused.  I don't remember why this is here.
    #        :debug => false,    # debug flag
    #        :sqlitedb => nil,   # filename for maintaining state in an sqlite3 db
    #        :limit => nil,      # number of results per provider per recursion
    #        :help => false      # display the usage text
    #      }
    def self.parse_command_line(args)
      origARGV = ARGV.dup
      ARGV.replace(args)
      opts = GetoptLong.new(
        [ '--help', '-h', GetoptLong::NO_ARGUMENT ],
        [ '--debug', '-v', GetoptLong::NO_ARGUMENT ],
        [ '--database', '-d', GetoptLong::REQUIRED_ARGUMENT ],
  
        [ '--gdf', '-g', GetoptLong::NO_ARGUMENT ],
        [ '--graphviz', '-z', GetoptLong::NO_ARGUMENT ],
        [ '--graphml', '-m', GetoptLong::NO_ARGUMENT ],
        [ '--csv', '-c', GetoptLong::NO_ARGUMENT ],
        [ '--xml', '-x', GetoptLong::NO_ARGUMENT ],
        [ '--yaml', '-y', GetoptLong::NO_ARGUMENT ],
        [ '--json', '-j', GetoptLong::NO_ARGUMENT ],
        [ '--text', '-t', GetoptLong::NO_ARGUMENT ],
        [ '--sep', '-s', GetoptLong::REQUIRED_ARGUMENT ],
  
        [ '--sqlite3', '-f', GetoptLong::REQUIRED_ARGUMENT ],
        [ '--recurse', '-r', GetoptLong::REQUIRED_ARGUMENT ],
        [ '--wait', '-w', GetoptLong::REQUIRED_ARGUMENT ],
        [ '--limit', '-l', GetoptLong::REQUIRED_ARGUMENT ]
      )

      letter_map = get_letter_map

      # sets the default search methods
      options = {
        :pdnsdbs => [],
        :format => "text",
        :sep => "\t",
        :recursedepth => 1,
        :wait => 0,
        :res => nil,
        :debug => false,
        :sqlitedb => nil,
        :limit => nil,
        :help => false
      }

      opts.each do |opt, arg|
        case opt
        when '--help'
          options[:help] = true
        when '--debug'
          options[:debug] = true
        when '--database'
          arg.split(//).each do |c|
            if c == ','
              next
            elsif letter_map[c]
              options[:pdnsdbs] << letter_map[c][1]
            else
              $stderr.puts "ERROR: Unknown passive DNS database identifier: #{c}."
              usage(letter_map)
            end
          end
        when '--gdf'
          options[:format] = 'gdf'
        when '--graphviz'
          options[:format] = 'graphviz'
        when '--graphml'
          options[:format] = 'graphml'
        when '--csv'
          options[:format] = 'text'
          options[:sep] = ','
        when '--yaml'
          options[:format] = 'yaml'
        when '--xml'
          options[:format] = 'xml'
        when '--json'
          options[:format] = 'json'
        when '--text'
          options[:format] = 'text'
        when '--sep'
          options[:sep] = arg
        when '--recurse'
          options[:recursedepth] = arg.to_i
        when '--wait'
          options[:wait] = arg.to_i
        when '--sqlite3'
          options[:sqlitedb] = arg
        when '--limit'
          options[:limit] = arg.to_i
        else
          options[:help] = true
        end
      end
      args = ARGV.dup
      ARGV.replace(origARGV)

      if options[:pdnsdbs].length == 0
        options[:pdnsdbs] << "bfk"
      end

      if options[:pdnsdbs].index("bfk") and options[:recursedepth] > 1 and options[:wait] < 60
        options[:wait] = 60
        $stderr.puts "Enforcing a minimal 60 second wait when using BFK for recursive crawling"
      end

      if options[:debug]
        $stderr.puts "Using the following databases: #{options[:pdnsdbs].join(", ")}"
        $stderr.puts "Recursions: #{options[:recursedepth]}, Wait time: #{options[:wait]}, Limit: #{options[:limit] or 'none'}"
        if options[:format] == "text" or options[:format] == "csv"
            $stderr.puts "Output format: #{options[:format]} (sep=\"#{options[:sep]}\")"
        else
            $stderr.puts "Output format: #{options[:format]}"
        end
        if ENV['http_proxy']
          $stderr.puts "Using proxy settings: http_proxy=#{ENV['http_proxy']}, https_proxy=#{ENV['https_proxy']}"
        end
      end
      
      [options, args]
    end
    
    # returns a string containing the usage information
    # takes in a hash of letter to passive dns providers
    def self.usage(letter_map)
      databases = letter_map.keys.sort.join("")
      help_text = ""
      help_text << "Usage: #{$0} [-d [#{databases}]] [-g|-v|-m|-c|-x|-y|-j|-t] [-os <sep>] [-f <file>] [-r#|-w#|-v] [-l <count>] <ip|domain|cidr>\n"
      help_text << "Passive DNS Providers\n"
      help_text << "  -d#{databases} uses all of the available passive dns database\n"
      letter_map.keys.sort.each do |l|
        help_text << "  -d#{l} use #{letter_map[l][0]}\n"
      end
      help_text << "  -dvt uses VirusTotal and TCPIPUtils (for example)\n"
      help_text << "\n"
      help_text << "Output Formatting\n"
      help_text << "  -g link-nodal GDF visualization definition\n"
      help_text << "  -z link-nodal graphviz visualization definition\n"
      help_text << "  -m link-nodal graphml visualization definition\n"
      help_text << "  -c CSV\n"
      help_text << "  -x XML\n"
      help_text << "  -y YAML\n"
      help_text << "  -j JSON\n"
      help_text << "  -t ASCII text (default)\n"
      help_text << "  -s <sep> specifies a field separator for text output, default is tab\n"
      help_text << "\n"
      help_text << "State and Recursion\n"
      help_text << "  -f[file] specifies a sqlite3 database used to read the current state - useful for large result sets and generating graphs of previous runs.\n"
      help_text << "  -r# specifies the levels of recursion to pull. **WARNING** This is quite taxing on the pDNS servers, so use judiciously (never more than 3 or so) or find yourself blocked!\n"
      help_text << "  -w# specifies the amount of time to wait, in seconds, between queries (Default: 0)\n"
      help_text << "  -l <count> limits the number of records returned per passive dns database queried.\n"
      help_text << "\n"
      help_text << "Getting Help\n"
      help_text << "  -h hello there.  This option produces this helpful help information on how to access help.\n"
      help_text << "  -v debugging information\n"
      
      help_text
    end
    
    # performs a stateful, recursive (if desired) passive DNS lookup against all specified providers
    def self.pdnslookup(state, pdnsclient, options)
      recursedepth = options[:recursedepth]
      wait = options[:wait]
      debug = options[:debug]
      limit = options[:limit]
      puts "pdnslookup: #{state.level} #{recursedepth}" if debug
      level = 0
      while level < recursedepth
        puts "pdnslookup: #{level} < #{recursedepth}" if debug
        state.each_query(recursedepth) do |q|
          rv = pdnsclient.query(q,limit)
          if rv
            rv.each do |r|
              if ["A","AAAA","NS","CNAME","PTR"].index(r.rrtype)
                puts "pdnslookup: #{r.to_s}" if debug
                state.add_result(r)
              end
            end
          else
            state.update_query(rv,'failed')
          end
          sleep wait if level < recursedepth
        end
        level += 1
      end
      state
    end
    
    # returns a string transforming all the PassiveDNS::PDNSResult stored in the state object into text/xml/json/etc.
    def self.results_to_s(state,options)
      format = options[:format]
      sep = options[:sep]
      case format
      when 'text'
        PassiveDNS::PDNSResult.members.join(sep)+"\n"+state.to_s(sep)
      when 'yaml'
        state.to_yaml
      when 'xml'
        state.to_xml
      when 'json'
        state.to_json
      when 'gdf'
        state.to_gdf
      when 'graphviz'
        state.to_graphviz
      when 'graphml'
        state.to_graphml
      end
    end
    
    # create a state instance
    def self.create_state(sqlitedb=nil)
      state = nil
      if sqlitedb
        state = PassiveDNS::PDNSToolStateDB.new(sqlitedb)
      else
        state = PassiveDNS::PDNSToolState.new
      end
    end
    
    # main method, takes command-line arguments and performs the desired queries and outputs
    def self.run(args)
      options, items = parse_command_line(args)
      if options[:help]
        return usage(get_letter_map)
      end
      if options[:recursedepth] > 3
        $stderr.puts "WARNING:  a recursedepth of > 3 can be abusive, please reconsider: sleeping 60 seconds for sense to come to you (hint: hit CTRL-C)"
        sleep 60
      end
      state = create_state(options[:sqlitedb])
      state.debug = options[:debug]

      pdnsclient = PassiveDNS::Client.new(options[:pdnsdbs])
      pdnsclient.debug = options[:debug]
      
      if items.length > 0
        items.each do |arg|
          state.add_query(arg,'pending',0)
        end
      else
        $stdin.each_line do |l|
          state.add_query(l.chomp,'pending',0)
        end
      end
      pdnslookup(state,pdnsclient,options)
      results_to_s(state,options)
    end
  end
  # Alias for the CLInterface class
  CLI = PassiveDNS::CLInterface
end

