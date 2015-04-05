unless Kernel.respond_to?(:require_relative)
	module Kernel
		def require_relative(path)
			require File.join(File.dirname(caller[0]), path.to_str)
		end
	end
end

require_relative 'helper'
require 'configparser'
require_relative '../lib/passivedns/client/cli.rb'

class TestCLI < Minitest::Test
  def test_letter_map
    letter_map = PassiveDNS::CLI.get_letter_map
    assert_equal("3bcdmprtv", letter_map.keys.sort.join(""))
  end
  
  def test_help_text
    helptext = PassiveDNS::CLI.run(["--help"])
    helptext.gsub!(/Usage: .*?\[/, "Usage: [")
    assert_equal(
"Usage: [-d [3bcdmprtv]] [-g|-v|-m|-c|-x|-y|-j|-t] [-os <sep>] [-f <file>] [-r#|-w#|-v] [-l <count>] <ip|domain|cidr>
Passive DNS Providers
  -d3bcdmprtv uses all of the available passive dns database
  -d3 use 360.cn
  -db use BFK.de
  -dc use CIRCL
  -dd use DNSDB
  -dm use Mnemonic
  -dp use PassiveTotal
  -dr use RiskIQ
  -dt use TCPIPUtils
  -dv use VirusTotal
  -dvt uses VirusTotal and TCPIPUtils (for example)

Output Formatting
  -g link-nodal GDF visualization definition
  -z link-nodal graphviz visualization definition
  -m link-nodal graphml visualization definition
  -c CSV
  -x XML
  -y YAML
  -j JSON
  -t ASCII text (default)
  -s <sep> specifies a field separator for text output, default is tab

State and Recursion
  -f[file] specifies a sqlite3 database used to read the current state - useful for large result sets and generating graphs of previous runs.
  -r# specifies the levels of recursion to pull. **WARNING** This is quite taxing on the pDNS servers, so use judiciously (never more than 3 or so) or find yourself blocked!
  -w# specifies the amount of time to wait, in seconds, between queries (Default: 0)
  -l <count> limits the number of records returned per passive dns database queried.

Getting Help
  -h hello there.  This option produces this helpful help information on how to access help.
  -v debugging information
", helptext)
  end
  
  def test_provider_parsing
    options_target = {
      :pdnsdbs => ["bfk"],
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
    
    options, items = PassiveDNS::CLI.parse_command_line([])
    assert_equal(options_target, options)
    assert_equal([], items)
    
    options_target[:pdnsdbs] = ["cn360"]
    options, items = PassiveDNS::CLI.parse_command_line(["-d3"])
    assert_equal(options_target, options)
    assert_equal([], items)

    options_target[:pdnsdbs] = ["bfk"]
    options, items = PassiveDNS::CLI.parse_command_line(["-db"])
    assert_equal(options_target, options)
    assert_equal([], items)
   
    options_target[:pdnsdbs] = ["circl", "dnsdb", "mnemonic", "riskiq"]
    options, items = PassiveDNS::CLI.parse_command_line(["-dcdmr"])
    assert_equal(options_target, options)
    assert_equal([], items)
    
    options_target[:pdnsdbs] = ["passivetotal", "tcpiputils", "virustotal"]
    options, items = PassiveDNS::CLI.parse_command_line(["-dptv"])
    assert_equal(options_target, options)
    assert_equal([], items)
    
  end
  
  def test_output_parsing
    options_target = {
      :pdnsdbs => ["passivetotal", "tcpiputils", "virustotal"],
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
    
    options_target[:sep] = ","
    options, items = PassiveDNS::CLI.parse_command_line(["-dptv", "-c", "8.8.8.8"])
    assert_equal(options_target, options)
    assert_equal(["8.8.8.8"], items)
    
    options_target[:sep] = "|"
    options, items = PassiveDNS::CLI.parse_command_line(["-dptv", "-s", "|", "8.8.8.8"])
    assert_equal(options_target, options)
    assert_equal(["8.8.8.8"], items)
    
    options_target[:sep] = "\t"
    
    options, items = PassiveDNS::CLI.parse_command_line(["-dptv", "-t", "8.8.8.8"])
    assert_equal(options_target, options)
    assert_equal(["8.8.8.8"], items)

    options_target[:format] = "json"
    options, items = PassiveDNS::CLI.parse_command_line(["-dptv", "-j", "8.8.8.8"])
    assert_equal(options_target, options)
    assert_equal(["8.8.8.8"], items)
    
    options_target[:format] = "xml"
    options, items = PassiveDNS::CLI.parse_command_line(["-dptv", "-x", "8.8.8.8"])
    assert_equal(options_target, options)
    assert_equal(["8.8.8.8"], items)
    
    options_target[:format] = "yaml"
    options, items = PassiveDNS::CLI.parse_command_line(["-dptv", "-y", "8.8.8.8"])
    assert_equal(options_target, options)
    assert_equal(["8.8.8.8"], items)
    
    options_target[:format] = "gdf"
    options, items = PassiveDNS::CLI.parse_command_line(["-dptv", "-g", "8.8.8.8"])
    assert_equal(options_target, options)
    assert_equal(["8.8.8.8"], items)
    
    options_target[:format] = "graphviz"
    options, items = PassiveDNS::CLI.parse_command_line(["-dptv", "-z", "8.8.8.8"])
    assert_equal(options_target, options)
    assert_equal(["8.8.8.8"], items)
    
    options_target[:format] = "graphml"
    options, items = PassiveDNS::CLI.parse_command_line(["-dptv", "-m", "8.8.8.8"])
    assert_equal(options_target, options)
    assert_equal(["8.8.8.8"], items)
    
    options_target[:format] = "text"
  end
  
  def test_help_debug_parsing
    options_target = {
      :pdnsdbs => ["passivetotal", "tcpiputils", "virustotal"],
      :format => "text",
      :sep => "\t",
      :recursedepth => 1,
      :wait => 0,
      :res => nil,
      :debug => false,
      :sqlitedb => nil,
      :limit => nil,
      :help => true
    }

    options, items = PassiveDNS::CLI.parse_command_line(["-dptv", "-h", "8.8.8.8"])
    assert_equal(options_target, options)
    assert_equal(["8.8.8.8"], items)
    
    options_target[:debug] = true
    options, items = PassiveDNS::CLI.parse_command_line(["-dptv", "-h", "-v", "8.8.8.8"])
    assert_equal(options_target, options)
    assert_equal(["8.8.8.8"], items)
  end
  
  def test_state_recursion_parsing
    options_target = {
      :pdnsdbs => ["passivetotal", "tcpiputils", "virustotal"],
      :format => "text",
      :sep => "\t",
      :recursedepth => 5,
      :wait => 30,
      :res => nil,
      :debug => false,
      :sqlitedb => "test.db",
      :limit => 10,
      :help => false
    }

    options, items = PassiveDNS::CLI.parse_command_line(["-dptv", "-f", "test.db", "-r", "5", "-w", "30", "-l", "10", "8.8.8.8"])
    assert_equal(options_target, options)
    assert_equal(["8.8.8.8"], items)
  end
end