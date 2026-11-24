# frozen_string_literal: true

# DESCRIPTION: queries passive DNS databases
# This code is released under the MIT license (see LICENSE.txt).
# Please note that use of any passive dns database is subject to the terms of use of that passive dns database.  Use of this script in
# violation of their terms is not encouraged in any way.  Also, please do not add any obfuscation to try to work around their terms of
# service.  If you need special services, ask the providers for help/permission.
# Remember, these passive DNS operators are my friends.  I don't want to have a row with them because some asshat used this library to
# abuse them.
require 'iniparse'
require_relative 'client/version'
require_relative 'client/state'
require_relative 'client/passivedb'

# load all the providers
Dir.glob(File.join(__dir__, 'client', 'provider', '*.rb')).each { |provider| require provider }

module PassiveDNS # :nodoc:
  class SecurityControl
    def allow(_user_level)
      raise 'unimplemented'
    end
  end

  class TLPSecurityControl < SecurityControl
    LEVELS = %w[white green yellow red].freeze

    def initialize(tlp)
      super()
      raise "Unknown TLP setting, #{tlp}" unless /(white|green|yellow|red)/i.match?(tlp)

      @tlp = tlp.downcase
      @tlp_level = LEVELS.index @tlp
    end

    def allow(user_level) # rubocop:disable Naming/PredicateMethod
      level = LEVELS.index user_level.downcase
      raise "Invalid user level, #{user_level}" if level.nil?

      level >= @tlp_level
    end

    def to_s
      @tlp
    end
  end

  # struct to contain the results from a PassiveDNS lookup
  # (the :count member intentionally shadows Struct#count)
  PDNSResult = Struct.new :source, :response_time, :query, :answer, :rrtype, :ttl, :firstseen, :lastseen, :count, :security # rubocop:disable Lint/StructNewOverride

  # coodinates the lookups accross all configured PassiveDNS providers
  class Client
    # the record types that are reported
    RRTYPES = %w[A AAAA NS CNAME PTR SOA].freeze

    # default location of the configuration file
    DEFAULT_CONFIG_FILE = File.join Dir.home, '.passivedns-client'

    # the names of all available providers, e.g., ["circl", "dnsdb", ...]
    def self.provider_names
      names = PassiveDB.providers.map(&:config_section_name)
      names.sort!
      names
    end

    # reads an INI-style configuration file and returns a hash of section name to a hash of settings.
    # A missing file yields an empty configuration and a warning.
    def self.load_config(configfile = DEFAULT_CONFIG_FILE)
      unless File.exist? configfile
        warn "Could not find config file at #{configfile}.  Using a blank configuration."
        return {}
      end

      IniParse.parse(File.read(configfile)).to_hash
    rescue IniParse::IniParseError => e
      raise "Unable to parse the config file #{configfile}: #{e.message}"
    end

    # instantiate and configure all specified PassiveDNS providers
    # pdns        array of passivedns provider names, e.g., ["dnsdb","virustotal"]
    # configfile  filename of the passivedns-client configuration
    def initialize(pdns = self.class.provider_names, configfile = DEFAULT_CONFIG_FILE)
      config = self.class.load_config configfile
      class_map = PassiveDB.providers.to_h { |provider| [provider.config_section_name, provider] }

      @pdnsdbs = pdns.uniq.map do |name| # rubocop:disable Performance/ChainArrayAllocation
        raise "Unknown Passive DNS provider: #{name}" unless class_map[name]

        class_map[name].new(config[name] || {})
      end
    end

    # set the debug flag
    def debug=(value)
      @pdnsdbs.each do |pdnsdb|
        pdnsdb.debug = value
      end
    end

    # set the timeout, in seconds, for each provider's lookups
    def timeout=(value)
      @pdnsdbs.each do |pdnsdb|
        pdnsdb.timeout = value
      end
    end

    # perform the query lookup accross all configured PassiveDNS providers
    def query(item, limit = nil)
      threads = @pdnsdbs.map do |pdnsdb|
        Thread.new item do |q|
          Thread.current.report_on_exception = false
          pdnsdb.lookup q, limit
        end
      end

      results = []
      threads.each do |thr|
        thr.value&.each do |r|
          results << r if RRTYPES.include? r.rrtype
        end
      rescue StandardError => e
        # one failing provider should not lose the answers from the others
        warn "ERROR: #{e.message}"
      end

      results
    end
  end
end
