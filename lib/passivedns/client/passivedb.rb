# frozen_string_literal: true

module PassiveDNS # :nodoc: don't document this
  # abstract class that all PassiveDNS::Provider should subclass
  class PassiveDB
    @providers = []

    class << self
      # all of the classes that subclass PassiveDB
      attr_reader :providers

      # registers each subclass as a provider
      def inherited(subclass)
        super
        PassiveDB.providers << subclass
      end
    end

    # :debug enables verbose logging to standard output
    # :timeout is the number of seconds to wait for a lookup
    attr_accessor :debug, :timeout

    # raises an exception that this should be implemented by the subclass
    def self.name
      raise 'You should implement your own version of .name'
    end

    # raises an exception that this should be implemented by the subclass
    def self.config_section_name
      name
    end

    # raises an exception that this should be implemented by the subclass
    def self.option_letter
      raise 'You should pick a unique letter to serve as your database option letter for the command line option -d'
    end

    # raises an exception that this should be implemented by the subclass
    def lookup(_label, _limit = nil)
      raise 'You must implement the lookup function'
    end
  end
end
