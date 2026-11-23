# frozen_string_literal: true

require 'net/http'

module PassiveDNS # :nodoc: don't document this
  # raised when a passive DNS provider reports a failure, such as a bad API key or a rate limit
  class ProviderError < StandardError; end

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

    private

    # returns the response when it is a success, otherwise raises a ProviderError that names the provider, the HTTP status
    # and the first line of the body (providers report errors as plain text, HTML or JSON)
    def check_response(response)
      return response if response.is_a? Net::HTTPSuccess

      detail = response.body.to_s.strip.lines.first.to_s.strip[0, 200]
      raise ProviderError, "#{self.class.name}: HTTP #{response.code}#{": #{detail}" unless detail.empty?}"
    end
  end
end
