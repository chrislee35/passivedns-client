module PassiveDNS #:nodoc: don't document this
  # abstract class that all PassiveDNS::Provider should subclass
  class PassiveDB
    # raises an exception that this should be implemented by the subclass
    def self.name
      raise "You should implement your own version of .name"
    end
    
    # raises an exception that this should be implemented by the subclass
    def self.config_section_name
      name
    end
    
    # raises an exception that this should be implemented by the subclass
    def self.option_letter
      raise "You should pick a unique letter to serve as your database option letter for the command line option -d"
    end
    
    # raises an exception that this should be implemented by the subclass
    def lookup(label, limit=nil)
      raise "You must implement the lookup function"
    end
  end
end