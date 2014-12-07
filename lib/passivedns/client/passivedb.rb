module PassiveDNS
  class PassiveDB
    def self.name
      raise "You should implement your own version of .name"
    end
    
    def self.config_section_name
      name
    end
    
    def self.option_letter
      raise "You should pick a unique letter to serve as your database option letter for the command line option -d"
    end
    
    def lookup(label, limit=nil)
      raise "You must implement the lookup function"
    end
  end
end