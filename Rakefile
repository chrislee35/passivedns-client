#!/usr/bin/env rake
require "bundler/gem_tasks"

require 'rake/testtask'
require 'rdoc/task'

Rake::TestTask.new do |t|
	t.libs << 'lib'
	t.test_files = FileList['test/test_*.rb']
	t.verbose = true
end

RDoc::Task.new do |rd|
  rd.main = "README.doc"
  rd.rdoc_files.include("README.md", "lib/**/*.rb")
  rd.options << "--all"
  rd.options << "--verbose"
end

task :default => :test