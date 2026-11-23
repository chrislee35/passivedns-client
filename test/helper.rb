# frozen_string_literal: true

require 'minitest/autorun'
require 'socket'
require 'tempfile'
require 'tmpdir'
require_relative '../lib/passivedns/client'

# A tiny HTTP server for exercising the providers without touching the network.
# It answers every request with the canned status and body, and remembers the requests it saw.
class FakeServer
  attr_reader :requests, :port

  def initialize(body, status: 200)
    @body = body
    @status = status
    @requests = []
    @server = TCPServer.new '127.0.0.1', 0
    @port = @server.addr[1]
    @thread = Thread.new { serve }
  end

  def url
    "http://127.0.0.1:#{@port}"
  end

  def close
    @thread.kill
    @server.close
  end

  private

  def serve
    loop do
      socket = @server.accept
      request = []
      while (line = socket.gets) && line != "\r\n"
        request << line.chomp
      end
      @requests << request
      socket.write "HTTP/1.1 #{@status} X\r\nContent-Length: #{@body.bytesize}\r\nConnection: close\r\n\r\n#{@body}"
      socket.close
    end
  end
end

# makes a result for the state tests
def make_result(query, answer, rrtype = 'A')
  PassiveDNS::PDNSResult.new 'test', 0.1, query, answer, rrtype, 60, Time.at(1_000_000), Time.at(2_000_000), 3, 'white'
end
