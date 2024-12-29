require "socket"
require "benchmark"

module NatPMP
  enum ResultCodes
    SUCCESS                   = 0
    UNSUPPORTED_VERSION       = 1
    NOT_AUTHORIZED_OR_REFUSED = 2
    NETWORK_FAILURE           = 3
    OUT_OF_RESOURCES          = 4
    UNSUPPORTED_OPCODE        = 5
  end

  enum OP : UInt8
    UDP = 1_u8
    TCP = 2_u8
  end

  struct MappingPacket
    @vers : UInt8 = 0_u8
    @op : UInt8 = OP::UDP.value
    @reserved : UInt16 = 0_u16
    @internal_port : UInt16
    @external_port : UInt16
    @lifetime : UInt32 = 0_u32

    def initialize(@internal_port, @external_port, @lifetime = 0, @op = UDP)
      unless [1, 2].include?(@op)
        raise ArgumentError, "Operation should be either '1_u8' for UDP or '2_u8' for TCP (default: UDP)"
      end
    end

    def initialize(@internal_port, @external_port)
    end

    def to_io
      io = IO::Memory.new(12)
      io.write_bytes(@vers, IO::ByteFormat::BigEndian)
      io.write_bytes(@op, IO::ByteFormat::BigEndian)
      io.write_bytes(@reserved, IO::ByteFormat::BigEndian)
      io.write_bytes(@internal_port, IO::ByteFormat::BigEndian)
      io.write_bytes(@external_port, IO::ByteFormat::BigEndian)
      io.write_bytes(@lifetime, IO::ByteFormat::BigEndian)
      return io
    end

    def to_slice
      slice = uninitialized UInt8[12]
      IO::ByteFormat::BigEndian.encode(@vers, v = Bytes.new(1))
      IO::ByteFormat::BigEndian.encode(@op, o = Bytes.new(1))
      # IO::ByteFormat::BigEndian.encode(@reserved, r = Bytes.new(2))
      IO::ByteFormat::BigEndian.encode(@internal_port, i = Bytes.new(2))
      IO::ByteFormat::BigEndian.encode(@external_port, e = Bytes.new(2))
      IO::ByteFormat::BigEndian.encode(@lifetime, l = Bytes.new(4))
      slice[0] = v[0]
      slice[1] = o[0]
      slice[2] = 0 # RESERVED
      slice[3] = 0 # RESERVED
      slice[4] = i[0]
      slice[5] = i[1]
      slice[6] = e[0]
      slice[7] = e[1]
      slice[8] = l[0]
      slice[9] = l[1]
      slice[10] = l[2]
      slice[11] = l[3]
      return slice
    end
  end

  class Client
    @client : UDPSocket
    @gateway_ip : String

    # Overload
    def initialize(gateway_ip : URI)
      initialize(gateway_ip.path)
    end

    def initialize(@gateway_ip : String)
      @client = UDPSocket.new
      # A given host may have more than one independent
      # NAT-PMP client running at the same time, and address announcements
      # need to be available to all of them.  Clients should therefore set
      # the SO_REUSEPORT option or equivalent in order to allow other
      # processes to also listen on port 5350.
      @client.reuse_port = true
      # Additionally, implementers
      # have encountered issues when one or more processes on the same device
      # listen to port 5350 on *all* addresses.  Clients should therefore
      # bind specifically to 224.0.0.1:5350, not to 0.0.0.0:5350.
      # @client.bind("224.0.0.1", 5350)
      connect()
    end

    def connect
      # @client.join_group(Socket::IPAddress.new("224.0.0.1", 5351))
      @client.connect(@gateway_ip, 5351)
    end

    def send_public_address_request_raw : Bytes
      @client.send("\x00\x00")
      msg = Bytes.new(12)
      @client.receive(msg)
      return msg
    end

    def send_public_address_request
      @client.send("\x00\x00")
      msg = Bytes.new(12)
      @client.read_timeout = 250.milliseconds
      8.times do |i|
        begin
          @client.receive(msg)
          break
        rescue IO::TimeoutError
          # If no
          # NAT-PMP response is received from the gateway after 250 ms, the
          # client retransmits its request and waits 500 ms.  The client SHOULD
          # repeat this process with the interval between attempts doubling each
          # time.
          @client.read_timeout = @client.read_timeout.not_nil!*2
          next
        rescue
          raise "The gateway '#{@gateway_ip}' does not support NAT-PMP"
          break
        end
      end

      vers = msg[0]
      op = msg[1]
      result_code = get_result_code(msg[2..3])
      epoch = get_epoch(msg[4..7])

      # If the result code is non-zero, the value of the External
      # IPv4 Address field is undefined (MUST be set to zero on transmission,
      # and MUST be ignored on reception).
      if result_code != 0
        ip_address = nil
      else
        ip_address = get_ip_address(msg[8..11])
      end
      return vers, op, result_code, epoch, ip_address
    end

    def request_mapping(internal_port : UInt16, external_port : UInt16, lifetime : Uint32, operation : UInt8)
      request = MappingPacket.new(internal_port, external_port, lifetime, operation)
      msg = Bytes.new(16)
      @client.receive(msg)
      vers = msg[0]
      op = msg[1]
      result_code = get_result_code(msg[2..3])
      epoch = get_epoch(msg[4..7])
      internal_port = get_port(msg[8..9])
      external_port = get_port(msg[10..11])
      lifetime = get_lifetime(msg[12..15])
      return vers, op, result_code, epoch, internal_port, external_port, lifetime
    end

    private def get_result_code(msg)
      # Responses always contain a
      # 16-bit result code in network byte order
      return IO::ByteFormat::BigEndian.decode(UInt16, msg)
    end

    # Seconds Since Start of Epoch
    private def get_epoch(msg)
      # Responses also contain a 32-bit unsigned integer
      # corresponding to the number of seconds since the NAT gateway was
      # rebooted or since its port mapping state was otherwise reset.
      return IO::ByteFormat::BigEndian.decode(UInt32, msg)
    end

    private def get_port(msg)
      return IO::ByteFormat::BigEndian.decode(UInt16, msg)
    end

    private def get_ip_address(msg)
      "#{msg[0]}.#{msg[1]}.#{msg[2]}.#{msg[3]}"
    end

  end
end

# client = NatPMP::Client.new("192.168.0.1")
# pp client.send_public_address_request
pp mapping_packet = NatPMP::MappingPacket.new(25555,25555)

Benchmark.ips do |x|
  x.report("bytes") do
    mapping_packet.to_io
  end

  x.report("staticarray") do
    # pp mapping_packet.to_io.to_slice
    mapping_packet.to_slice
  end

  x.report("staticarray to io") do
    # pp mapping_packet.to_io.to_slice
    mapping_packet.to_slice
  end
end

pp typeof(mapping_packet)

# xd = client.send_public_address_request_raw
# pp xd

# request = client.request_mapping(25580, 25580)

# request2 = client.request_mapping(1, 255802, 25580, 0)

# pp request
