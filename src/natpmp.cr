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

  struct MappingPacket
    @vers : UInt8 = 0_u8
    @op : UInt8
    @reserved : UInt16 = 0_u16
    @internal_port : UInt16
    @external_port : UInt16
    @lifetime : UInt32 = 0_u32

    def initialize(@internal_port, @external_port, @lifetime = 7200, @op = 1)
      raise ArgumentError.new("operation should be either 1_u8 for UDP or 2_u8 for TCP") if ![1, 2].includes?(@op)
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
      # This is not actually a Slice, it's an StaticArray so I don't
      # think this member function should be called like this.
      slice = uninitialized UInt8[12]
      IO::ByteFormat::BigEndian.encode(@op, o = Bytes.new(1))
      IO::ByteFormat::BigEndian.encode(@internal_port, i = Bytes.new(2))
      IO::ByteFormat::BigEndian.encode(@external_port, e = Bytes.new(2))
      IO::ByteFormat::BigEndian.encode(@lifetime, l = Bytes.new(4))
      slice[0] = 0 # vers is always 0
      slice[1] = o[0]
      slice[2] = 0 # RESERVED, always 0
      slice[3] = 0 # RESERVED, always 0
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
    @socket : UDPSocket
    @gateway_ip : String

    # Overload
    def initialize(gateway_ip : URI)
      initialize(gateway_ip.path)
    end

    def initialize(@gateway_ip : String, autoconnect : Bool = true)
      # The specification is IPV4 only!
      @socket = UDPSocket.new(Socket::Family::INET)
      # A given host may have more than one independent
      # NAT-PMP client running at the same time, and address announcements
      # need to be available to all of them.  Clients should therefore set
      # the SO_REUSEPORT option or equivalent in order to allow other
      # processes to also listen on port 5350.
      @socket.reuse_port = true
      @socket.reuse_address = true
      # Additionally, implementers
      # have encountered issues when one or more processes on the same device
      # listen to port 5350 on *all* addresses.  Clients should therefore
      # bind specifically to 224.0.0.1:5350, not to 0.0.0.0:5350.
      @socket.bind 5350
      if autoconnect
        connect()
      end
    end

    def connect
      # @socket.join_group(Socket::IPAddress.new("224.0.0.1", 5351))
      @socket.connect(@gateway_ip, 5351)
    end

    def send_public_address_request_raw : Bytes
      @socket.send("\x00\x00")
      msg = Bytes.new(12)
      @socket.receive(msg)
      return msg
    end

    def send_public_address_request
      @socket.send("\x00\x00")
      msg = Bytes.new(12)
      @socket.read_timeout = 250.milliseconds

      8.times do |i|
        begin
          @socket.receive(msg)
          break
        rescue IO::TimeoutError
          # If no
          # NAT-PMP response is received from the gateway after 250 ms, the
          # client retransmits its request and waits 500 ms.  The client SHOULD
          # repeat this process with the interval between attempts doubling each
          # time.
          @socket.read_timeout = @socket.read_timeout.not_nil!*2
          next
        rescue
          raise "The gateway '#{@gateway_ip}' does not support NAT-PMP"
          break
        end
      end

      vers : UInt8 = msg[0]
      op : UInt8 = msg[1]
      result_code = decode_msg(UInt16, msg[2..3])
      epoch = decode_msg(UInt32, msg[4..7])

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

    def request_mapping(internal_port : UInt16, external_port : UInt16, operation : UInt8, lifetime : UInt32 = 7200)
      request = MappingPacket.new(internal_port, external_port, lifetime, operation).to_slice
      msg = Bytes.new(16)
      @socket.send(request)
      @socket.receive(msg)

      vers : UInt8 = msg[0]
      op : UInt8 = msg[1]
      result_code = decode_msg(UInt16, msg[2..3])
      epoch = decode_msg(UInt32, msg[4..7])
      internal_port = decode_msg(UInt16, msg[8..9])
      external_port = decode_msg(UInt16, msg[10..11])
      lifetime = decode_msg(UInt32, msg[12..15])

      return vers, op, result_code, epoch, internal_port, external_port, lifetime
    end

    # https://datatracker.ietf.org/doc/html/rfc6886#section-3.4
    def destroy_mapping(internal_port : UInt16, operation : UInt8)
      request = MappingPacket.new(internal_port, 0, 0, operation).to_slice
      msg = Bytes.new(16)
      @socket.send(request)
      @socket.receive(msg)

      vers : UInt8 = msg[0]
      op : UInt8 = msg[1]
      result_code = decode_msg(UInt16, msg[2..3])
      epoch = decode_msg(UInt32, msg[4..7])
      internal_port = decode_msg(UInt16, msg[8..9])
      external_port = decode_msg(UInt16, msg[10..11])
      lifetime = decode_msg(UInt32, msg[12..15])

      return vers, op, result_code, epoch, internal_port, external_port, lifetime
    end

    private macro decode_msg(type, msg)
      IO::ByteFormat::BigEndian.decode({{type}}, {{msg}})
    end

    private def get_ip_address(msg)
      "#{msg[0]}.#{msg[1]}.#{msg[2]}.#{msg[3]}"
    end
  end
end
