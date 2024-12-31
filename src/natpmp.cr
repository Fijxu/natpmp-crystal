require "socket"

module NatPMP
  # Result codes defined by the RFC 6886
  #
  # [RFC 6886 - 3.5.  Result Codes](https://datatracker.ietf.org/doc/html/rfc6886#section-3.5)
  enum ResultCodes
    SUCCESS                   = 0
    UNSUPPORTED_VERSION       = 1
    NOT_AUTHORIZED_OR_REFUSED = 2
    NETWORK_FAILURE           = 3
    OUT_OF_RESOURCES          = 4
    UNSUPPORTED_OPCODE        = 5
  end

  # Opcodes defined by the RFC 6886
  #
  # *"Otherwise, if the opcode in the request is less than 128, but is not a supported opcode **(currently 0, 1, or 2)**"*
  #
  # [RFC 6886 - 3.5.  Result Codes](https://datatracker.ietf.org/doc/html/rfc6886#section-3.5)
  enum OP : UInt8
    NOOP = 0_u8
    UDP  = 1_u8
    TCP  = 2_u8
  end

  # You can use this struct to craft your own mapping packets in case you want
  # to handle it all by yourself.
  #
  # ```
  # # This creates a mapping that you can use to send trough a Socket
  # packet_io = NatPMP::MappingPacket.new(25565, 25565, 1, 3600).to_io
  # packet_slice = NatPMP::MappingPacket.new(25565, 25565, 1, 3600).to_slice
  # ```
  struct MappingPacket
    @vers : UInt8 = 0_u8
    @op : UInt8
    @reserved : UInt16 = 0_u16
    @internal_port : UInt16
    @external_port : UInt16
    @lifetime : UInt32

    def initialize(@internal_port, @external_port, @op = 1, @lifetime = 7200)
      raise ArgumentError.new("operation should be either 1_u8 for UDP or 2_u8 for TCP") if ![1, 2].includes?(@op)
    end

    # Converts the struct instance variables to IO.
    def to_io
      io = IO::Memory.new(12)
      io.write_bytes(@vers, IO::ByteFormat::BigEndian)
      io.write_bytes(@op, IO::ByteFormat::BigEndian)
      io.write_bytes(@reserved, IO::ByteFormat::BigEndian)
      io.write_bytes(@internal_port, IO::ByteFormat::BigEndian)
      io.write_bytes(@external_port, IO::ByteFormat::BigEndian)
      io.write_bytes(@lifetime, IO::ByteFormat::BigEndian)
      io
    end

    # Converts the struct instance variables to an StaticArray.
    #
    # Side Note: This is not actually a Slice, it's an StaticArray so I don't
    # think this member function should be called like this.
    def to_slice
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
      slice
    end
  end

  class Client
    @socket : UDPSocket
    @gateway_ip : String

    def initialize(gateway_ip : URI, autoconnect : Bool = true)
      initialize(gateway_ip.path, autoconnect)
    end

    # Creates a new NAT-PMP Client, it's only able to connect trough IPV4 so
    # if you supply a IPV6 address, it will fail;
    # By default, it connects automatically to the NAT-PMP server, you can
    # change this by setting `autoconnect` to false like this:
    # `client = NatPMP::Client.new("192.168.1.1", false)`, that way, you can
    # change the socket properties like `client.@socket.bind` to your liking
    # before connecting.
    #
    # ```
    # client = NatPMP::Client.new("192.168.1.1")
    # ```
    def initialize(@gateway_ip : String, autoconnect : Bool = true)
      # The specification is IPV4 only!
      @socket = UDPSocket.new(Socket::Family::INET)
      @socket.reuse_port = true
      @socket.reuse_address = true
      @socket.bind 5350
      if autoconnect
        connect()
      end
    end

    # Connects to the NAT-PMP server, you don't need to call this function
    # unless you have setted `autoconnect` is false on the constructor.
    def connect : Nil
      @socket.connect(@gateway_ip, 5351)
    end

    private def send_external_address_request_ : Bytes
      @socket.send("\x00\x00")
      msg = Bytes.new(12)
      @socket.read_timeout = 250.milliseconds

      8.times do |i|
        begin
          @socket.receive(msg)
          break
        rescue IO::TimeoutError
          @socket.read_timeout = @socket.read_timeout.not_nil!*2
          next
        rescue
          raise "The gateway '#{@gateway_ip}' does not support NAT-PMP"
          break
        end
      end

      msg
    end

    # Returns the external address response as a `Slice(UInt8)`
    #
    # ```
    # client.send_external_address_request_as_bytes # => Bytes[0, 128, 0, 0, 0, 0, 88, 230, 104, 0, 0, 0]
    # ```
    def send_external_address_request_as_bytes : Bytes
      msg = send_external_address_request_
      msg
    end

    # Returns the external address response as a `Tuple(UInt8, UInt8, UInt16, UInt32, String | Nil)`
    #
    # ```
    # res = client.send_external_address_request # => {0, 128, 0, 177060, "104.0.0.0"}
    # version = res[0]
    # operation = res[1]
    # result_code = res[2]
    # epoch = res[3]
    # external_address = res[4]
    # ```
    def send_external_address_request : Tuple(UInt8, UInt8, UInt16, UInt32, String | Nil)
      msg = send_external_address_request_

      vers : UInt8 = msg[0]
      op : UInt8 = msg[1]
      result_code = decode_msg(UInt16, msg[2..3])
      epoch = decode_msg(UInt32, msg[4..7])

      if result_code != 0
        ip_address = nil
      else
        ip_address = get_ip_address(msg[8..11])
      end
      return vers, op, result_code, epoch, ip_address
    end

    # Requests a mapping to the NAT-PMP server
    #
    # More details about how requesting a mapping works here: [RFC 6886 - 3.3. Requesting a Mapping](https://datatracker.ietf.org/doc/html/rfc6886#section-3.3)
    # ```
    # # Maps the internal port 25565 to external port 25565, TCP, with a lifetime
    # # of 7200 seconds (the default defined by the RFC)
    # client.request_mapping(25565, 25565, 2) # => {0, 130, 0, 22758, 25565, 25565, 7200}
    # # The same as above, but with a lifetime of 60 seconds
    # client.request_mapping(25565, 25565, 2, 60) # => {0, 130, 0, 22758, 25565, 25565, 60}
    # # Maps the internal port 25565 to external port 25565, UDP, with a lifetime
    # # of 7200 seconds (the default defined by the RFC)
    # client.request_mapping(25565, 25565, 1) # => {0, 129, 0, 22758, 25565, 25565, 7200}
    # # The same as above, but with a lifetime of 60 seconds
    # client.request_mapping(25565, 25565, 1, 60) # => {0, 129, 0, 22758, 25565, 25565, 60}
    # ```
    def request_mapping(internal_port : UInt16, external_port : UInt16, operation : UInt8, lifetime : UInt32 = 7200) : Tuple(UInt8, UInt8, UInt16, UInt32, UInt16, UInt16, UInt32)
      request = MappingPacket.new(internal_port, external_port, operation, lifetime).to_slice
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

    # Destroys a mapping in the NAT-PMP server
    #
    # More details about how destroying a mapping works here: [RFC 6886 - 3.4. Destoying a Mapping](https://datatracker.ietf.org/doc/html/rfc6886#section-3.4)
    # ```
    # # Destroys the mapping with internal port 25565, TCP
    # client.destroy_mapping(25565, 2) # => {0, 130, 0, 22758, 25565, 0, 0}
    # # Destroys the mapping with internal port 25565, UDP
    # client.destroy_mapping(25565, 1) # => {0, 130, 0, 22758, 25565, 0, 0}
    # ```
    def destroy_mapping(internal_port : UInt16, operation : UInt8) : Tuple(UInt8, UInt8, UInt16, UInt32, UInt16, UInt16, UInt32)
      request = MappingPacket.new(internal_port, 0, operation, 0).to_slice
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
