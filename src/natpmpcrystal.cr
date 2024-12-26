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
    enum OP : UInt8
      UDP = 1_u8
      TCP = 2_u8
    end

    property vers : UInt8 = 0_u8
    property op : UInt8
    property reserved : UInt16 = 0_u16
    property internal_port : UInt16
    property external_port : UInt16
    property lifetime : UInt32

    def initialize(@op = UDP, @internal_port = nil, @external_port = nil, @lifetime = 0)
    end
  end

  # private record MappingPacket,
  #   vers : UInt8 = 0,
  #   op : UInt8 = 0,
  #   reserved : UInt16 = 0,
  #   internal_port : UInt16 = 0,
  #   external_port : UInt16 = 0,
  #   lifetime : UInt32 = 0,

  class Client
    @client : UDPSocket
    @gateway_ip : String

    # Overload
    def initialize(gateway_ip : URI)
      initialize(gateway_ip.path)
    end

    def initialize(gateway_ip : String)
      @gateway_ip = gateway_ip
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
      @client.receive(msg)
      vers = (msg[0])
      op = (msg[1])
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

    # def request_mapping(op : Int32, internal_port : Int32, external_port : Int32, lifetime : Int32)
    #   begin
    #   request_mapping(op.to_u8, internal_port.to_u16, external_port.to_u16, lifetime.to_u32)
    #   rescue ex
    #     puts ex.message
    #     exit(1)
    #   end
    # end

    def request_mapping(op : UInt8, internal_port : UInt16, external_port : UInt16, lifetime : UInt32)
      request = MappingPacket.new(op, internal_port, external_port, lifetime)
    end

    private def get_result_code(msg)
      # Responses always contain a
      # 16-bit result code in network byte order
      return IO::ByteFormat::BigEndian.decode(UInt16, msg)
    end

    # Seconds Since Start of Epoch
    private def get_epoch(msg)
      # epoch : Int32 = 0
      # msg.each_with_index do |byte, index|
      #   epoch |= (byte.to_i << (8 * (msg.size - 1 - index)))
      # end

      # Responses also contain a 32-bit unsigned integer
      # corresponding to the number of seconds since the NAT gateway was
      # rebooted or since its port mapping state was otherwise reset.
      return IO::ByteFormat::BigEndian.decode(UInt32, msg)
    end

    private def get_ip_address(msg)
      "#{msg[0]}.#{msg[1]}.#{msg[2]}.#{msg[3]}"
    end
  end
end

client = NatPMP::Client.new("192.168.1.1")
pp client.send_public_address_request
xd = client.send_public_address_request_raw
pp xd

request = client.request_mapping(NatPMP::MappingPacket::OP::UDP.value, 25580_u16, 25580_u16, 0_u32)

# request2 = client.request_mapping(1, 255802, 25580, 0)

pp request
