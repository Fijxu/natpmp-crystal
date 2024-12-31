# natpmp-crystal

Work in progress implementation of RFC 6886 **NAT Port Mapping Protocol (NAT-PMP)**, client side.

Since RFC 6886 is a pretty simple protocol, it should be ready to use to requests mappings

## Installation

1. Add the dependency to your `shard.yml`:

   ```yaml
   dependencies:
     natpmp-crystal:
       github: fijxu/natpmp-crystal
   ```

2. Run `shards install`

## Usage

```crystal
require "natpmp"

# Create NAT-PMP client, replace the IP by the IP of your
# gateway
client = NatPMP::Client.new("192.168.1.1")
# Public address request
client.send_external_address_request # => {0, 128, 0, 22758, "104.0.0.0"}
client.send_external_address_request_as_bytes # => Bytes[0, 128, 0, 0, 0, 0, 88, 230, 104, 0, 0, 0]

# Maps the internal port 25565 to external port 25565, TCP
client.request_mapping(25565, 25565, 2) # => {0, 130, 0, 22758, 25565, 25565, 7200}
# Destroys the mapping with internal port 25565, TCP
client.destroy_mapping(25565, 2) # => {0, 130, 0, 22758, 25565, 0, 0}

# Maps the internal port 22000 to external port 22000, UDP
client.request_mapping(22000, 22000, 1) # => {0, 129, 0, 22758, 22000, 22000, 7200}
# Destroys the mapping with internal port 22000, UDP
client.destroy_mapping(22000, 1) # => {0, 129, 0, 22758, 22000, 0, 0}
```

## Contributing

1. Fork it (<https://github.com/fijxu/natpmp-crystal/fork>)
2. Create your feature branch (`git checkout -b my-new-feature`)
3. Commit your changes (`git commit -am 'Add some feature'`)
4. Push to the branch (`git push origin my-new-feature`)
5. Create a new Pull Request

## Contributors

- [Fijxu](https://github.com/fijxu) - creator and maintainer
