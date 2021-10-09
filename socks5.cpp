#include "socks5.hpp"

namespace socks5
{

std::string string_from_vector(std::vector<std::uint8_t> v)
{
    return std::string(v.begin(), v.end());
}

void print_byte_vector(const std::size_t& bytes, const std::vector<uint8_t>& client_buf)
{
    std::cerr << "[ " << std::flush;
    for (std::size_t i = 0; i < bytes; ++i)
        std::cout << std::hex << std::setw(4) << static_cast<int>(client_buf[i]) << ' ' << std::flush;
    std::cerr << ']' << std::endl;
}

Session::Session(ba_tcp::socket client_socket, std::size_t buffer_size, std::size_t timeout)
        : client_stream(std::move(client_socket)),
          remote_stream(make_strand(client_socket.get_executor())),
          client_buf(buffer_size),
          resolver(client_socket.get_executor()),
          buffer_size(buffer_size),
          timeout(timeout) {
}

bool Session::handshake(const ba::yield_context& yield, const std::shared_ptr<Session>& self)
{
    error_code ec;
    std::cerr << "Address: " << self->socket_to_string() << " | Endpoint: " << self->endpoint_to_string() << std::endl;

//    Client send greetings:
//    +----+----------+----------+
//    |VER | NMETHODS | METHODS  |
//    +----+----------+----------+
//    | 1  |    1     | 1 to 255 |
//    +----+----------+----------+

    self->client_stream.expires_after(self->timeout);
    std::size_t readed_bytes = ba::async_read(self->client_stream, ba::buffer(self->client_buf, 2), yield[ec]);

    if (ec)
    {
        if (ec != operation_aborted && (ec != eof))
            std::cerr << "Failed to read connection request: " << ec.message() << std::endl;
        return false;
    }
    std::cerr << "Read VER and NMETHODS: " << std::flush;
    print_byte_vector(readed_bytes, self->client_buf);

    if (self->client_buf[0] != SOCKS_VER)
    {
        std::cout << "Connection request with unsupported VER: " << unsigned(self->client_buf[0])
                  << std::endl;
        return false;
    }
    uint8_t num_methods = self->client_buf[1];
    self->client_stream.expires_after(self->timeout);

//    now we read supported methods
    readed_bytes = ba::async_read(self->client_stream, ba::buffer(self->client_buf, num_methods), yield[ec]);


//    o  X'00' NO AUTHENTICATION REQUIRED
//    o  X'01' GSSAPI
//    o  X'02' USERNAME/PASSWORD
//    o  X'03' to X'7F' IANA ASSIGNED
//    o  X'80' to X'FE' RESERVED FOR PRIVATE METHODS
//    o  X'FF' NO ACCEPTABLE METHODS

    std::cerr << "Read AUTH METHODS: " << std::flush;
    print_byte_vector(readed_bytes, self->client_buf);

    if (ec) {
        if (ec != operation_aborted && (ec != eof)) {
            std::cerr << "Failed to read connection request: " << ec.message() << std::endl;
        }
        return false;
    }

    // go through supported methods and try to find out: NO_AUTH.
    // If we didn't, handshake in connect answer will be AUTH_UNACCETPABLE
    for (uint8_t method = 0; method < num_methods; ++method)
    {
        if (self->client_buf[method] == AUTH_NONE) {
            self->connect_answer[1] = AUTH_NONE;
            break;
        }
    }

    //    server answers:
    //    +----+--------+
    //    |VER | METHOD |
    //    +----+--------+
    //    | 1  |   1    |
    //    +----+--------+
    // default connect_answer is 5 ff: ver5 and no acceptable auth. But if we found AUTH_NONE in client methods, send 5 0
    self->client_stream.expires_after(self->timeout);
    std::size_t writed_bytes = async_write(self->client_stream, ba::buffer(self->connect_answer, 2), yield[ec]);

    std::cerr << "Wrote VER and METHOD: [" << std::flush;
    for (std::size_t i = 0; i < writed_bytes; ++i)
        std::cerr << std::hex << unsigned(self->connect_answer[i]) << ' ' << std::flush;
    std::cerr << ']' << std::endl;

    // if we can't connect 'cause of unacceptable auth method, handshake will fail
    if (self->client_buf[1] == AUTH_UNACCEPTABLE) {
        std::cout << "Connection request with unsupported METHOD: "
                  << (uint8_t) self->client_buf[1]
                  << std::endl;
        return false;
    }

    if (ec) {
        if (ec != operation_aborted) {
            std::cerr << "Failed to write connection response: " << ec.message() << std::endl;
        }
        return false;
    }

//    The SOCKS client request is formed as follows:

//           +----+-----+-------+------+----------+----------+
//           |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
//           +----+-----+-------+------+----------+----------+
//           | 1  |  1  | X'00' |  1   | Variable |    2     |
//           +----+-----+-------+------+----------+----------+

//        Where:

//             o  VER    protocol version: X'05'
//             o  CMD
//                o  CONNECT X'01'
//                o  BIND X'02'
//                o  UDP ASSOCIATE X'03'
//             o  RSV    RESERVED
//             o  ATYP   address type of following address
//                o  IP V4 address: X'01'
//                o  DOMAINNAME: X'03'
//                o  IP V6 address: X'04'
//             o  DST.ADDR       desired destination address
//             o  DST.PORT desired destination port in network octet
//                order

    self->client_stream.expires_after(self->timeout);
    readed_bytes = ba::async_read(self->client_stream, ba::buffer(self->client_buf, 4), yield[ec]);

    std::cerr << "Read VER, CMD, ATYP: " << std::flush;
    print_byte_vector(readed_bytes, self->client_buf);

    if (ec) {
        if (ec != operation_aborted && (ec != eof)) {
            std::cerr << "Failed to read command request: " << ec.message() << std::endl;
        }
        return false;
    }
    if (self->is_command_request_valid())
    {
        if (self->client_buf[3] == 0x03)
        {
            self->client_stream.expires_after(self->timeout);
            readed_bytes = ba::async_read(self->client_stream, ba::buffer(self->client_buf, 1), yield[ec]);

            std::cerr << "ATYP is DOMAINNAME so read name length" << std::flush;
            print_byte_vector(readed_bytes, self->client_buf);

            if (ec) {
                if (ec != operation_aborted && (ec != eof)) {
                    std::cerr << "Failed to read command request: " << ec.message() << std::endl;
                }
                return false;
            }
            uint8_t domain_name_length = self->client_buf[0];
            self->client_stream.expires_after(self->timeout);
            readed_bytes = ba::async_read(self->client_stream, ba::buffer(self->client_buf, domain_name_length + 2), yield[ec]);

            std::cerr << "Read domain name: " << std::flush;
            print_byte_vector(readed_bytes, self->client_buf);

            if (ec) {
                if (ec != operation_aborted && (ec != eof)) {
                    std::cerr << "Failed to read command request: " << ec.message() << std::endl;
                }
                return false;
            }
            self->resolve_domain_name(yield, ec, domain_name_length);
        }
        else
        {
            self->client_stream.expires_after(self->timeout);
            readed_bytes = ba::async_read(self->client_stream, ba::buffer(self->client_buf, 6), yield[ec]);
            std::cerr << "Read ipv4 address and port: " << std::flush;
            print_byte_vector(readed_bytes, self->client_buf);

            if (ec) {
                if (ec != operation_aborted && (ec != eof)) {
                    std::cerr << "Failed to read command request: " << ec.message() << std::endl;
                }
                return false;
            }
            self->endpoint = ba_tcp::tcp::endpoint(address_v4(big_to_native(*((uint32_t *) &self->client_buf[0]))),
                                     big_to_native(*((uint16_t *) &self->client_buf[4])));
        }
    }
    if (self->command_answer[1] == 0x00) {
        self->remote_stream.expires_after(self->timeout);
        self->remote_stream.async_connect(self->endpoint, yield[ec]);
        if (ec) {
            //TODO: Specify error code
            std::cerr << "Failed to connect to remote server: " << ec.message() << std::endl;
            self->command_answer[1] = 0x03;
        }
    }
    if (self->command_answer[1] == 0x00) {
        uint32_t real_local_ip = big_to_native(
                self->remote_stream.socket().local_endpoint().address().to_v4().to_uint());
        uint16_t real_local_port = big_to_native(self->remote_stream.socket().local_endpoint().port());
        std::memcpy(&self->command_answer[4], &real_local_ip, 4);
        std::memcpy(&self->command_answer[8], &real_local_port, 2);
    }
    self->client_stream.expires_after(self->timeout);
    async_write(self->client_stream, ba::buffer(self->command_answer, 10), yield[ec]);
    if (ec) {
        if (ec != operation_aborted) {
            std::cerr << "Failed to write command response" << std::endl;
        }
        return false;
    }
    return true;
}

void Session::go() {
    auto self(shared_from_this());
    spawn(client_stream.get_executor(), [self](const ba::yield_context &yield) {

        if (!self->handshake(yield, self))
        {
            std::cerr << "Handshake failed" << std::endl;
            return;
        }

        boost::asio::spawn(self->client_stream.get_executor(), [self](const ba::yield_context &yield) {
            self->echo(self->client_stream, self->remote_stream, yield, self);
        });
        self->echo(self->remote_stream, self->client_stream, yield, self);

    });
}

void
Session::echo(beast::tcp_stream &src, beast::tcp_stream &dst, const ba::yield_context &yield, const std::shared_ptr<Session> &self) {
    error_code ec;
    std::vector<uint8_t> buf(buffer_size);
    for (;;) {
        std::size_t n = src.async_read_some(ba::buffer(buf), yield[ec]);
        if (ec) {
            return;
        }
        dst.async_write_some(ba::buffer(buf, n), yield[ec]);
        if (ec) {
            return;
        }
    }
}

bool Session::is_command_request_valid() {
    if (client_buf[2] != 0x00) {
        std::cout << "Invalid command request" << std::endl;
        command_answer[1] = 0xFF;
        return false;
    }
    if (client_buf[0] != 0x05) {
        std::cerr << "Command request with unsupported VER: " << unsigned(client_buf[0]) << std::endl;
        command_answer[1] = 0xFF;
        return false;
    }
    if (client_buf[1] != 0x01) {
        std::cout << "Command request with unsupported CMD: " << unsigned(client_buf[1]) << std::endl;
        command_answer[1] = COMMAND_NOT_SUPPORTED;
        return false;
    }
    if (client_buf[3] != 0x01 && client_buf[3] != 0x03) {
        std::cout << "Command request with unsupported ATYP: " << unsigned(client_buf[3]) << std::endl;
        command_answer[1] = ADDRESS_TYPE_NOT_SUPPORTED;
        return false;
    }
    return true;
}

void Session::resolve_domain_name(const ba::yield_context &yield, error_code ec, uint8_t domain_name_length) {
    std::string remote_host(client_buf.begin(), client_buf.begin() + domain_name_length);
    std::string remote_port = std::to_string(big_to_native(*((uint16_t *) &client_buf[domain_name_length])));
    ba_tcp::resolver::query query(remote_host, remote_port);
    ba_tcp::resolver::iterator endpoint_iterator = resolver.async_resolve(query, yield[ec]);
    if (ec) {
        std::cout << "Failed to resolve domain name" << std::endl;
        //TODO: Specify error code
        command_answer[1] = 0x03;
        return;
    }
    endpoint = *endpoint_iterator;
}

std::string Session::socket_to_string() const {
    beast::error_code ec;
    ba_tcp::endpoint endpoint = client_stream.socket().remote_endpoint(ec);
    if (ec) {
        return "closed socket";
    }
    return endpoint.address().to_string() + ":" + std::to_string(big_to_native(endpoint.port()));

}

std::string Session::endpoint_to_string() const {
    return endpoint.address().to_string() + " " +
           std::to_string(endpoint.port());
}

} // socks5
