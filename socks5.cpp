#include "socks5.hpp"

#include <sstream>

namespace study
{

template<typename T>
void print_byte_sequence(std::size_t bytes, const T& buf, const std::string& action)
{
    std::stringstream ss;
    ss << action << ": [ ";
    for (std::size_t i = 0; i < bytes; ++i)
    {
        ss << std::hex << std::internal << std::setfill('0')
           << std::setw(2) << (0xff & static_cast<int>(buf[i])) << ' ';
    }
    ss << ']';
    BOOST_LOG_TRIVIAL(trace) << ss.str();
}

template<typename T>
void print_str_byte_sequence(std::size_t bytes, const T& buf, const std::string& action)
{
    std::string_view str(reinterpret_cast<const char*>(buf.data()), bytes);
    BOOST_LOG_TRIVIAL(trace) << action << ": " << str;
}

bool check_ec(error_code ec, const std::string& ec_text = "Fail: ")
{
    if (!ec)
        return true;
    BOOST_LOG_TRIVIAL(error) << ec_text << ec.message();
    return false;
}

namespace socks5
{

Session::Session(tcp_socket client_socket, std::size_t buffer_size, std::size_t timeout)
        : client_stream(std::move(client_socket)),
          remote_stream(make_strand(client_socket.get_executor())),
          client_buf(buffer_size),
          resolver(client_socket.get_executor()),
          buffer_size(buffer_size),
          timeout(timeout)
{}

bool Session::handshake(const ba::yield_context& yield, const std::shared_ptr<Session>& self)
{
    error_code ec;
    BOOST_LOG_TRIVIAL(trace) << "Local address: " << self->socket_to_string() << " | Endpoint: " << self->endpoint_to_string() << std::endl;

//---------------------------------------------GREETINGS-------------------------------------------------------------

//    Client send greetings:
//    +----+----------+----------+
//    |VER | NMETHODS | METHODS  |
//    +----+----------+----------+
//    | 1  |    1     | 1 to 255 |
//    +----+----------+----------+
//     X'00' NO AUTHENTICATION REQUIRED
//     X'01' GSSAPI
//     X'02' USERNAME/PASSWORD
//     X'03' to X'7F' IANA ASSIGNED
//     X'80' to X'FE' RESERVED FOR PRIVATE METHODS
//     X'FF' NO ACCEPTABLE METHODS

//    server answers:
//    +----+--------+
//    |VER | METHOD |
//    +----+--------+
//    | 1  |   1    |
//    +----+--------+

    self->client_stream.expires_after(self->timeout);
    std::size_t readed_bytes = ba::async_read(self->client_stream, ba::buffer(self->client_buf, 2), yield[ec]);
    if (!check_ec(ec, "Fail in reading client greetings (ver and nmeths): ")) return false;

    print_byte_sequence<std::vector<byte_t>>(readed_bytes, self->client_buf, "Read VER and NMETHODS");

    if (self->client_buf[0] != SOCKS_VER)
    {
        BOOST_LOG_TRIVIAL(error) << "Unsupported SOCKS version request: " << unsigned(self->client_buf[0]);
        return false;
    }

    byte_t num_methods = self->client_buf[1];
    self->client_stream.expires_after(self->timeout);
    readed_bytes = ba::async_read(self->client_stream, ba::buffer(self->client_buf, num_methods), yield[ec]);
    if(!check_ec(ec, "Fail in reading client greetings (methods): ")) return false;

    print_byte_sequence<std::vector<byte_t>>(readed_bytes, self->client_buf, "Read AUTH METHODS");

    // go through supported methods and try to find out: NO_AUTH.
    // If we didn't, it will will be AUTH_UNACCETPABLE (default) in connect_answer
    for (byte_t method = 0; method < num_methods; ++method)
    {
        if (self->client_buf[method] == AUTH_NONE)
        {
            self->connect_answer[1] = AUTH_NONE;
            break;
        }
    }

    self->client_stream.expires_after(self->timeout);
    std::size_t writed_bytes = async_write(self->client_stream, ba::buffer(self->connect_answer, 2), yield[ec]);

    if(!check_ec(ec, "Fail to write answer with ver and method: ")) return false;

    print_byte_sequence(writed_bytes, connect_answer, "Wrote VER and METHOD");

    // After writing to client, we fail handshake if there was no acceptable AUTH
    if (self->client_buf[1] == AUTH_UNACCEPTABLE)
    {
        std::cout << "Connection request with unsupported AUTH METHOD: "
                  << unsigned(self->client_buf[1])
                  << std::endl;
        return false;
    }


//----------------------------------------REQUEST---------------------------------------------------

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

//    The server evaluates the request, and returns a reply formed as follows:

//           +----+-----+-------+------+----------+----------+
//           |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
//           +----+-----+-------+------+----------+----------+
//           | 1  |  1  | X'00' |  1   | Variable |    2     |
//           +----+-----+-------+------+----------+----------+

    self->client_stream.expires_after(self->timeout);
    readed_bytes = ba::async_read(self->client_stream, ba::buffer(self->client_buf, 4), yield[ec]);
    if(!check_ec(ec, "Fail in reading client request with VER, CMD, RSV and ATYP: ")) return false;

    print_byte_sequence(readed_bytes, self->client_buf, "Read VER, CMD, ATYP");

    // Checking VER, CMD, ATYP and read destination endpoint
    if (self->is_command_request_valid())
    {
        if (self->client_buf[3] == ATYP_DOMAINNAME)
        {
            self->client_stream.expires_after(self->timeout);
            ba::async_read(self->client_stream, ba::buffer(self->client_buf, 1), yield[ec]);
            if(!check_ec(ec, "reading domain name length: ")) return false;

            byte_t domain_name_length = self->client_buf[0];
            self->client_stream.expires_after(self->timeout);
            ba::async_read(self->client_stream, ba::buffer(self->client_buf, domain_name_length + 2), yield[ec]);
            if(!check_ec(ec, "reading domain name: ")) return false;

            self->displayed_address = std::string(self->client_buf.begin(), self->client_buf.begin() + domain_name_length);
//            std::string str_port(self->client_buf.begin() + domain_name_length, self->client_buf.end());

            std::uint16_t port;
            std::memcpy(&port, client_buf.data() + domain_name_length, 2);
            std::string str_port = std::to_string(boost::endian::big_to_native(port));

            self->displayed_address += std::string(":") + str_port;
            BOOST_LOG_TRIVIAL(trace) << "Read domain name: " << self->displayed_address;

            self->resolve_domain_name(yield, ec, domain_name_length);
        }
        else // 'cause of logic is_command_request_valid always ATYP_IPV4
        {
            self->client_stream.expires_after(self->timeout);
            ba::async_read(self->client_stream, ba::buffer(self->client_buf, 6), yield[ec]);

            if(!check_ec(ec, "reading ip4 address and port: ")) return false;

            self->endpoint = boost_endpoint(boost_ipv4(boost::endian::big_to_native(*((uint32_t *) &self->client_buf[0]))),
                                                       boost::endian::big_to_native(*((uint16_t *) &self->client_buf[4])));

            self->displayed_address = self->endpoint_to_string();

            BOOST_LOG_TRIVIAL(trace) << "Readed endpoint: " << self->displayed_address;
        }
    }

//------------------------------------------CONNECTION--WITH--REMOTE-----------------------------------------------

    // command_answer may have non-default SUCCEEDED value 'cause of checking previous client request
    if (self->command_answer[1] == SUCCEEDED)
    {
        self->remote_stream.expires_after(self->timeout);
        self->remote_stream.async_connect(self->endpoint, yield[ec]);

        if(!check_ec(ec, "Async connection to remote server: "))
        {
            self->command_answer[1] = NETWORK_UNREACHABLE;
            BOOST_LOG_TRIVIAL(warning) << "Can't connect to " << self->endpoint_to_string();
        }
        else
        {
            uint32_t real_local_ip = boost::endian::big_to_native(self->remote_stream.socket().local_endpoint().address().to_v4().to_uint());
            uint16_t real_local_port = boost::endian::big_to_native(self->remote_stream.socket().local_endpoint().port());
            std::memcpy(&self->command_answer[4], &real_local_ip, 4);
            std::memcpy(&self->command_answer[8], &real_local_port, 2);

            std::string client_ip = self->client_stream.socket().local_endpoint().address().to_string();
            std::string client_port = std::to_string(boost::endian::big_to_native(self->client_stream.socket().local_endpoint().port()));
            BOOST_LOG_TRIVIAL(info) << "Connected: " << client_ip << ':' << client_port << " to " << self->displayed_address;
        }
    }

    self->client_stream.expires_after(self->timeout);
    async_write(self->client_stream, ba::buffer(self->command_answer, 10), yield[ec]);

    if(!check_ec(ec, "writing command response: ")) return false;

    return true;
}

void Session::go()
{
    auto self(shared_from_this());
    spawn(client_stream.get_executor(), [self](const ba::yield_context &yield)
    {

        if (!self->handshake(yield, self))
        {
            std::cerr << "Handshake failed" << std::endl;
            return;
        }

        boost::asio::spawn(self->client_stream.get_executor(), [self](const ba::yield_context &yield)
        {
            self->echo(self->client_stream, self->remote_stream, yield, self);
        });
        self->echo(self->remote_stream, self->client_stream, yield, self);

    });
}

void Session::echo(beast::tcp_stream &src, beast::tcp_stream &dst, const ba::yield_context &yield, const std::shared_ptr<Session> &self)
{
    error_code ec;
    std::vector<byte_t> buf(buffer_size);
    for (;;)
    {
        std::size_t n = src.async_read_some(ba::buffer(buf), yield[ec]);
        if (ec) return;

        dst.async_write_some(ba::buffer(buf, n), yield[ec]);
        if (ec) return;
    }
}

bool Session::is_command_request_valid()
{
    // VER checking
    if (client_buf[0] != SOCKS_VER)
    {
        BOOST_LOG_TRIVIAL(warning) << "Request with unsupported VER: " << unsigned(client_buf[0]);
        command_answer[1] = UNACCEPTABLE_VER;
        return false;
    }
    // CMD checking
    if (client_buf[1] != CMD_CONNECT)
    {
        BOOST_LOG_TRIVIAL(warning) << "Request with unsupported CMD: " << unsigned(client_buf[1]);
        command_answer[1] = COMMAND_NOT_SUPPORTED;
        return false;
    }
    // RSV checking
    if (client_buf[2] != RSV)
    {
        BOOST_LOG_TRIVIAL(warning) << "Request with invalid RSV";
        command_answer[1] = UNASSIGNED;
        return false;
    }
    //ATYP checking
    if (client_buf[3] != ATYP_DOMAINNAME && client_buf[3] != ATYP_IPV4)
    {
        BOOST_LOG_TRIVIAL(warning) << "Request with unsupported ATYP: " << unsigned(client_buf[3]);
        command_answer[1] = ADDRESS_TYPE_NOT_SUPPORTED;
        return false;
    }
    return true;
}

void Session::resolve_domain_name(const ba::yield_context &yield, error_code ec, byte_t domain_name_length)
{
    std::string remote_host(reinterpret_cast<char*>(client_buf.data()), domain_name_length);
    std::uint16_t port;
    std::memcpy(&port, client_buf.data() + domain_name_length, 2);
//    std::string str_port = std::to_string(port);
//    std::string remote_port = std::to_string(boost::endian::big_to_native(*((uint16_t *) &client_buf[domain_name_length])));
    std::string remote_port = std::to_string(boost::endian::big_to_native(port));
    boost_resolver::query query(remote_host, remote_port);
    boost_resolver::iterator endpoint_iterator = resolver.async_resolve(query, yield[ec]);
    if (ec)
    {
        BOOST_LOG_TRIVIAL(error) << "Failed to resolve domain name" << std::endl;
        command_answer[1] = NETWORK_UNREACHABLE;
        return;
    }
    endpoint = *endpoint_iterator;
}

std::string Session::socket_to_string() const
{
    beast::error_code ec;
    boost_endpoint endpoint = client_stream.socket().remote_endpoint(ec);
    if (ec) return "closed socket";
    return endpoint.address().to_string() + ":" + std::to_string(boost::endian::big_to_native(endpoint.port()));

}

std::string Session::endpoint_to_string() const
{
    return endpoint.address().to_string() + ":" + std::to_string(endpoint.port());
}

} // socks5

} // study
