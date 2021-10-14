#ifndef BOOST_COROUTINE_SOCKS5_HPP_
#define BOOST_COROUTINE_SOCKS5_HPP_

#include <boost/beast/core.hpp>
#include <boost/asio.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/spawn.hpp>
#include <boost/asio/write.hpp>
#include <boost/asio/read.hpp>
#include <boost/beast/core/tcp_stream.hpp>
#include <boost/endian/conversion.hpp>
#include <boost/asio/streambuf.hpp>
#include <boost/asio/buffer.hpp>
#include <iostream>
#include <memory>
#include <string_view>

#include <boost/log/core.hpp>
#include <boost/log/trivial.hpp>
#include <boost/log/expressions.hpp>
#include <boost/log/utility/setup/console.hpp>
#include <boost/log/utility/setup/common_attributes.hpp>
#include <boost/log/expressions/formatters/date_time.hpp>
#include <boost/log/utility/setup.hpp>
#include <boost/log/support/date_time.hpp>
#include <boost/date_time/posix_time/posix_time.hpp>

namespace study
{

namespace beast = boost::beast;
namespace ba = boost::asio;

using boost_ipv4 = boost::asio::ip::address_v4;
using error_code = boost::system::error_code;
using tcp_socket = boost::asio::ip::tcp::socket;
using boost_endpoint = boost::asio::ip::tcp::endpoint;
using boost_resolver = boost::asio::ip::tcp::resolver;
using byte_t = std::uint8_t;

namespace socks5
{

enum
{
    SOCKS_VER = 0x05,

    AUTH_NONE = 0x00,
    AUTH_USER_PASS = 0x02,
    AUTH_UNACCEPTABLE = 0xFF,

    CMD_CONNECT = 0x01,
    CMD_BIND = 0x02,
    CMD_UDP_ASSOCIATE = 0x03,

    ATYP_IPV4 = 0x01,
    ATYP_DOMAINNAME = 0x03,
    ATYP_IPV6 = 0x04,

    RSV = 0x00,  // reserved byte
    BNDADDR_DEFAULT_BYTE = 0x00,
    BNDPORT_DEFAULT_BYTE = 0x00
};

enum
{
    SUCCEEDED = 0x00,
    GENERAL_SOCKS_SERVER_FAILURE,
    CONNECTION_NOT_ALLOWED_BY_RULESET,
    NETWORK_UNREACHABLE,
    HOST_UNREACHABLE,
    CONNECTION_REFUSED,
    TTL_EXPIRED,
    COMMAND_NOT_SUPPORTED,
    ADDRESS_TYPE_NOT_SUPPORTED,
    UNASSIGNED,

    UNACCEPTABLE_VER = 0xff
};


//from boost example
class Session : public std::enable_shared_from_this<Session> {
public:
    explicit Session(tcp_socket client_socket, std::size_t buffer_size = (1 << 14), std::size_t timeout = 60);
    void go();

private:

    void echo(beast::tcp_stream& src, beast::tcp_stream& dst, const ba::yield_context& yield, const std::shared_ptr<Session>& self);
    bool handshake(const ba::yield_context& yield, const std::shared_ptr<Session>& self);
    bool is_command_request_valid();

    void resolve_domain_name(const ba::yield_context &yield, error_code ec, byte_t domain_name_length);

    std::string socket_to_string() const;
    std::string endpoint_to_string() const;

    beast::tcp_stream client_stream;
    beast::tcp_stream remote_stream;
    std::vector<byte_t> client_buf;
    byte_t connect_answer[2]  = {SOCKS_VER, AUTH_UNACCEPTABLE};
    byte_t command_answer[10] = {SOCKS_VER, SUCCEEDED, RSV, ATYP_IPV4,
                                 BNDADDR_DEFAULT_BYTE, BNDADDR_DEFAULT_BYTE, BNDADDR_DEFAULT_BYTE, BNDADDR_DEFAULT_BYTE,
                                 BNDPORT_DEFAULT_BYTE, BNDPORT_DEFAULT_BYTE};
    boost_endpoint endpoint;
    boost_resolver resolver;
    std::size_t buffer_size;
    std::chrono::seconds timeout;
    std::string displayed_address;
};


} // socks5

} // study

#endif // BOOST_COROUTINE_SOCKS5_HPP_
