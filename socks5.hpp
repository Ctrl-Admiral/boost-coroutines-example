#ifndef BOOST_COROUTINE_SOCKS5_HPP_
#define BOOST_COROUTINE_SOCKS5_HPP_

#include <boost/beast/core.hpp>
#include <boost/asio.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/signal_set.hpp>
#include <boost/asio/spawn.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/write.hpp>
#include <boost/asio/read.hpp>
#include <boost/beast/core/tcp_stream.hpp>
#include <boost/endian/conversion.hpp>
#include <boost/asio/streambuf.hpp>
#include <boost/asio/buffer.hpp>
#include <iostream>
#include <memory>

namespace socks5
{
using boost::asio::ip::address_v4;
//using boost::asio::buffer;
using boost::asio::error::operation_aborted;
using boost::asio::error::eof;
//using boost::asio::spawn;
//using boost::beast::tcp_stream;
using boost::system::error_code;
using boost::endian::big_to_native;

namespace beast = boost::beast;         // from <boost/beast.hpp>
namespace ba = boost::asio;             // from <boost/asio.hpp>
using ba_tcp = boost::asio::ip::tcp;    // from <boost/asio/ip/tcp.hpp>

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
    ATYP_IPV6 = 0x04
};


//from boost example
class Session : public std::enable_shared_from_this<Session> {
public:
    explicit Session(ba_tcp::tcp::socket client_socket, std::size_t buffer_size = 2046, std::size_t timeout = 60);
    void go();

private:

    void echo(beast::tcp_stream& src, beast::tcp_stream& dst, const ba::yield_context& yield, const std::shared_ptr<Session>& self);
    bool handshake(const ba::yield_context& yield, const std::shared_ptr<Session>& self);

    bool is_command_request_valid();

    void resolve_domain_name(const ba::yield_context &yield, error_code ec, std::uint8_t domain_name_length);

    std::string socket_to_string() const;

    std::string endpoint_to_string() const;

    beast::tcp_stream client_stream;
    beast::tcp_stream remote_stream;
    std::vector<uint8_t> client_buf;
    uint8_t connect_answer[2] = {SOCKS_VER, AUTH_UNACCEPTABLE};
    uint8_t command_answer[10] = {0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    ba_tcp::endpoint endpoint;
    ba_tcp::resolver resolver;
    std::size_t buffer_size;
    std::chrono::seconds timeout;
};


enum
{
    SUCCEEDED = 0x00,
    SOCKS5_GENERAL_SOCKS_SERVER_FAILURE,
    SOCKS5_CONNECTION_NOT_ALLOWED_BY_RULESET,
    SOCKS5_NETWORK_UNREACHABLE,
    SOCKS5_CONNECTION_REFUSED,
    SOCKS5_TTL_EXPIRED,
    COMMAND_NOT_SUPPORTED,
    ADDRESS_TYPE_NOT_SUPPORTED,
    SOCKS5_UNASSIGNED
};


} // socks5

#endif // BOOST_COROUTINE_SOCKS5_HPP_
