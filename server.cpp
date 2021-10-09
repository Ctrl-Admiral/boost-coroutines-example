#include "socks5.hpp"

#include <boost/beast/core.hpp>
#include <boost/beast/websocket.hpp>
#include <boost/asio/spawn.hpp>
#include <boost/asio/streambuf.hpp>
#include <boost/asio/buffer.hpp>
#include <boost/asio.hpp>
#include <algorithm>
#include <cstdlib>
#include <functional>
#include <iostream>
#include <memory>
#include <string>
#include <thread>
#include <vector>

namespace beast = boost::beast;         // from <boost/beast.hpp>
namespace ba = boost::asio;             // from <boost/asio.hpp>
using ba_tcp = boost::asio::ip::tcp;    // from <boost/asio/ip/tcp.hpp>

#include <boost/log/core.hpp>
#include <boost/log/trivial.hpp>
#include <boost/log/expressions.hpp>
#include <boost/log/utility/setup/console.hpp>
#include <boost/log/utility/setup/common_attributes.hpp>
#include <boost/log/expressions/formatters/date_time.hpp>
#include <boost/log/utility/setup.hpp>
#include <boost/log/support/date_time.hpp>
#include <boost/date_time/posix_time/posix_time.hpp>

// Accepts incoming connections and launches the sessions
void
do_listen(
    ba::io_context& ioc,
    ba_tcp::endpoint endpoint,
    ba::yield_context yield)
{
    boost::system::error_code ec;

    // Open the acceptor
    ba_tcp::acceptor acceptor(ioc);
    acceptor.open(endpoint.protocol(), ec);
    if(ec)
        throw std::runtime_error("open acceptor: " + ec.message());

    // Allow address reuse. To prevent bind error: in use
    acceptor.set_option(ba::socket_base::reuse_address(true), ec);
    if(ec)
        throw std::runtime_error("set acceptor option (reuse_address): " + ec.message());

    // Bind to the address
    acceptor.bind(endpoint, ec);
    if(ec)
        throw std::runtime_error("bind acceptor: " + ec.message());

    // Start listening for connections
    acceptor.listen(ba::socket_base::max_listen_connections, ec);
    if(ec)
        throw std::runtime_error("listen acceptor: " + ec.message());

    for(;;)
    {
        ba_tcp::socket socket{ba::make_strand(acceptor.get_executor())};
        acceptor.async_accept(socket, yield[ec]);
        if(ec)
            throw std::runtime_error("acception socket: " + ec.message());
        else
        {
            BOOST_LOG_TRIVIAL(info) << "Socket accepted";

            if (!ec)
                std::make_shared<socks5::Session>(std::move(socket))->go();
        }
    }
}

void do_my_log_format()
{
    auto sink = boost::log::add_console_log(std::cout);
    sink->set_formatter
       (
           boost::log::expressions::stream << "["  << boost::log::trivial::severity << "]"
                << " [" << boost::log::expressions::format_date_time< boost::posix_time::ptime >("TimeStamp", "%H:%M:%S.%f") << "]"
                << " [" << boost::log::expressions::attr<boost::log::attributes::current_thread_id::value_type>("ThreadID") << "] "
                << boost::log::expressions::smessage
       );
       sink->imbue(sink->getloc());
       boost::log::add_common_attributes();
}

int main(int argc, char* argv[]) try
{
    do_my_log_format();

    if (argc != 3)
    {
        std::cerr <<
            "Usage: ./socks5-server <port> <threads>\n" <<
            "Example:\n" <<
            "    ./socks5-server 8080 1\n";
        return EXIT_FAILURE;
    }
    auto const port = static_cast<unsigned short>(std::atoi(argv[1]));
    auto const threads = std::max<int>(1, std::atoi(argv[2]));

    // The io_context is required for all I/O
    ba::io_context ioc{threads};

    // Spawn a listening port
    ba::spawn(ioc,
        std::bind(
            &do_listen,
            std::ref(ioc),
            ba_tcp::endpoint{ba_tcp::v4(), port},  // any IPv4 address
            std::placeholders::_1));

    BOOST_LOG_TRIVIAL(info) << "Spawned listening port";

    // Run the I/O service on the requested number of threads
    std::vector<std::thread> v;
    v.reserve(threads - 1);
    for(auto i = threads - 1; i > 0; --i)
    {
        v.emplace_back([&ioc]{ ioc.run(); });
        BOOST_LOG_TRIVIAL(info) << "Added thread";
    }
    ioc.run();

    return EXIT_SUCCESS;
}
catch (const std::exception& e)
{
    std::cerr << e.what() << std::endl;
}
catch (...)
{
    std::cerr << "Unknown error!" << std::endl;
}
