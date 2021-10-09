#include "socks5.hpp"

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

//namespace beast = boost::beast;
namespace ba = boost::asio;

using boost_ipv4 = boost::asio::ip::address_v4;
using error_code = boost::system::error_code;
using tcp_socket = boost::asio::ip::tcp::socket;
using boost_endpoint = boost::asio::ip::tcp::endpoint;
using boost_resolver = boost::asio::ip::tcp::resolver;
using boost_acceptor = boost::asio::ip::tcp::acceptor;

// Accepts incoming connections and launches the sessions
void
do_listen(
    ba::io_context& ioc,
    boost_endpoint endpoint,
    ba::yield_context yield)
{
    boost::system::error_code ec;

    // Open the acceptor
    boost_acceptor acceptor(ioc);
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
        tcp_socket socket{ba::make_strand(acceptor.get_executor())};
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

} // study

int main(int argc, char* argv[]) try
{
    study::do_my_log_format();

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
    study::ba::io_context ioc{threads};

    // Spawn a listening port
    study::ba::spawn(ioc,
        std::bind(
            &study::do_listen,
            std::ref(ioc),
            study::boost_endpoint{study::boost_ipv4(), port},  // any IPv4 address
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
