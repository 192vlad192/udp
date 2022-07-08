#include <iostream>

#include <memory>

#include <boost/asio.hpp>
#include <boost/bind.hpp>
#include <boost/date_time/posix_time/posix_time.hpp>
#include <boost/thread.hpp>
#include <boost/lambda/lambda.hpp>
#include <boost/signals2.hpp>

#include <boost/program_options.hpp>

#include "command.h"

namespace asio = boost::asio;
namespace ip = boost::asio::ip;
namespace progOpt = boost::program_options;

std::string get_time()
{
    std::time_t t = time(NULL);
    struct tm *time = localtime(&t);
    std::string buf = ((time->tm_mday < 10) ? "0" : "") + std::to_string(time->tm_mday) + "." +
                      ((time->tm_mon < 10) ? "0" : "") + std::to_string(time->tm_mon + 1) + "." +
                      "" + std::to_string(time->tm_year + 1900) + " " +
                      ((time->tm_hour < 10) ? "0" : "") + std::to_string(time->tm_hour) + ":" +
                      ((time->tm_min < 10) ? "0" : "") + std::to_string(time->tm_min) + ":" +
                      ((time->tm_sec < 10) ? "0" : "") + std::to_string(time->tm_sec);
    return buf;
}

class clientUDP_t
{
public:
    std::unique_ptr<boost::mutex> mtx;

    clientUDP_t(uint16_t port = 0);

    uint16_t get_port() { return endp.port(); }

    void set_port(uint16_t port) { endp.port(port); }

    void transmit(void *buffer, uint32_t lengthBuffer,
                  ip::udp::endpoint endpoint_to,
                  boost::system::error_code &ec);

    std::size_t receive(void *buffer, uint32_t lengthBuffer,
                        ip::udp::endpoint endpoint_from,
                        boost::posix_time::time_duration timeout,
                        boost::system::error_code &ec);

private:
    void check_deadline();

    static void handle_receive(const boost::system::error_code &ec, std::size_t length,
                               boost::system::error_code *&out_ec, std::size_t *out_length);
    asio::io_service io_serv;
    ip::udp::endpoint endp;
    ip::udp::socket socket;
    asio::deadline_timer deadline_t;
};

class serverUDP_t
{
public:
    serverUDP_t(asio::io_service &io_service, uint16_t port);
    void do_receive();
    void do_send(std::size_t size, std::vector<uint16_t> data_transmit);

private:
    ip::udp::socket socket_server;
    ip::udp::endpoint sender_endpoint;
    enum
    {
        max_length = 1024
    };
    std::vector<uint8_t> data;
};

template <typename T>
void dispalay(std::vector<T> data, uint32_t align)
{
    for (uint32_t i = 0; i < data.size(); i++)
    {
        if (i % align == 0)
            std::cout << std::endl;
        std::cout << "\t" << (uint32_t)data[i];
    }
    std::cout << std::endl;
}

int32_t serverDo()
{
    system("clear");
    std::cout << "SERVER" << std::endl;
    try
    {
        boost::asio::io_service io_service;
        serverUDP_t s(io_service, 11223);
        io_service.run();
    }
    catch (std::exception &e)
    {
        std::cerr << "Exception: " << e.what() << "\n";
    }
    return 0;
}

int32_t clientDo(uint8_t cmd, uint8_t ch, uint64_t data)
{
    std::cout << "CLIENT" << " " << get_time() << std::endl;
    std::cout << "\t" << "cmd\t"  << (uint32_t)cmd  << std::endl;
    std::cout << "\t" << "ch\t"   << (uint32_t)ch   << std::endl;
    std::cout << "\t" << "data\t" << data << std::endl;


    pckg_t pckg;
    pckg.cmd = cmd;
    // pckg.data_len;
    pckg.data[0] = ch;
    memcpy(pckg.data + 1, &data, 8);
    
    std::cout << "\tfor send:\t";
    switch (cmd)
    {
    case PING:
        std::cout << "PING" << std::endl;
        pckg.data_len = 0;
        break;
    case SET_DIR:
        std::cout << "SET_DIR" << std::endl;
        pckg.data_len = 2;
        break;
    case SET_POS:
        std::cout << "SET_POS" << std::endl;
        pckg.data_len = 9;
        break;
    case SET_DIV:
        std::cout << "SET_DIV" << std::endl;
        pckg.data_len = 2;
        break;
    case SET_ENABLE:
        std::cout << "SET_ENABLE" << std::endl;
        pckg.data_len = 2;
        break;
    case SET_HOME:
        std::cout << "SET_HOME" << std::endl;
        pckg.data_len = 0;
        break;
    case SET_BREAK:
        std::cout << "SET_BREAK" << std::endl;
        pckg.data_len = 2;
        break;
    case SET_PROG:
        std::cout << "SET_PROG" << std::endl;
        std::cout << "\t\tnot implemented" << std::endl;
        pckg.data_len = 10;
        return -2;
        break;
    default:
        std::cout << "\tnot recogmized" << std::endl;
        return -1;
        break;
    }

    clientUDP_t client(1111);
    ip::udp::endpoint ep(ip::address::from_string("192.168.124.72"), 3000);
    // ip::udp::endpoint ep(ip::address::from_string("127.0.0.1"), 11223);
    boost::system::error_code ec;
    client.transmit(&pckg, pckg.data_len + 2, ep, ec);
    std::cout << "\t\tTransmitted" << std::endl;

    return 0;
}

int main(int argc, char *argv[])
{
    std::string client_str = "cmd";
    std::string server_str = "s";
    progOpt::options_description desc;
    desc.add_options()("help", "this help")
    (server_str.c_str(), "Server run")
    (client_str.c_str(), progOpt::value<uint32_t>()->default_value(1), 
    "Run client for recieve cmd\n"
	"    0x01 PING        Команда проверки связи;\n"
    "    0x02 SET_DIR     Команда принудительного изменения направления движения позиционера;\n"
    "    0x03 SET_POS     Команда установки целевой позиции позиционера;\n"
    "    0x04 SET_DIV     Команда установки делителя шага для позиционера;\n"
    "    0x05 SET_ENABLE  Принудительное включение / отключение позиционера;\n"
    "    0x06 SET_HOME    Команда калибровки системы;\n"
    "    0x07 SET_BREAK   Команда принудительного сброса / установки тормоза для позиционера (имеет воздействие только на вертикальные позиционеры, для горизонтальных будет проигнорирована);\n"
    "    0x08 SET_PROG    Команда установки программы перемещений для позиционера.\n"
    )
    ("ch", progOpt::value<uint32_t>()->default_value(0), "number channel")
    ("data", progOpt::value<uint64_t>()->default_value(0), "data");
    

    progOpt::variables_map vm;
    try {
        // std::cout << "DEBUG MARK " << __LINE__ << std::endl;
        progOpt::store(progOpt::parse_command_line(argc, argv, desc), vm);
        progOpt::notify(vm);
    } catch ( const std::exception& e ) {
        std::cerr << e.what() << std::endl;
        return 1;
    }

    if (vm.count("help"))
    { // HELP
        std::cout << desc << "\n";
    }
    else if (vm.count(server_str.c_str()))
    { // SERVER
        serverDo();
    }
    else if (vm.count(client_str.c_str()))
    { // CLIENT
        uint32_t codeValue = vm[client_str.c_str()].as<uint32_t>();
        clientDo(codeValue, vm["ch"].as<uint32_t>(), vm["data"].as<uint64_t>());
    }
    else
    {
        std::cout << "What doing" << std::endl;
        std::cout << "\tTry using options --help" << std::endl;
    }

    return 0;
}

clientUDP_t::clientUDP_t(uint16_t port) : endp(ip::udp::v4(), port), socket(io_serv, endp), deadline_t(io_serv)
{
    mtx = std::unique_ptr<boost::mutex>();
    deadline_t.expires_at(boost::posix_time::pos_infin);
    check_deadline();
}

void clientUDP_t::transmit(void *buffer, uint32_t lengthBuffer,
                           ip::udp::endpoint endpoint_to,
                           boost::system::error_code &ec)
{
    ec = asio::error::would_block;
    std::size_t length;
    socket.async_send_to(asio::buffer(buffer, lengthBuffer),
                         endpoint_to,
                         boost::bind(&clientUDP_t::handle_receive, _1, _2, &ec, &length));
    do
        io_serv.run_one();
    while (ec == asio::error::would_block);
}

std::size_t clientUDP_t::receive(void *buffer, uint32_t lengthBuffer,
                                 ip::udp::endpoint endpoint_from,
                                 boost::posix_time::time_duration timeout,
                                 boost::system::error_code &ec)
{
    deadline_t.expires_from_now(timeout);
    ec = asio::error::would_block;
    std::size_t length = 0;
    socket.async_receive_from(boost::asio::buffer(buffer, lengthBuffer),
                              endpoint_from,
                              boost::bind(&clientUDP_t::handle_receive, _1, _2, &ec, &length));
    do
        io_serv.run_one();
    while (ec == asio::error::would_block);
    return length;
}

void clientUDP_t::check_deadline()
{
    if (deadline_t.expires_at() <= asio::deadline_timer::traits_type::now())
    {
        socket.cancel();
        deadline_t.expires_at(boost::posix_time::pos_infin);
    }
    deadline_t.async_wait(boost::bind(&clientUDP_t::check_deadline, this));
}

void clientUDP_t::handle_receive(const boost::system::error_code &ec,
                                 std::size_t length,
                                 boost::system::error_code *&out_ec,
                                 std::size_t *out_length)
{
    *out_ec = ec;
    *out_length = length;
}

serverUDP_t::serverUDP_t(asio::io_service &io_service, uint16_t port)
    : socket_server(io_service, ip::udp::endpoint(ip::udp::v4(), port))
{
    data.reserve(512);
    do_receive();
}

void serverUDP_t::do_receive()
{
    data.resize(512);
    socket_server.async_receive_from(
        asio::buffer(data, max_length), sender_endpoint,
        [&](boost::system::error_code ec, std::size_t bytes_recvd)
        {
            if (!ec && bytes_recvd > 0)
            {
                std::cout << get_time() << " " << bytes_recvd << " байт "
                          << " "
                          << sender_endpoint.address() << ":" << sender_endpoint.port() << std::endl;
                data.resize(bytes_recvd);
                std::cout << "data: ";
                for (uint32_t i = 0; i < bytes_recvd; i++)
                    std::cout << (int32_t)data[i] << " ";
                std::cout << std::endl;

                do_receive();
            }
            else
            {
                std::cout << "Result " << ec.message() << std::endl;
                std::cout << "Count " << bytes_recvd << std::endl;
                do_receive();
            }
        });
}

void serverUDP_t::do_send(std::size_t size, std::vector<uint16_t> data_transmit)
{
    socket_server.async_send_to(
        asio::buffer(data_transmit, size), sender_endpoint,
        [this](boost::system::error_code, std::size_t)
        {
            do_receive();
        });
}