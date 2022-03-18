#include <iostream>

#include <memory>

#include <boost/asio.hpp>
#include <boost/bind.hpp>
#include <boost/date_time/posix_time/posix_time.hpp>
#include <boost/thread.hpp>
#include <boost/lambda/lambda.hpp>
#include <boost/signals2.hpp>

#include <boost/program_options.hpp>

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



class clientUDP_t {
public:
    std::unique_ptr<boost::mutex> mtx;
    
    clientUDP_t(uint16_t port = 0);

    uint16_t get_port() { return endp.port(); }
    
    void set_port(uint16_t port) { endp.port(port); }

    void transmit(  void *buffer, uint32_t lengthBuffer,
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


int32_t serverDo(){
        system("clear");
        std::cout << "SERVER" << std::endl;
        try{
            boost::asio::io_service io_service;
            serverUDP_t s(io_service, 11223);
            io_service.run();
        }
        catch (std::exception &e){
            std::cerr << "Exception: " << e.what() << "\n";
        }
        return 0;
}

int32_t clientDo(uint8_t codeValue){
        std::cout << "CLIENT" << std::endl;

        uint8_t *ptrData;
        uint8_t lengthData = 0;        
        switch (codeValue) {
        case 1: //STCgetTemp
            std::cout << "for send: \tSTCgetTemp" << std::endl;
            goto markToData1;
        case 4: //STCturnOffPump
            std::cout << "for send: \tSTCturnOffPump" << std::endl;
            goto markToData1;
        case 3: //STCturnOnPump
            std::cout << "for send: \tSTCturnOnPump" << std::endl;
        markToData1:
            lengthData = 1;
            ptrData = new uint8_t[lengthData];
            ptrData[0] = codeValue;
            break;
        case 2: //STCsetTempThreshold
            std::cout << "for send: \tSTCsetTempThreshold" << std::endl;
            goto markToData2;
        case 5: //STCsetTimePollingSensors
            std::cout << "for send: \tSTCsetTimePollingSensors" << std::endl;
        markToData2:
            lengthData = 2;
            ptrData = new uint8_t[lengthData];
            ptrData[0] = codeValue;
            ptrData[1] = 5;
            break;
        default:
            std::cout << "command not recogmized" << std::endl;
            return -1;
            break;
        }
    
        clientUDP_t client(1111);
        ip::udp::endpoint ep(ip::address::from_string("192.168.124.32"), 1111);
        // ip::udp::endpoint ep(ip::address::from_string("127.0.0.1"), 11223);
        boost::system::error_code ec;
        client.transmit(ptrData, lengthData, ep, ec);
        
        std::cout << "Transmitted" << std::endl;
        if (ptrData != NULL) delete[] ptrData;
        return 0;
}


int main(int argc, char *argv[])
{
    std::string client_str = "c";
    std::string server_str = "s";
    progOpt::options_description desc;
    desc.add_options()
    ("help", "this help")
    (client_str.c_str(), progOpt::value<int32_t>()->default_value(1), "Run client : send command \n\
    1-STCgetTemp\n\
    2-STCsetTempThreshold\n\
    3-STCturnOnPump\n\
    4-STCturnOffPump\n\
    5-STCsetTimePollingSensors\n\
    ")
    (server_str.c_str(), "Server run");

    progOpt::variables_map vm;

    progOpt::store(progOpt::parse_command_line(argc, argv, desc), vm);
    progOpt::notify(vm);    
    

    if (vm.count("help")) {
        //HELP
        std::cout << desc << "\n";
        return 0;
    } else if (vm.count(server_str.c_str())) {  //SERVER
        serverDo();
        return 0;
    } else if (vm.count(client_str.c_str())) {  //CLIENT
        uint32_t codeValue = vm[client_str.c_str()].as<int>();
        clientDo(codeValue);
        return 0;
    } else {
        std::cout << "server-1 or client-0\t";
        bool server = false;
        std::cin >> server;
        
        if (server){        //SERVER
            serverDo();
        } else {            //CLIENT
            std::cout << "\n\n";
            uint8_t codeValue = 0;
            std::cout << "Code cmd to send: ";
            std::cin >> codeValue;
            clientDo(codeValue);
        }
    }
    return 0;
}



clientUDP_t::clientUDP_t(uint16_t port) : endp(ip::udp::v4(), port), socket(io_serv, endp), deadline_t(io_serv) {
    mtx = std::unique_ptr<boost::mutex>();
    deadline_t.expires_at(boost::posix_time::pos_infin);
    check_deadline();
}

void clientUDP_t::transmit( void *buffer, uint32_t lengthBuffer,
                            ip::udp::endpoint endpoint_to,
                            boost::system::error_code &ec) {
    ec = asio::error::would_block;
    std::size_t length;
    socket.async_send_to(asio::buffer(buffer, lengthBuffer),
                            endpoint_to,
                            boost::bind(&clientUDP_t::handle_receive, _1, _2, &ec, &length));
    do
        io_serv.run_one();
    while (ec == asio::error::would_block);
}


std::size_t clientUDP_t::receive(   void *buffer, uint32_t lengthBuffer,
                                    ip::udp::endpoint endpoint_from,
                                    boost::posix_time::time_duration timeout,
                                    boost::system::error_code &ec) {
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

void clientUDP_t::check_deadline() {
    if (deadline_t.expires_at() <= asio::deadline_timer::traits_type::now()) {
        socket.cancel();
        deadline_t.expires_at(boost::posix_time::pos_infin);
    }
    deadline_t.async_wait(boost::bind(&clientUDP_t::check_deadline, this));
}

void clientUDP_t::handle_receive(   const boost::system::error_code &ec, 
                                    std::size_t length,
                                    boost::system::error_code *&out_ec,
                                    std::size_t *out_length) {
    *out_ec = ec;
    *out_length = length;
}





serverUDP_t::serverUDP_t(   asio::io_service &io_service, uint16_t port)
    : socket_server(io_service, ip::udp::endpoint(ip::udp::v4(), port))
{
    data.reserve(512);
    do_receive();
}


void serverUDP_t::do_receive(){
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
                for(uint32_t i = 0; i < bytes_recvd; i++)
                    std::cout << (uint32_t)data[i]<< " ";
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