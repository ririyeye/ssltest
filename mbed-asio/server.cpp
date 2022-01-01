#include <boost/asio.hpp>
#include <boost/bind.hpp>
#include <iostream>
#include "mbed_cfg.h"
#include <memory>

#include <cstdlib>
#include <iostream>
#include <memory>
#include <utility>
#include <boost/asio.hpp>
#include "mbed_cfg.h"

#include "server.h"

class server {
    public:
	server(boost::asio::io_context &io_context, short port, mbed_context *pctx)
		: acceptor_(io_context, tcp::endpoint(tcp::v4(), port)), ctx(io_context), mbed_ctx(pctx)

	{
		do_accept();
	}

    private:
	void do_accept()
	{
		acceptor_.async_accept(
			[this](boost::system::error_code ec, tcp::socket socket) {
				if (!ec) {
					std::make_shared<session>(std::move(socket), ctx , mbed_ctx)->start();
				}

				do_accept();
			});
	}

	tcp::acceptor acceptor_;
	boost::asio::io_context &ctx;
	mbed_context *mbed_ctx;
};

int main(int argc, char *argv[])
{
	auto conf = create_mbed_config_server("server/pri.ca", "server/pri_key.pem", "12138");

	try {
		boost::asio::io_context io_context;

		server s(io_context, 8888, conf.get());

		io_context.run();
	} catch (std::exception &e) {
		std::cerr << "Exception: " << e.what() << "\n";
	}

	return 0;
}
