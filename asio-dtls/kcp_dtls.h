#ifndef __kcp_dtls_h__
#define __kcp_dtls_h__

#include "DTLS_Context.h"
#include "kcp/ikcp.h"


class kcp_Context : public DTLS_Context {
    public:
	kcp_Context(boost::asio::io_context &serv, dtls_sock_ptr this_ptr)
		: DTLS_Context(serv, this_ptr)
	{
	}
};

#endif
