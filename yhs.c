#define _CRT_SECURE_NO_WARNINGS
#define _CRT_NONSTDC_NO_DEPRECATE

#include "yhs.h"

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////
//
// yhs - yocto HTTP server
// -----------------------
//
// `yocto' is (at the time of writing) the smallest SI prefix. It is
// very small.
//
// `yocto' refers to the server's feature set, not the size of the code.
// Though there's not THAT much to trawl through.
//
// THIS IS NOT FOR PRODUCTION USE. It's designed for use during development.
//
// yhs was written by Tom Seddon <yhs@tomseddon.plus.com>.
//
// yhs is in the public domain.
//
//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

// Mac/iThing portajunk
#ifdef __APPLE__

#include <errno.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <dirent.h>
#include <arpa/inet.h>

#define STRICMP(X,Y) (strcasecmp((X),(Y)))
#define STRNICMP(X,Y,N) (strncasecmp((X),(Y),(N)))
#define CLOSESOCKET(X) (close(X))
#define ALLOCA(X) (alloca(X))

typedef int SOCKET;

#define INVALID_SOCKET (-1)

#define DEBUG_BREAK() (assert(0))

#endif

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

// Windows portajunk
#ifdef WIN32

#define _CRTDBG_MAP_ALLOC
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <WS2tcpip.h>
#include <windows.h>
#include <malloc.h>
#include <crtdbg.h>

typedef unsigned __int64 uint64_t;
typedef unsigned __int32 uint32_t;
typedef unsigned __int16 uint16_t;
typedef unsigned __int8 uint8_t;

#define STRICMP(X,Y) (_stricmp((X),(Y)))
#define STRNICMP(X,Y,N) (strnicmp((X),(Y),(N)))
#define CLOSESOCKET(X) (closesocket(X))
#define ALLOCA(X) (_alloca(X))

typedef int socklen_t;

#ifdef _MSC_VER
#pragma warning(error:4020)// too many actual parameters
#pragma warning(disable:4204)// nonstandard extension used : non-constant
                             // aggregate initializer (think this is part of C99
                             // now)
#endif//_MSC_VER

#define DEBUG_BREAK() (__debugbreak())

#endif

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

#include <limits.h>
#include <ctype.h>
#include <assert.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

#ifndef NDEBUG

#define ENABLE_UNIT_TESTS 1

#define YHS_ASSERT(X) ((X)?(void)0:(DEBUG_BREAK(),(void)0))

#else

#define YHS_ASSERT(X) ((void)0)

#endif//NDEBUG

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////
//
// Notes
// -----
//
// - Only one response is serviced at once. No multithreading, no funny
//   business.
//
// - The connection is not reused. No need for Content-Length; just send
//   whatever, the connection is closed afterwards, and the browser gets
//   the picture.
//
// - I avoided implementing things I didn't absolutely have to...
//
// - Tested on the following browsers:
//
//   - Safari 5 (Mac OS X)
//
//   - Opera 10 (Mac OS X/Windows)
//
//   - Firefox 3.5 (Windows)
//
//   - Internet Explorer 6 (Windows)
//
// TODO
// ----
//
// - The PNG writing is pretty basic. It could be ten times smarter, and
//   it would still be dumb as rocks.
//
// - Handle "Transfer-Encoding: chunked"? Does anything send this? At the
//   very least, send some kind of error if a chunked request is received.
//
// - Send "Connection: close" as part of the response? Doesn't seem to
//   bother any of the tested browsers, and it's not like they won't find
//   out as the connection will get closed anyway...
//
// - Accept absolute URLs in the GET request?
//
// DONE
// ----
//
// - Support HEAD. Should be easy enough. Could be made transparent to the
//   request handler by discarding the response data.
//
// - Probably want some way of deferring responses, so they can be
//   serviced later during the main update loop. (Would just put the
//   response on a list, and leave the socket open, so it can be referred
//   to later.)
//
// - Make sure this is valid C++, or port back to C89.
//
//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

// Tweakables.

enum
{
    // Maximum size of request, in chars, as sent (i.e. excluding trailing
    // 0)
    MAX_REQUEST_SIZE=8192,
    
    // `backlog' argument for listening socket.
    LISTEN_SOCKET_BACKLOG=10,
    
    // Maximum length of format string expansion when using yhs_text*
    MAX_TEXT_LEN=8192,
    
    // Size of write buffer.
    WRITE_BUF_SIZE=1000,
	
	// Max size of server name
	MAX_SERVER_NAME_SIZE=64,
	
	// Max length of a path for the file serving component
	MAX_PATH_SIZE=1000,

	// Timeout, in seconds, to use when selecting sockets that are
	// expected to definitely have incoming data.
	EXPECTED_DATA_TIMEOUT=10,
};

// Memory allocation wrappers.

#define MALLOC(SIZE) (malloc(SIZE))
#define FREE(PTR) (free(PTR))

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

static void print_message(FILE *f,const char *fmt,...)
{
	va_list v;

	va_start(v,fmt);
	vfprintf(f,fmt,v);
	va_end(v);

#ifdef _WIN32
	{
		char buf[1000];

		va_start(v,fmt);
		_vsnprintf(buf,sizeof buf,fmt,v);
		buf[sizeof buf-1]=0;
		va_end(v);

		OutputDebugStringA(buf);
	}
#endif
}

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

static char *yhs_strdup(const char *str)
{
	size_t n;
	char *s;

	assert(str);

	n=strlen(str)+1;

	s=(char *)MALLOC(n);

	if(s)
		memcpy(s,str,n);

	return s;
}

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

// from http://nothings.org/stb.h

static void stb__sha1(const uint8_t *chunk, uint32_t h[5])
{
	int i;
	uint32_t a,b,c,d,e;
	uint32_t w[80];

	for (i=0; i < 16; ++i)
		w[i]=(chunk[i*4+0]<<24)|(chunk[i*4+1]<<16)|(chunk[i*4+2]<<8)|(chunk[i*4+3]<<0);

	for (i=16; i < 80; ++i) {
		uint32_t t;
		t = w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16];
		w[i] = (t + t) | (t >> 31);
	}

	a = h[0];
	b = h[1];
	c = h[2];
	d = h[3];
	e = h[4];

#define STB__SHA1(k,f)                                            \
	{                                                                 \
	uint32_t temp = (a << 5) + (a >> 27) + (f) + e + (k) + w[i];  \
	e = d;                                                       \
	d = c;                                                     \
	c = (b << 30) + (b >> 2);                               \
	b = a;                                              \
	a = temp;                                    \
	}

	i=0;
	for (; i < 20; ++i) STB__SHA1(0x5a827999, d ^ (b & (c ^ d))       );
	for (; i < 40; ++i) STB__SHA1(0x6ed9eba1, b ^ c ^ d               );
	for (; i < 60; ++i) STB__SHA1(0x8f1bbcdc, (b & c) + (d & (b ^ c)) );
	for (; i < 80; ++i) STB__SHA1(0xca62c1d6, b ^ c ^ d               );

#undef STB__SHA1

	h[0] += a;
	h[1] += b;
	h[2] += c;
	h[3] += d;
	h[4] += e;
}

void yhs_sha1(unsigned char output[20], const void *buffer_a,unsigned len)
{
	unsigned char final_block[128];
	uint32_t end_start, final_len, j;
	int i;
	const uint8_t *buffer=(const uint8_t *)buffer_a;

	uint32_t h[5];

	h[0] = 0x67452301;
	h[1] = 0xefcdab89;
	h[2] = 0x98badcfe;
	h[3] = 0x10325476;
	h[4] = 0xc3d2e1f0;

	// we need to write padding to the last one or two
	// blocks, so build those first into 'final_block'

	// we have to write one special byte, plus the 8-byte length

	// compute the block where the data runs out
	end_start = len & ~63;

	// compute the earliest we can encode the length
	if (((len+9) & ~63) == end_start) {
		// it all fits in one block, so fill a second-to-last block
		end_start -= 64;
	}

	final_len = end_start + 128;

	// now we need to copy the data in
	assert(end_start + 128 >= len+9);
	assert(end_start < len || len < 64-9);

	j = 0;
	if (end_start > len)
		j = (uint32_t) - (int) end_start;

	for (; end_start + j < len; ++j)
		final_block[j] = buffer[end_start + j];
	final_block[j++] = 0x80;
	while (j < 128-5) // 5 byte length, so write 4 extra padding bytes
		final_block[j++] = 0;
	// big-endian size
	final_block[j++] = (uint8_t)(len >> 29);
	final_block[j++] = (uint8_t)(len >> 21);
	final_block[j++] = (uint8_t)(len >> 13);
	final_block[j++] = (uint8_t)(len >>  5);
	final_block[j++] = (uint8_t)(len <<  3);
	assert(j == 128 && end_start + j == final_len);

	for (j=0; j < final_len; j += 64) { // 512-bit chunks
		if (j+64 >= end_start+64)
			stb__sha1(&final_block[j - end_start], h);
		else
			stb__sha1(&buffer[j], h);
	}

	for (i=0; i < 5; ++i) {
		output[i*4 + 0] = (uint8_t)(h[i] >> 24);
		output[i*4 + 1] = (uint8_t)(h[i] >> 16);
		output[i*4 + 2] = (uint8_t)(h[i] >>  8);
		output[i*4 + 3] = (uint8_t)(h[i] >>  0);
	}
}

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

enum HandlerFlags
{
	HF_TOC=1,
};

struct yhsHandler
{
    struct yhsHandler *next,*prev;

	unsigned flags;
	unsigned valid_methods;
    
    char *res_path;
    size_t res_path_len;

	char *description;
    
    yhsResPathHandlerFn handler_fn;
    void *context;
};

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

struct PNGData
{
    // Dimensions of image and bytes/pixel.
    int w,h,bypp;
    
    // Coords of next pixel to be written.
    int x,y;
    
    // Chunk CRC so far.
    uint32_t chunk_crc;
    
    // Adler sums for the Zlib encoding.
    uint32_t adler32_s1,adler32_s2;
};
typedef struct PNGData PNGData;

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

enum yhsResponseFlags
{
	RF_DEFERRED=1,
	RF_OWN_HEADER_DATA=2,
	RF_HEAD=4,
};

enum yhsResponseType
{
    RT_NONE_SET,
    RT_DEFER,

	// TEXT and IMAGE are distinguished for asserting purposes. 
	RT_TEXT,
	RT_IMAGE,

	RT_WEBSOCKET,
};
typedef enum yhsResponseType yhsResponseType;

enum {
	MAX_WEBSOCKET_HEADER_SIZE=14,
	SEC_WEBSOCKET_KEY_LEN=22,
	SEC_WEBSOCKET_ACCEPT_LEN=28,
};

enum yhsResponseState
{
	RS_NONE,
	RS_HEADER,
	RS_DATA,
};
typedef enum yhsResponseState yhsResponseState;

enum WebSocketState
{
	WSS_NONE,
	WSS_OPEN,
	WSS_CLOSING,
	WSS_CLOSED,
};
typedef enum WebSocketState WebSocketState;

enum WebSocketRecvState
{
	WSRS_NONE,
	WSRS_RECV,
	WSRS_NEXT_FRAGMENT,
	WSRS_DONE,
};
typedef enum WebSocketRecvState WebSocketRecvState;

enum WebSocketSendState
{
	WSSS_NONE,
	WSSS_SEND,
};
typedef enum WebSocketSendState WebSocketSendState;

enum WebSocketOpcode
{
	// Data frames
	WSO_CONTINUATION=0,
	WSO_TEXT=1,
	WSO_BINARY=2,

	// Control frames
	WSO_CLOSE=8,
	WSO_PING=9,
	WSO_PONG=10,
};
typedef enum WebSocketOpcode WebSocketOpcode;

struct WebSocketFrameHeader
{
	uint8_t fin;
	uint8_t opcode;
	uint8_t mask;
	int len;
	uint8_t masking_key[4];
};
typedef struct WebSocketFrameHeader WebSocketFrameHeader;

struct KeyValuePair
{
    const char *key;
    const char *value;
};
typedef struct KeyValuePair KeyValuePair;

// SCHEME://HOST/PATH;PARAMS?QUERY#FRAGMENT
// \____/   \__/\___/ \____/ \___/ \______/

struct FormData
{
	size_t num_controls;
	KeyValuePair *controls;
	char *controls_data_buffer;
};
typedef struct FormData FormData;

struct HeaderData
{
	char *data;
	size_t data_size;
	size_t method_pos;
	size_t path_pos;
	size_t first_field_pos;
};
typedef struct HeaderData HeaderData;

typedef void (*WriteBufferFlushFn)(yhsRequest *);

struct WriteBufferData
{
	char data[WRITE_BUF_SIZE];
	size_t data_size;
	WriteBufferFlushFn flush_fn;
};
typedef struct WriteBufferData WriteBufferData;

struct WebSocketRecvData
{
	// websocket recv
	WebSocketRecvState state;
	int is_text;
	int is_fragmented;
	int offset;
	int utf8_count;
	int utf8_left;
	uint32_t utf8_char;
	WebSocketFrameHeader fh;
};
typedef struct WebSocketRecvData WebSocketRecvData;

struct WebSocketSendData
{
	// websocket send
	WebSocketSendState state;
	WebSocketOpcode opcode;
	int fin;
};
typedef struct WebSocketSendData WebSocketSendData;

struct WebSocketData
{
	WebSocketState state;
	char accept_str[SEC_WEBSOCKET_ACCEPT_LEN+1];

	WebSocketSendData send;
	WebSocketRecvData recv;
};
typedef struct WebSocketData WebSocketData;

struct yhsRequest
{
	yhsRequest *next_deferred,*prev_deferred;
	yhsRequest *next_deferred_in_chain;

	unsigned flags;
    yhsServer *server;
	const yhsHandler *handler;
    
    SOCKET sock;
    yhsResponseType type;
	yhsResponseState state;
	yhsMethod method;

    PNGData png;
	FormData form;
	HeaderData hdr;
	WriteBufferData wbuf;
	WebSocketData ws;
};

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

struct LogData
{
	yhsBool enabled[YHS_LOG_ENDVALUE];
	yhsLogFn fn;
	void *context;
};
typedef struct LogData LogData;

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

enum ServerState
{
	SS_NONE,
	SS_RUNNING,
	SS_ERROR,
};
typedef enum ServerState ServerState;

struct yhsServer
{
	// port to open on
	int port;
	
	//
	ServerState state;
	
    // socket that listens for incoming connections.
    SOCKET listen_sock;
    
    // doubly-linked. terminator has NULL handler_fn.
    yhsHandler handlers;

	// singly-linked.
	yhsRequest *first_deferred;
	
	LogData log;
    
    // server name
	char name[MAX_SERVER_NAME_SIZE];
};

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

#define SERVER_DEBUG(SERVER_PTR,...) (SERVER_MESSAGE((SERVER_PTR),DEBUG,__VA_ARGS__))
#define SERVER_INFO(SERVER_PTR,...) (SERVER_MESSAGE((SERVER_PTR),INFO,__VA_ARGS__))
#define SERVER_ERROR(SERVER_PTR,...) (SERVER_MESSAGE((SERVER_PTR),ERROR,__VA_ARGS__))

#define SERVER_MESSAGE(SERVER_PTR,CAT,...) ((SERVER_PTR)->log.enabled[YHS_LOG_##CAT]?do_log(&(SERVER_PTR)->log,YHS_LOG_##CAT,__VA_ARGS__):(void)0)

static void do_log(LogData *log,yhsLogCategory cat,const char *fmt,...)
{
	char tmp[1000];
	va_list v;
	
	if(!log->enabled[cat])
		return;
	
	if(!log->fn)
		return;
	
	va_start(v,fmt);
	
	vsnprintf(tmp,sizeof tmp,fmt,v);
	tmp[sizeof tmp-1]=0;
	
	va_end(v);
	
	(*log->fn)(cat,tmp,log->context);
}

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

//#define YHS_ERROR(LOG_PTR,MSG) (yhs_err((LOG_PTR),__FILE__,__FUNCTION__,__LINE__,(MSG)),(void)0)

static void yhs_err(yhsServer *server,const char *file,const char *function,int line,const char *msg)
{
    SERVER_ERROR(server,"YHS: Error:\n");
    SERVER_ERROR(server,"    %s(%d): %s: %s\n",file,line,function,msg);
}

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

#define SERVER_SOCKET_ERROR(SERVER_PTR,MSG) (yhs_socket_err((SERVER_PTR),__FILE__,__FUNCTION__,__LINE__,(MSG)),(void)0)

static void yhs_socket_err(yhsServer *server,const char *file,const char *function,int line,const char *msg)
{
#ifdef WIN32
	int err=WSAGetLastError();
#else
	int err=errno;
#endif
	
	yhs_err(server,file,function,line,msg);

#ifdef WIN32
	{
		char msg[1000];

		FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM,0,err,0,msg,sizeof msg,0);

		while(strlen(msg)>=0&&isspace(msg[strlen(msg)-1]))
			msg[strlen(msg)-1]=0;

		SERVER_ERROR(server,"    %d - %s\n",err,msg);
	}
#else
	SERVER_ERROR(server,"    %d - %s\n",err,strerror(err));
#endif
}

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

// static void hex_dump(const void *data,size_t data_size)
// {
//     size_t i;
//     
//     for(i=0;i<data_size+16;i+=16)
//     {
//         size_t j;
//         const uint8_t *line=(const uint8_t *)data+i;
//         
//         printf("%08lX:",i);
//         
//         for(j=0;j<16;++j)
//         {
//             if(i+j<data_size)
//                 printf(" %02X",line[j]);
//             else
//                 printf(" **");
//         }
//         
//         printf("  ");
//         
//         for(j=0;j<16;++j)
//         {
//             if(i+j<data_size)
//                 printf("%c",isprint(line[j])?line[j]:'.');
//             else
//                 printf(" ");
//         }
//         
//         printf("\n");
//     }
// }

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

static yhsBool create_listen_socket(yhsServer *server)
{
    int good=0;
    const int reuse_addr=1;
    struct sockaddr_in listen_addr;
    SOCKET sock=socket(PF_INET,SOCK_STREAM,IPPROTO_TCP);
    
    if(sock<0)
    {
		SERVER_ERROR(server,"Create listen socket.");
        goto done;
    }
    
    if(setsockopt(sock,SOL_SOCKET,SO_REUSEADDR,(const char *)&reuse_addr,sizeof reuse_addr)<0)
    {
        SERVER_ERROR(server,"Set REUSEADDR.");
        goto done;
    }
    
    // Bind
    memset(&listen_addr,0,sizeof listen_addr);
    
    listen_addr.sin_family=AF_INET;
    listen_addr.sin_addr.s_addr=htonl(INADDR_ANY);
    
    assert(server->port>=0&&server->port<65536);
    listen_addr.sin_port=htons((u_short)server->port);
    
    if(bind(sock,(struct sockaddr *)&listen_addr,sizeof(listen_addr))<0)
    {
        SERVER_ERROR(server,"Bind listen socket.");
        goto done;
    }
    
    // Listen
    if(listen(sock,LISTEN_SOCKET_BACKLOG)<0)
    {
        SERVER_ERROR(server,"Set listen socket to listen mode.");
        goto done;
    }
    
    good=1;
    
done:
    if(!good)
    {
        CLOSESOCKET(sock);
        sock=INVALID_SOCKET;
    }
	
	server->listen_sock=sock;
    
    return sock;
}

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

static void print_likely_urls(yhsServer *server)
{
    SERVER_INFO(server,"YHS: Likely URLs for this system are:\n");
    SERVER_INFO(server,"\n");
    
#ifdef WIN32
    
    {
        char computer_name[500];
        DWORD computer_name_size=sizeof computer_name;
        
        if(!GetComputerNameExA(ComputerNameDnsHostname,computer_name,&computer_name_size))
            SERVER_INFO(server,"YHS: Failed to get computer name.\n");
        else
        {
            SERVER_INFO(server,"    http://%s",computer_name);
            
            if(server->port!=80)
                SERVER_INFO(server,":%d",server->port);
            
            SERVER_INFO(server,"/\n");
        }
    }
    
#else
    
    {
        struct ifaddrs *interfaces;
        if(getifaddrs(&interfaces)<0)
        {
            SERVER_INFO(server,"Get network interfaces.");
            return;
        }
        
        for(struct ifaddrs *ifa=interfaces;ifa;ifa=ifa->ifa_next)
        {
            if(ifa->ifa_addr->sa_family==AF_INET)
            {
                struct sockaddr_in *addr_in=(struct sockaddr_in *)ifa->ifa_addr;
                
                uint32_t addr=ntohl(addr_in->sin_addr.s_addr);
                
                if(addr==0x7F000001)
                    continue;//don't bother printing localhost.
                
                SERVER_INFO(server,"    http://%d.%d.%d.%d",(addr>>24)&0xFF,(addr>>16)&0xFF,(addr>>8)&0xFF,(addr>>0)&0xFF);
                
                if(server->port!=80)
                    SERVER_INFO(server,":%d",server->port);
                
                SERVER_INFO(server,"/\n");
            }
        }
        
        freeifaddrs(interfaces);
        interfaces=NULL;
        
        SERVER_INFO(server,"\n");
    }
    
#endif
}

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

static void default_log_callback(yhsLogCategory category,const char *message,void *context)
{
	FILE *f;

	(void)context;
	
	if(category==YHS_LOG_ERROR)
		f=stderr;
	else
		f=stdout;
	
	fputs(message,f);
}

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

yhsServer *yhs_new_server(int port)
{
    yhsServer *server=(yhsServer *)MALLOC(sizeof *server);

	if(!server)
		return NULL;

    memset(server,0,sizeof *server);
    
    server->handlers.next=&server->handlers;
    server->handlers.prev=&server->handlers;
	
	server->listen_sock=INVALID_SOCKET;
	
	server->port=port;
	
	yhs_set_server_log_enabled(server,YHS_LOG_ERROR,1);
	
	yhs_set_server_log_callback(server,&default_log_callback,0);
    
	yhs_set_server_name(server,"yhs");
    
    return server;
}

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

void yhs_set_server_name(yhsServer *server,const char *name)
{
	strncpy(server->name,name,sizeof server->name);
	server->name[sizeof server->name-1]=0;
}

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

void yhs_delete_server(yhsServer *server)
{
    yhsHandler *h;
    
    if(!server)
        return;
    
    h=server->handlers.next;
    while(h->handler_fn)
    {
        yhsHandler *next=h->next;
        
		FREE(h->description);
        FREE(h->res_path);
        FREE(h);
        
        h=next;
    }
    
    if(server->listen_sock!=INVALID_SOCKET)
        CLOSESOCKET(server->listen_sock);
    
    FREE(server);
}

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

static int select_socket(SOCKET sock,int num_seconds,int *is_readable,int *is_writeable)
{
    struct timeval timeout;
    fd_set read_fds,write_fds;
    int nfds=0;
    
    timeout.tv_sec=num_seconds;
    timeout.tv_usec=0;
    
#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable:4127)
#endif

	if(is_readable)
	{
		FD_ZERO(&read_fds);
		FD_SET(sock,&read_fds);
	}

	if(is_writeable)
	{
		FD_ZERO(&write_fds);
		FD_SET(sock,&write_fds);
	}
#ifdef _MSC_VER
#pragma warning(pop)
#endif
    
#ifndef WIN32
    nfds=sock+1;
#endif//WIN32
    
	if(select(nfds,is_readable?&read_fds:0,is_writeable?&write_fds:0,NULL,&timeout)<0)
        return 0;
    
	if(is_readable)
		*is_readable=FD_ISSET(sock,&read_fds);

	if(is_writeable)
		*is_writeable=FD_ISSET(sock,&write_fds);

    return 1;
}

// Accepts request and stores header. *data_size is set to total data read,
// maybe including part of the payload; *request_size points just after the
// \r\n\r\n that terminates the request header.
static int accept_request(yhsServer *server,SOCKET *accepted_sock)
{
    struct sockaddr_in client_addr;
    socklen_t client_addr_size=sizeof client_addr;
    int is_accept_waiting;
	char client_addr_str[100];
    
    // Maybe accept request?
    if(!select_socket(server->listen_sock,0,&is_accept_waiting,0))
    {
        SERVER_SOCKET_ERROR(server,"Check listen socket readability.");
        // @TODO: Should close and re-open socket if this happens.
        return 0;
    }
    
    if(!is_accept_waiting)
        return 0;//nobody waiting.
    
    // Accept socket.
    *accepted_sock=accept(server->listen_sock,(struct sockaddr *)&client_addr,&client_addr_size);
    if(*accepted_sock<0)
    {
        SERVER_SOCKET_ERROR(server,"Accept incoming connection on listen socket.");
        return 0;
    }
	
#ifndef _WIN32

	// Suppress SIGPIPE. I am quite capable of checking return values
	// each time. (Well... I think.)
	{
		int value=1;
		if(setsockopt(*accepted_sock,SOL_SOCKET,SO_NOSIGPIPE,&value,sizeof value)<0)
		{
			SERVER_SOCKET_ERROR(server,"Set SO_NOSIGPIPE on accepted socket.");
			return 0;
		}
	}

#endif//_WIN32
	
	inet_ntop(AF_INET,&client_addr.sin_addr,client_addr_str,sizeof client_addr_str);
	SERVER_DEBUG(server,"%s: connection from %s port %d\n",__FUNCTION__,client_addr_str,ntohs(client_addr.sin_port));
    
    return 1;
}

static int read_request_header(yhsServer *server,SOCKET sock,char *buf,size_t buf_size,size_t *request_size)
{
    // Keep reading until the data ends with the \r\n\r\n that signifies the
    // end of the request, or there's no more buffer space.
    int good=0;
    
    *request_size=0;
    
    for(;;)
    {
        int is_data_waiting,n;
        
        if(!select_socket(sock,EXPECTED_DATA_TIMEOUT,&is_data_waiting,0))
        {
            SERVER_SOCKET_ERROR(server,"Check accepted socket readability.");
            break;
        }
        
        if(!is_data_waiting)
        {
            // The polling timeout is deliberately set high; if there's no
            // data waiting in that time, the client must have given up.
            SERVER_SOCKET_ERROR(server,"Timed out waiting for client to send request.");
            break;
        }
        
        if(*request_size==buf_size)
        {
            // Too much data in request header.
            SERVER_ERROR(server,"Request too large.");
            break;
        }
        
        n=recv(sock,buf+*request_size,1,0);
        if(n<=0)
        {
            // Error, or client closed connection prematurely.
            if(n<0)
                SERVER_SOCKET_ERROR(server,"Read accepted socket.");
            
            break;
        }
        
        *request_size+=n;
        
        // Is there a \r\n\r\n yet?
        if(*request_size>=4)
        {
			if(strncmp(buf+*request_size-4,"\r\n\r\n",4)==0)
			{
				// 0-terminate so it ends with a single \r\n, and adjust the
                // size accordingly.
				*(buf+*request_size-2)=0;
				*request_size-=2;

				good=1;

				// Any associated data from the browser is in the socket's recv
				// buffer.

				goto done;
			}
		}
    }
    
done:;
    return good;
}    

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

static char unhex(char nybble)
{
    char c=(char)tolower(nybble);
    
    if(c>='a'&&c<='f')
        return 10+(c-'a');
    else if(c>='0'&&c<='9')
        return c-'0';
    else
        return 0;
}

static char *fix_up_uri(char *uri_arg)
{
    // @TODO: IE lets you type, like, "http:\\xyz\etc" - how does that end up?
    static char http_prefix[]="http://";
    
    char *uri=uri_arg;
    
    if(STRNICMP(uri,http_prefix,sizeof http_prefix-1)==0)
    {
        // Skip prefix
        uri+=sizeof http_prefix-1;
        
        // Skip hostname
        uri=strchr(uri,'/');
        
        if(!uri)
        {
            // Malformed URI, I think? Return something sensible anyway.
            return 0;
        }
    }
    
    // Sort out '%' in the URI.
    //
    // http://www.ietf.org/rfc/rfc2396.txt
    {
        char *src=uri,*dest=uri;
        
        while(*src!=0)
        {
            if(src[0]=='%'&&isxdigit(src[1])&&isxdigit(src[2]))
            {
                *dest++=(unhex(src[1])<<4)|(unhex(src[2])<<0);
                src+=3;
            }
            else
                *dest++=*src++;
        }
        
        *dest=0;
    }
    
    return uri;
}

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

static int is_separator_char(char c)
{
	switch(c)
	{
	default:
		return 0;

	case '(':
	case ')':
	case '<':
	case '>':
	case '@':
	case ',':
	case ';':
	case ':':
	case '\\':
	case '"':
	case '{':
	case '}':
	case ' ':
	case '\t':
		return 1;
	}
}

static int is_token_char(char c)
{
	if(c<0)
		return 0;

	if(c>127)
		return 0;

	if(is_separator_char(c))
		return 0;

	if(iscntrl(c))
		return 0;

	return 1;
}

static int is_lws_char(char c)
{
	switch(c)
	{
	default:
		return 0;

	case ' ':
	case '\t':
		return 1;
	}
}

// pack keys and values tightly in the buffer.
static int pack_request_fields(char *fields)
{
	char *dest=fields;
	char *src=fields;

	while(*src!=0)
	{
		if(is_lws_char(*src))
		{
			// process continuation line.
			if(dest==fields)
			{
				// first line may not be a continuation line.
				return 0;
			}

			// back up to overwrite the '\x0'.
			--dest;
			assert(*dest==0);

			// collapse upcoming spaces into a single space.
			*dest++=' ';
		}
		else
		{
			while(is_token_char(*src))
				*dest++=*src++;

			if(*src!=':')
			{
				// ummm... no.
				return 0;
			}

			// 0-terminate the field key.
			*dest++=0;
			++src;
		}

		// copy field value.

		// skip any spaces.
		while(is_lws_char(*src))
			++src;

		// copy the chars.
		while(*src!='\r')
		{
			if(*src==0)
			{
				// ummm... no.
				return 0;
			}

			*dest++=*src++;
		}

		// 0-terminate the field value.
		*dest++=0;
		++src;

		// all newlines must be CRLF.
		if(*src!='\n')
		{
			// not CRLF.
			return 0;
		}

		++src;
	}

	// pop a final 0 in, to signal the end.
	*dest=0;

	return 1;
}

// Takes an HTTP request (request line, then header lines) and fishes out the
// interesting parts: method, resource path, pointer to first header line.
static int process_request_header(char *request,size_t *method_pos,size_t *res_path_pos,size_t *first_header_line_pos)
{
	char *method;
	char *uri;
	const char *http_version;

	// find line end - first header line is just past it
	char *line_end=strstr(request,"\r\n");
	if(!line_end)
		return 0;

	*first_header_line_pos=line_end+2-request;

	// 0-terminate first line
	*line_end=0;

	// find the parts.
	method=strtok(request," ");
	uri=strtok(0," ");
	http_version=strtok(0," ");

	// fix up URI.
	uri=fix_up_uri(uri);
	if(!uri)
		return 0;

	// turn them into offsets.
	*method_pos=method-request;
	*res_path_pos=uri-request;
	(void)http_version;

	// pack the request fields.
	if(!pack_request_fields(request+*first_header_line_pos))
		return 0;

    return 1;
}

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

// yhsResPathHandlerFn that prints a 404 message.
//static void error_handler(yhsRequest *re,void *context,yhsResPathHandlerArgs *args)
//{
//    yhs_data_response(re,"text/html");
//    
//    yhs_textf(re,"<html>\n");
//    yhs_textf(re," <head>\n");
//    yhs_textf(re,"  <title>%s</title>\n",context);
//    yhs_textf(re," </head>\n");
//    yhs_textf(re," <body>\n");
//    yhs_textf(re,"  <h1>%s</h1>",context);
//    yhs_textf(re,"  <hr>\n");
//    yhs_textf(re,"  <p>HTTP Method: <tt>%s</tt></p>",args->method);
//    yhs_textf(re,"  <p>Resource Path: <tt>%s</tt></p>",args->res_path);
//    yhs_textf(re,"  <hr>\n");
//    yhs_textf(re,"  <i>yocto HTTP server - compiled at %s on %s</i>\n",__TIME__,__DATE__);
//    yhs_textf(re," </body>\n");
//    yhs_textf(re,"</html>");
//}

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

// Finds most appropriate res path handler for the given res path, which may
// refer to a file or a folder.
static const yhsHandler *find_handler_for_res_path(yhsServer *server,const char *res_path,yhsMethod method)
{
    const yhsHandler *h;
    size_t res_path_len=strlen(res_path);
    
    for(h=server->handlers.prev;h->handler_fn;h=h->prev)
    {
		if(h->valid_methods&method)
		{
			if(res_path_len>=h->res_path_len)
			{
				if(strncmp(h->res_path,res_path,h->res_path_len)==0)
				{
					if(res_path_len==h->res_path_len||h->res_path[h->res_path_len-1]=='/')
						return h;
				}
			}
		}
    }

    return 0;
}

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

// TODO: fix wayward layering.
static void close_connection_forcibly(yhsRequest *re,const char *reason);

static int send_unbuffered_bytes(yhsRequest *re,const void *data,size_t num_bytes)
{
	const char *src=(const char *)data;
	int left=num_bytes;

	while(left>0)
	{
		int n=send(re->sock,src,left,0);
		if(n<=0)
		{
			SERVER_SOCKET_ERROR(re->server,"write.");
			close_connection_forcibly(re,__FUNCTION__);
			return 0;
		}

		src+=n;
		left-=n;
	}

	return 1;
}

static int send_unbuffered_frame(yhsRequest *re,WebSocketOpcode opcode,int fin,const void *data,size_t data_size)
{
	uint8_t h[MAX_WEBSOCKET_HEADER_SIZE];
	size_t i=0;

	{
		// <pre>
		//  7   6    5    4    3      0
		//  FIN RSV1 RSV2 RSV3  OPCODE
		// +---+----+----+----+--------+
		// |fin| 0  | 0  | 0  |(opcode)|
		// +---+----+----+----+--------+

		assert((opcode&~0x0F)==0);

		if(fin)
			opcode=(WebSocketOpcode)(opcode|0x80);

		h[i++]=(uint8_t)opcode;
	}

	if(data_size<=125)
	{
		// <pre>
		//  7    6      0
		//  MASK   SIZE
		// +----+--------+
		// | 0  | size   |
		// +----+--------+
		h[i++]=(uint8_t)data_size;
	}
	else if(data_size<=65535)
	{
		// <pre>
		//  7    6   0
		//  MASK  SIZE   15    8   7      0
		// +----+-----+ +-------+ +-------+
		// | 0  | 126 | | data_size_bytes |
		// +----+-----+ +-------+ +-------+
		h[i++]=126;
		h[i++]=(uint8_t)(data_size>>8);
		h[i++]=(uint8_t)(data_size>>0);
	}
	else
	{
		// <pre>
		//  7    6   0
		//  MASK  SIZE   63  56   55  48   47  40   39  32   31  24   23  16   15   8   7    0
		// +----+-----+ +------+ +------+ +------+ +------+ +------+ +------+ +------+ +------+
		// | 0  | 127 | |                  data_size_bytes                                    |
		// +----+-----+ +------+ +------+ +------+ +------+ +------+ +------+ +------+ +------+
		h[i++]=127;
		h[i++]=(uint8_t)((uint64_t)data_size>>56);
		h[i++]=(uint8_t)((uint64_t)data_size>>48);
		h[i++]=(uint8_t)((uint64_t)data_size>>40);
		h[i++]=(uint8_t)((uint64_t)data_size>>32);
		h[i++]=(uint8_t)((uint64_t)data_size>>24);
		h[i++]=(uint8_t)((uint64_t)data_size>>16);
		h[i++]=(uint8_t)((uint64_t)data_size>>8);
		h[i++]=(uint8_t)((uint64_t)data_size>>0);
	}

	assert(i<=MAX_WEBSOCKET_HEADER_SIZE);

	if(!send_unbuffered_bytes(re,h,i))
		return 0;

	if(data_size>0)
	{
		if(!send_unbuffered_bytes(re,data,data_size))
			return 0;
	}

	return 1;
}

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

static void flush_data(yhsRequest *re)
{
	send_unbuffered_bytes(re,re->wbuf.data,re->wbuf.data_size);
}

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

static void flush_websocket_frame(yhsRequest *re)
{
	if(re->ws.send.opcode==WSO_CONTINUATION&&re->wbuf.data_size==0)
	{
		// don't bother sending anything in this case.
		//
		// (the check comes before a byte is written! - so if the frame is
		// an exact multiple of the write buffer in size, it'll be
		// filled but unwritten when the end frame function is called and
		// so FIN will be set appropriately and there will be some non-zero
		// amount of stuff to write. there's no situation where
		// an empty FIN packet needs to be sent, since yhs doesn't support
		// sending empty frames (they don't appear to be useful). DO NOT
		// RETHINK THIS... you'll only get it wrong again.)
		return;
	}

	if(send_unbuffered_frame(re,re->ws.send.opcode,re->ws.send.fin,re->wbuf.data,re->wbuf.data_size))
	{
		// if another packet is going to get sent, it will be a
		// continuation one, so change the opcode here.
		re->ws.send.opcode=WSO_CONTINUATION;
	}
}

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

// send data to client, with some buffering.

static void flush_write_buf(yhsRequest *re)
{
	if(re->wbuf.flush_fn)
	{
		WriteBufferFlushFn flush_fn=re->wbuf.flush_fn;

		re->wbuf.flush_fn=0;

		(*flush_fn)(re);

		re->wbuf.flush_fn=flush_fn;
		re->wbuf.data_size=0;
	}
}

static void send_byte(yhsRequest *re,uint8_t value)
{
	if(re->wbuf.data_size==WRITE_BUF_SIZE)
		flush_write_buf(re);

	assert(re->wbuf.data_size<WRITE_BUF_SIZE);
	re->wbuf.data[re->wbuf.data_size++]=value;
}

static void send_string(yhsRequest *re,const char *str)
{
	const char *c;

	for(c=str;*c!=0;++c)
		send_byte(re,*c);
}

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

static void reset_request(yhsRequest *re)
{
	memset(re,0,sizeof *re);

	re->sock=INVALID_SOCKET;
}

static void close_connection_forcibly(yhsRequest *re,const char *reason)
{
	if(reason)
		SERVER_DEBUG(re->server,"%s: reason: \"%s\"\n",__FUNCTION__,reason);

	if(re->type==RT_WEBSOCKET)
		re->ws.state=WSS_CLOSED;

	if(re->sock!=INVALID_SOCKET)
	{
		CLOSESOCKET(re->sock);
		re->sock=INVALID_SOCKET;
	}

	FREE(re->form.controls);
	re->form.controls=0;

	FREE(re->form.controls_data_buffer);
	re->form.controls_data_buffer=0;

	if(re->flags&RF_OWN_HEADER_DATA)
	{
		FREE(re->hdr.data);
		re->hdr.data=0;
	}
}

static void do_websocket_closing_handshake(yhsRequest *re);

static void close_connection_cleanly(yhsRequest *re)
{
	flush_write_buf(re);

	switch(re->type)
	{
		default:
			break;
			
		case RT_IMAGE:
			assert(re->png.y==re->png.h);
			break;
			
		case RT_WEBSOCKET:
			do_websocket_closing_handshake(re);
			break;
	}

	if(shutdown(re->sock,SD_SEND)<0)
		SERVER_SOCKET_ERROR(re->server,"shutdown with SD_SEND during clean close - this error will be ignored");

	for(;;)
	{
		char tmp;
		int n=recv(re->sock,&tmp,1,0);
		if(n<1)
		{
			// don't bother mentioning the error - it's probably just the
			// connection reset message from the client forcibly closing the
			// connection.
			break;
		}
	}

	close_connection_forcibly(re,0);
}

static void header(yhsRequest *re,yhsResponseType type,const char *status)
{
	assert(re->type==RT_NONE_SET);
	assert(re->state==RS_NONE);

	re->type=type;

	send_string(re,"HTTP/1.1 ");
	send_string(re,status);
	send_string(re,"\r\n");

	re->state=RS_HEADER;
}

static void ensure_header_finished(yhsRequest *re)
{
	// If still sending the header, finish it off.
	if(re->state==RS_HEADER)
	{
		send_string(re,"\r\n");

		re->state=RS_DATA;
	}
}

static void send_response_byte(yhsRequest *re,uint8_t value)
{
	assert(re->state==RS_HEADER||re->state==RS_DATA);

	ensure_header_finished(re);

	if(re->method!=YHS_METHOD_HEAD)
		send_byte(re,value);
}

static void debug_dump_string(yhsServer *server,const char *str,int max_len)
{
    int i;
    
    for(i=0;(max_len<0||i<max_len)&&str[i]!=0;++i)
    {
        switch(str[i])
        {
        case '\n':
            SERVER_DEBUG(server,"\\n");
            break;
            
        case '\r':
            SERVER_DEBUG(server,"\\r");
            break;
            
        case '\t':
            SERVER_DEBUG(server,"\\t");
            break;
            
        case '"':
            SERVER_DEBUG(server,"\\\"");
            break;
            
        default:
            SERVER_DEBUG(server,"%c",str[i]);
            break;
        }
    }
}

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

static void handle_toc(yhsRequest *re)
{
	yhsHandler *h;

	yhs_begin_data_response(re,"text/html");
	
	yhs_textf(re,"<html>\n");
	yhs_html_textf(re," <head><title>\a+%s\a- - Contents</title></head>\n",re->server->name);
	yhs_textf(re," <body>\n");
	yhs_html_textf(re," <h1>\a+%s\a- - Contents</h1>\n",re->server->name);
	
	for(h=re->server->handlers.next;h->handler_fn;h=h->next)
	{
		if(h->flags&HF_TOC)
		{
			yhs_html_textf(re," <p><a href=\"\a+%s\a-\">",h->res_path);
			
			if(h->description)
				yhs_html_textf(re,"\a+%s (",h->description);

			yhs_html_textf(re,"<tt>\a+%s\a-</tt>",h->res_path);

			if(h->description)
				yhs_textf(re,")");

			yhs_textf(re,"\n");
		}
	}
	
	yhs_textf(re," </body>\n");
	yhs_textf(re,"</html>\n");
}

static const yhsHandler toc_handler={
	NULL,NULL,
	0,
	YHS_METHOD_GET|YHS_METHOD_HEAD,
	"/",1,
	"TOC handler",
	&handle_toc,
	NULL,
};

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

const char *yhs_get_path(yhsRequest *re)
{
	const char *path=re->hdr.data+re->hdr.path_pos;
	return path;
}

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

const char *yhs_get_path_handler_relative(yhsRequest *re)
{
	const char *path=yhs_get_path(re);
	const char *h_path=yhs_get_handler_path(re);
	size_t h_path_len=strlen(h_path);

	// TODO: case-insensitiveness...?
	if(STRNICMP(path,h_path,h_path_len)==0)
	{
		path+=h_path_len;
	}

	return path;
}

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

yhsMethod yhs_get_method(yhsRequest *re)
{
	return re->method;
}

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

const char *yhs_get_method_str(yhsRequest *re)
{
	const char *method=re->hdr.data+re->hdr.method_pos;
	return method;
}

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

const char *yhs_find_header_field(yhsRequest *re,const char *key,const char *last_result)
{
	const char *field;
	
	if(last_result)
	{
		assert(last_result>=re->hdr.data+re->hdr.first_field_pos&&last_result<re->hdr.data+re->hdr.data_size);
		field=last_result+strlen(last_result)+1;
	}
	else
		field=re->hdr.data+re->hdr.first_field_pos;

	for(;;)
	{
		const char *k=field;
		size_t n=strlen(k);
		const char *v=k+n+1;
		
		if(n==0)
			return 0;

		if(STRICMP(k,key)==0)
			return v;

		field=v+strlen(v)+1;
	}
}

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

void *yhs_get_handler_context(yhsRequest *re)
{
	if(!re->handler)
		return 0;
	else
		return re->handler->context;
}

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

const char *yhs_get_handler_path(yhsRequest *re)
{
	if(!re->handler)
		return "";
	else
		return re->handler->res_path;
}

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

static const char WEBSOCKET_MAGIC[]="258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
enum {
	WEBSOCKET_MAGIC_LEN=sizeof WEBSOCKET_MAGIC-1,
};

static const char BASE64_CHARS[]="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
extern const char CHECK_BASE64_CHARS_SIZE[sizeof(BASE64_CHARS)-1==64];
static const char BASE64_PAD='=';

static void make_ws_accept(char *accept,const char *key)
{
	size_t i;
	uint8_t hash[21];
	char *nonce=(char *)ALLOCA(strlen(key)+WEBSOCKET_MAGIC_LEN+1);
	strcpy(nonce,key);
	strcat(nonce,WEBSOCKET_MAGIC);

	yhs_sha1(hash,nonce,strlen(nonce));
	hash[20]=0;

	for(i=0;i<7;++i)
	{
		//  76543210 76543210 76543210
		// +--------+--------+--------+
		// |AAAAAABB|BBBBCCCC|CCDDDDDD|
		// +--------+--------+--------+
		accept[i*4+0]=BASE64_CHARS[hash[i*3+0]>>2];
		accept[i*4+1]=BASE64_CHARS[((hash[i*3+0]<<4)|(hash[i*3+1]>>4))&63];
		accept[i*4+2]=BASE64_CHARS[((hash[i*3+1]<<2)|(hash[i*3+2]>>6))&63];
		accept[i*4+3]=BASE64_CHARS[hash[i*3+2]&63];
	}

	// final quantum is 16 bits. the last char should be '=', so fix up the 'A'
    // that the loop above leaves.
	accept[27]='=';

	accept[28]=0;
}

static int maybe_upgrade_to_websocket(yhsRequest *re)
{
	const char *upgrade,*connection,*sec_websocket_version,*sec_websocket_key;

	// ``The request MUST contain an |Upgrade| header field whose value MUST
    // include the "websocket" keyword.''
	upgrade=yhs_find_header_field(re,"Upgrade",0);
	if(!upgrade)
		return 1;

	if(STRICMP(upgrade,"websocket")!=0)
		return 1;

	// ``The request MUST contain a |Connection| header field whose value MUST
    // include the "Upgrade" token.''
	connection=yhs_find_header_field(re,"Connection",0);
	if(!connection)
		return 1;

	if(STRICMP(connection,"Upgrade")!=0)
		return 1;

	// ``The request MUST include a header field with the name
    // |Sec-WebSocket-Key|. The value of this header field MUST be a nonce
    // consisting of a randomly selected 16-byte value that has been
    // base64-encoded''
	sec_websocket_key=yhs_find_header_field(re,"Sec-WebSocket-Key",0);
	if(!sec_websocket_key)
		return 1;

// 	if(strlen(sec_websocket_key)!=SEC_WEBSOCKET_KEY_LEN)
// 		return;

	if(strspn(sec_websocket_key,BASE64_CHARS)!=SEC_WEBSOCKET_KEY_LEN)
		return 1;

	// ``The request MUST include a header field with the name
    // |Sec-WebSocket-Version|. The value of this header field MUST be 13.''
	sec_websocket_version=yhs_find_header_field(re,"Sec-WebSocket-Version",0);
	if(!sec_websocket_version)
		return 1;

	if(strcmp(sec_websocket_version,"13")!=0)
	{
		// TODO: ``If this version does not match a version understood by the
		// server, the server MUST abort the WebSocket handshake described in
        // this section and instead send an appropriate HTTP error code (such as
		// 426 Upgrade Required) and a |Sec-WebSocket-Version| header field
		// indicating the version(s) the server is capable of understanding.''
		header(re,RT_TEXT,"426 Upgrade Required");
		yhs_header_field(re,"Sec-Websocket-Version","13");
		return 0;
	}

	// Form the accept token.
	make_ws_accept(re->ws.accept_str,sec_websocket_key);

	re->method=YHS_METHOD_WEBSOCKET;

	return 1;
}

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

static int accept_new_connections(yhsServer *server)
{
	int any=0;
	
	for(;;)
	{
		// response gunk
		const char *response_line=NULL;
		yhsRequest re;

		// request and parts
		const char *path,*method;
		char header_data_buf[MAX_REQUEST_SIZE+1];

		reset_request(&re);

		if(!accept_request(server,&re.sock))
			break;

		any=1;
		re.server=server;

		re.server=server;
		re.hdr.data=header_data_buf;

		re.wbuf.flush_fn=&flush_data;

		// read header and 0-terminate so that it ends with a single \r\n.
		if(!read_request_header(server,re.sock,re.hdr.data,MAX_REQUEST_SIZE,&re.hdr.data_size))
		{
			yhs_error_response(&re,"500 Internal Server Error");
			goto done;
		}

		SERVER_DEBUG(server,"REQUEST(RAW): %u/%u bytes:\n---8<---\n",(unsigned)re.hdr.data_size,sizeof header_data_buf);
		debug_dump_string(server,re.hdr.data,-1);
		SERVER_DEBUG(server,"\n---8<---\n");

		if(!process_request_header(re.hdr.data,&re.hdr.method_pos,&re.hdr.path_pos,&re.hdr.first_field_pos))
		{
			yhs_error_response(&re,"400 Bad Request");
			goto done;
		}

		path=yhs_get_path(&re);
		method=yhs_get_method_str(&re);

		SERVER_DEBUG(server,"REQUEST: Method: %s\n",method);
		SERVER_DEBUG(server,"         Res Path: \"%s\"\n",path);

		if(strcmp(method,"GET")==0)
		{
			re.method=YHS_METHOD_GET;

			if(!maybe_upgrade_to_websocket(&re))
				goto done;
		}
		else if(strcmp(method,"HEAD")==0)
			re.method=YHS_METHOD_HEAD;
		else if(strcmp(method,"PUT")==0)
			re.method=YHS_METHOD_PUT;
		else if(strcmp(method,"POST")==0)
			re.method=YHS_METHOD_POST;
		else
			re.method=YHS_METHOD_OTHER;

		re.handler=find_handler_for_res_path(server,path,re.method);

		if(!re.handler)
		{
			if(strcmp(path,"/")==0)
				re.handler=&toc_handler;
			else
			{
				yhs_error_response(&re,"404 Not Found");
				goto done;
			}
		}

		if(re.handler)
		{
			SERVER_DEBUG(server,"         Handler: \"%s\"",re.handler->res_path);

			if(re.handler->description)
				SERVER_DEBUG(server," (%s)",re.handler->description);

			SERVER_DEBUG(server,"\n");
		}

		if(!response_line)
		{
			(*re.handler->handler_fn)(&re);

			if(re.type==RT_NONE_SET)
				yhs_error_response(&re,"404 Not Found");
		}

done:
		if(re.type!=RT_DEFER)
		{
			close_connection_cleanly(&re);
		}
	}

	return any;
}

int yhs_update(yhsServer *server)
{
    int any=0;
	
	switch(server->state)
	{
		default:
			assert(0);
			break;
			
		case SS_NONE:
		{
			if(!create_listen_socket(server))
				server->state=SS_ERROR;
			else
			{
				print_likely_urls(server);
				
				server->state=SS_RUNNING;
			}
		}
			break;
			
		case SS_RUNNING:
		{
			if(accept_new_connections(server))
				any=1;
		}
			break;
			
		case SS_ERROR:
		{
			// erm...
		}
			break;
	}
	
    return any;
}

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

void yhs_set_server_log_callback(yhsServer *server,yhsLogFn fn,void *context)
{
	server->log.fn=fn;
	server->log.context=context;
}

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

void yhs_set_server_log_enabled(yhsServer *server,yhsLogCategory category,yhsBool enabled)
{
	assert(category>=0&&category<YHS_LOG_ENDVALUE);
	
	server->log.enabled[category]=enabled;
}

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

void yhs_begin_data_response(yhsRequest *re,const char *type)
{
    assert(re->type==RT_NONE_SET);
	
	header(re,RT_TEXT,"200 OK");//,"Content-Type",type,(char *)0);
	yhs_header_field(re,"Content-Type",type);
	//yhs_header_field(re,"Connection","close");
}

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

void yhs_textf(yhsRequest *re,const char *fmt,...)
{
    va_list v;
    va_start(v,fmt);
    yhs_textv(re,fmt,v);
    va_end(v);
}

void yhs_textv(yhsRequest *re,const char *fmt,va_list v)
{
    char text[MAX_TEXT_LEN];
    
    vsnprintf(text,sizeof text,fmt,v);
	text[sizeof text-1]=0;
    
    yhs_text(re,text);
}

void yhs_text(yhsRequest *re,const char *text)
{
	const char *c;

	for(c=text;*c!=0;++c)
		send_response_byte(re,*c);
}

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

void yhs_html_textf(yhsRequest *re,const char *fmt,...)
{
    va_list v;
    va_start(v,fmt);
    yhs_html_textv(re,fmt,v);
    va_end(v);
}

void yhs_html_textv(yhsRequest *re,const char *fmt,va_list v)
{
    char text[MAX_TEXT_LEN];
    
    vsnprintf(text,sizeof text,fmt,v);
	text[sizeof text-1]=0;
    
    yhs_html_text(re,text);
}

void yhs_html_text(yhsRequest *re,const char *text)
{
	int escape=1;//@TODO make this configurable with a flag again??
	int br=0;
	int on=0;
	int *esc_flag=NULL;
	const char *c;

	assert(re->type==RT_TEXT);
	
	for(c=text;*c!=0;++c)
	{
		if(esc_flag)
		{
			if(*c=='+')
				*esc_flag=1;
			else if(*c=='-')
				*esc_flag=0;
			else
			{
				// umm...
			}
			
			esc_flag=NULL;
		}
		else
		{
			if(*c=='\a')
				esc_flag=&on;
			else if(*c=='\b')
				esc_flag=&br;
			else if(*c=='<'&&escape&&on)
				yhs_text(re,"&lt;");
			else if(*c=='>'&&escape&&on)
				yhs_text(re,"&gt;");
			else if(*c=='&'&&escape&&on)
				yhs_text(re,"&amp;");
			else if(*c=='"'&&escape&&on)
				yhs_text(re,"&quot;");
			else if(*c=='\n'&&br&&on)
				yhs_text(re,"<BR>");
			else
				yhs_data(re,c,1);
		}
	}
}

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

void yhs_data(yhsRequest *re,const void *data,size_t data_size)
{
	size_t i;
	const uint8_t *p=(const uint8_t *)data;

	for(i=0;i<data_size;++i)
		yhs_data_byte(re,p[i]);
}

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

void yhs_data_byte(yhsRequest *re,unsigned char value)
{
	send_response_byte(re,value);
}

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

static uint32_t yhs_crc_table[256];

static void png8(yhsRequest *re,uint8_t value)
{
    assert(yhs_crc_table[1]!=0);
    
    re->png.chunk_crc=(re->png.chunk_crc>>8)^yhs_crc_table[value^(re->png.chunk_crc&0xFF)];
    
    yhs_data(re,&value,1);
}

static void png8_adler(yhsRequest *re,uint8_t value)
{
    png8(re,value);
    
    re->png.adler32_s1+=value;
    re->png.adler32_s1%=65521;
    
    re->png.adler32_s2+=re->png.adler32_s1;
    re->png.adler32_s2%=65521;
}

static void png32(yhsRequest *re,uint32_t value)
{
    png8(re,(uint8_t)(value>>24));
    png8(re,(uint8_t)(value>>16));
    png8(re,(uint8_t)(value>>8));
    png8(re,(uint8_t)(value>>0));
}

static void start_png_chunk(yhsRequest *re,uint32_t length,const char *name)
{
    if(yhs_crc_table[1]==0)
    {
        // http://nothings.org/stb/stb_image_write.h
        int i,j;
        for(i=0; i < 256; i++)
        {
            for (yhs_crc_table[i]=i, j=0; j < 8; ++j)
                yhs_crc_table[i] = (yhs_crc_table[i] >> 1) ^ (yhs_crc_table[i] & 1 ? 0xedb88320 : 0);
        }
    }
    
    png32(re,length);
    
    re->png.chunk_crc=~0u;
    
    png8(re,name[0]);
    png8(re,name[1]);
    png8(re,name[2]);
    png8(re,name[3]);
    
}

static void end_png_chunk(yhsRequest *re)
{
    png32(re,~re->png.chunk_crc);
}

static const uint8_t png_sig[]={137,80,78,71,13,10,26,10,};

void yhs_begin_image_response(yhsRequest *re,int width,int height,int ncomp)
{
    assert(ncomp==3||ncomp==4);
    assert(re->type==RT_NONE_SET);
	
	header(re,RT_IMAGE,"200 OK");
	yhs_header_field(re,"Content-Type","image/png");

	memset(&re->png,0,sizeof re->png);
    
    re->png.w=width;
    re->png.h=height;
    
    re->png.x=0;
    re->png.y=0;
    
    re->png.adler32_s1=1;
    re->png.adler32_s2=0;
    
    if(ncomp==4)
        re->png.bypp=4;
    else
        re->png.bypp=3;
}

void yhs_pixel(yhsRequest *re,int r,int g,int b,int a)
{
    assert(re->type==RT_IMAGE);
    assert(re->png.y<re->png.h);

	if(re->png.x==0&&re->png.y==0)
	{
		// Send PNG header.
		yhs_data(re,png_sig,8);

		// Obligatory IHDR chunk
		start_png_chunk(re,4+4+1+1+1+1+1,"IHDR");
		png32(re,re->png.w);
		png32(re,re->png.h);
		png8(re,8);//bits per sample

		if(re->png.bypp==4)
			png8(re,6);//colour type (6=RGBA)
		else
			png8(re,2);//colour type (2=RGB)

		png8(re,0);//compression type (0=deflate)
		png8(re,0);//filter type (0=standard set)
		png8(re,0);//interlace type (0=none)
		end_png_chunk(re);

		// IDAT chunk with ZLIB header
		start_png_chunk(re,2,"IDAT");
		png8(re,0x78);//default, 32K window (not that it matters)
		png8(re,1);//compressor used fastest algorithm; no dictionary; +1 for FCHECK.
		end_png_chunk(re);
	}
    
    if(re->png.x==0)
    {
        int nlen=1+re->png.w*re->png.bypp;
        assert(nlen>=0&&nlen<65536);
        
        // 5 for the deflate header; 1 for the filter byte; then the
        // scanline data.
        start_png_chunk(re,5+1+re->png.w*re->png.bypp,"IDAT");
        
        // deflate data
        png8(re,0);//BYTPE=0 (no compression)
        
        png8(re,(uint8_t)(nlen>>0));
        png8(re,(uint8_t)(nlen>>8));
        png8(re,(uint8_t)~(nlen>>0));
        png8(re,(uint8_t)~(nlen>>8));
        
        png8_adler(re,0);///filter type (0=no filter)
    }
    
    png8_adler(re,(uint8_t)r);
    png8_adler(re,(uint8_t)g);
    png8_adler(re,(uint8_t)b);
    
    if(re->png.bypp>3)
        png8_adler(re,(uint8_t)a);
    
    ++re->png.x;
    
    if(re->png.x==re->png.w)
    {
        end_png_chunk(re);
        
        ++re->png.y;
        re->png.x=0;
        
        if(re->png.y==re->png.h)
        {
            // Final IDAT
            
            start_png_chunk(re,5+4,"IDAT");
            
            // 0-byte final uncompressed chunk
            png8(re,1);
            png8(re,0);
            png8(re,0);
            png8(re,(uint8_t)~0);
            png8(re,(uint8_t)~0);
            
            // Zlib checksum
            png32(re,(re->png.adler32_s2<<16)|(re->png.adler32_s1<<0));
            end_png_chunk(re);
            
            start_png_chunk(re,0,"IEND");
            end_png_chunk(re);
        }
    }
}

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

void yhs_error_response(yhsRequest *re,const char *status_line)
{
	yhs_verbose_error_response(re,status_line,NULL);
}

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

void yhs_verbose_error_response(yhsRequest *re,const char *status_line,const char *elaboration)
{
	SERVER_INFO(re->server,"%s: %s\n",__FUNCTION__,status_line);
	
	header(re,RT_TEXT,status_line);
	yhs_header_field(re,"Content-Type","text/html");
    
    yhs_textf(re,"<html>\n");
    yhs_textf(re," <head>\n");
    yhs_html_textf(re,"  <title>\a+%s - %s\a-</title>\n",re->server->name,status_line);
    yhs_textf(re," </head>\n");
    yhs_textf(re," <body>\n");
    yhs_html_textf(re,"  <h1>\a+%s - %s\a-</h1>",re->server->name,status_line);
    yhs_textf(re,"  <hr>\n");

	if(elaboration)
		yhs_html_textf(re,"  <p>\a+%s\a-</p>",elaboration);
	
	yhs_textf(re,"  <p>HTTP Method: <tt>%s</tt></p>",yhs_get_method_str(re));
	yhs_html_textf(re,"  <p>Resource Path: <tt>\a+%s\a-</tt></p>",yhs_get_path(re));
	
    yhs_textf(re,"  <hr>\n");
    yhs_textf(re,"  <i>yocto HTTP server - compiled at %s on %s</i>\n",__TIME__,__DATE__);
    yhs_textf(re," </body>\n");
    yhs_textf(re,"</html>");
}

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

void yhs_see_other_response(yhsRequest *re,const char *destination)
{
	header(re,RT_TEXT,"303 See Other");
	yhs_header_field(re,"Location",destination);
}

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

void yhs_accept_websocket(yhsRequest *re,const char *protocol)
{
	assert(re->method==YHS_METHOD_WEBSOCKET);

	header(re,RT_WEBSOCKET,"101 Switching Protocols");
	yhs_header_field(re,"Sec-WebSocket-Accept",re->ws.accept_str);
	yhs_header_field(re,"Upgrade","websocket");
	yhs_header_field(re,"Connection","Upgrade");

	if(protocol)
		yhs_header_field(re,"Sec-WebSocket-Protocol",protocol);
}

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

static void ensure_websocket_handshake_finished(yhsRequest *re)
{
	assert(re->type==RT_WEBSOCKET);

	if(re->state==RS_HEADER)
	{
		ensure_header_finished(re);

		flush_write_buf(re);

		re->wbuf.flush_fn=&flush_websocket_frame;
		re->ws.state=WSS_OPEN;
	}
}

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

yhsBool yhs_is_websocket_open(yhsRequest *re)
{
	ensure_websocket_handshake_finished(re);

	if(re->type==RT_WEBSOCKET&&re->ws.state==WSS_OPEN)
		return 1;

	return 0;
}

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

static int recv_websocket_bytes(yhsRequest *re,void *buf,int buf_size,const char *msg)
{
	char *dest=(char *)buf;
	int left=buf_size;

	while(left>0)
	{
		int n;
		
		if(dest)
			n=recv(re->sock,dest,left,0);
		else
		{
			char tmp;
			n=recv(re->sock,&tmp,1,0);
		}

		if(n==-1)
		{
			SERVER_SOCKET_ERROR(re->server,msg);
			close_connection_forcibly(re,__FUNCTION__);
			return -1;
		}
		else if(n==0)
		{
			SERVER_ERROR(re->server,"endpoint closed web socket connection prematurely");
			close_connection_forcibly(re,__FUNCTION__);
			return 0;
		}

		if(dest)
			dest+=n;

		left-=n;
	}

	return buf_size;
}

static int recv_websocket_frame_header(yhsRequest *re,WebSocketFrameHeader *fh)
{
	int rr;
	uint8_t header[2];

	// Read the 2 header bytes.
	rr=recv_websocket_bytes(re,header,2,"recv web socket frame header");
	if(rr<=0)
		return rr;

	fh->opcode=header[0]&0x0F;
	fh->fin=!!(header[0]&0x80);
	fh->mask=!!(header[1]&0x80);
	fh->len=header[1]&0x7F;

	//SERVER_INFO(server,"recv_websocket_frame_header: (opcode=%d; fin=%d; mask=%d; len=%d).\n",fh->opcode,fh->fin,fh->mask,fh->len);

	// (in)sanity checks
	if((header[0]&(0x40|0x20|0x10))!=0)
	{
		SERVER_ERROR(re->server,"received web socket frame with RSV1, RSV2 or RSV3 set");
		goto bad;
	}

	if(!fh->mask)
	{
		// ``All frames sent from client to server have this bit set to
		// 1.''
		SERVER_ERROR(re->server,"received unmasked web socket frame");
		goto bad;
	}

	// Get payload length.
	if(fh->len==127)
	{
		uint64_t len;
		uint8_t buf[8];
		rr=recv_websocket_bytes(re,buf,8,"recv web socket frame 64-bit payload length");
		if(rr<=0)
			return rr;

		len=((uint64_t)buf[0]<<56)|((uint64_t)buf[1]<<48)|((uint64_t)buf[2]<<40)|((uint64_t)buf[3]<<32)|(buf[4]<<24)|(buf[5]<<16)|(buf[6]<<8)|(buf[7]<<0);

		if(len>INT_MAX)
		{
			SERVER_ERROR(re->server,"received unsupportedly large web socket frame");
			goto bad;
		}

		fh->len=(int)len;
		//SERVER_INFO(server,"64-bit: %d\n",fh->len);
	}
	else if(fh->len==126)
	{
		uint8_t buf[2];
		rr=recv_websocket_bytes(re,buf,2,"recv web socket frame 16-bit payload length");
		if(rr<=0)
			return rr;

		fh->len=(buf[0]<<8)|(buf[1]<<0);


		//SERVER_INFO(server,"16-bit: %d\n",fh->len);
	}
	else
	{
		//SERVER_INFO(server,"8-bit: %d\n",fh->len);
	}

	// Read mask.
	if(fh->mask)
	{
		rr=recv_websocket_bytes(re,fh->masking_key,4,"recv web socket masking key");
		if(rr<=0)
			return rr;
	}

	return 1;

bad:
	close_connection_forcibly(re,__FUNCTION__);
	return -1;
}

// do_control_frames reads and processes control frames from the websocket
// until a data frame is received or there's nothing left to do.

enum DoControlFramesMode
{
	// keep processing control frames as long as some are available.
	// if a data frame arrives, set *got_data_frame and return without
	// error; if no data on web socket, reset *got_data_frame and return
	// without error.
	DCFM_POLL_OR_READ_DATA,
	
	// keep processing control frames as long as some are available. if
	// no data on web socket, block. if a data frame is available, set
	// *got_data_frame and return without error. (in BLOCK_AND_READ_DATA
	// mode, do_control_frames will never return with *got_data_frame
	// reset.)
	DCFM_BLOCK_AND_READ_DATA,
	
	// spin, waiting for a CLOSE control frame. if data frames are
	// received, they are discarded out of hand without being checked.
	DCFM_WAIT_FOR_CLOSE,
};
typedef enum DoControlFramesMode DoControlFramesMode;

static int do_control_frames(yhsRequest *re,WebSocketFrameHeader *fh,int *got_data_frame,DoControlFramesMode mode)
{
	uint8_t payload[125];
	int rr;


	//SERVER_INFO(re->server,"%s\n",__FUNCTION__);

	for(;;)
	{
		if(mode==DCFM_POLL_OR_READ_DATA)
		{
			int is_data_waiting;

			//SERVER_INFO(re->server,"    select_socket.\n");
			if(!select_socket(re->sock,0,&is_data_waiting,0))
			{
				//SERVER_INFO(re->server,"    (bad)\n");
				goto bad;
			}

			// if there's no data waiting, leave in the WSRS_NO_FRAME state.
			if(!is_data_waiting)
			{
				//SERVER_INFO(re->server,"    (no data waiting. not got data frame.)\n");
				*got_data_frame=0;
				return 1;
			}
		}

		// get incoming header.
		//SERVER_INFO(re->server,"    recv_websocket_frame_header.\n");
		rr=recv_websocket_frame_header(re,fh);
		if(rr<=0)
		{
			//SERVER_INFO(re->server,"        (bad; rr=%d)\n",rr);
			goto bad;
		}

		// data frame?
		SERVER_DEBUG(re->server,"%s: got frame: opcode=%d, fin=%d, len=%d.\n",__FUNCTION__,fh->opcode,fh->fin,fh->len);
		if(!(fh->opcode&8))
		{
			switch(fh->opcode)
			{
			default:
				SERVER_ERROR(re->server,"received data frame with unknown opcode");
				goto bad;

			case WSO_CONTINUATION:
			case WSO_TEXT:
			case WSO_BINARY:
				// OK.
				break;
			}

			if(mode==DCFM_WAIT_FOR_CLOSE)
			{
				// discard frame.

				if(fh->len>0)
				{
					// TODO: should really check the frame for validity, but the
					// code is just not structured to make that at all
                    // convenient.
					rr=recv_websocket_bytes(re,0,fh->len,"recv data to discard while awaiting close");
					if(rr<=0)
						goto bad;
				}

				continue;
			}
			else
			{
				// ok - data frame.
				//SERVER_INFO(server,"    (got data frame.).\n",fh->opcode);
				*got_data_frame=1;
				return 1;
			}
		}

		// control frames may not be fragmented.
		if(!fh->fin)
		{
			SERVER_ERROR(re->server,"received fragmented web socket control frame");
			goto bad;
		}

		// control frames must have an 8-bit size field.
		if(fh->len>125)
		{
			SERVER_ERROR(re->server,"received web socket control frame with large payload");
			goto bad;
		}

		// retrieve and unmask payload.
		if(fh->len>0)
		{
			rr=recv_websocket_bytes(re,payload,(int)fh->len,"recv web socket control frame payload");
			if(rr<=0)
				goto bad;

			// unmask payload.
			if(fh->mask)
			{
				int i;

				for(i=0;i<fh->len;++i)
					payload[i]^=fh->masking_key[i&3];
			}
		}

		// do whatever.
		switch(fh->opcode)
		{
		default:
			SERVER_ERROR(re->server,"received unknown web socket control frame");
			goto bad;

		case WSO_PING:
			SERVER_DEBUG(re->server,"%s: received PING (%d bytes payload). Sending PONG.\n",__FUNCTION__,fh->len);
			send_unbuffered_frame(re,WSO_PONG,1,payload,(size_t)fh->len);
			break;

		case WSO_PONG:
			SERVER_DEBUG(re->server,"%s: received PONG. Ignoring.\n",__FUNCTION__);
			// ignore pongs.
			break;

		case WSO_CLOSE:
			{
				SERVER_DEBUG(re->server,"%s: received CLOSE frame.\n",__FUNCTION__);

				if(re->ws.state==WSS_OPEN)
				{
					send_unbuffered_frame(re,WSO_CLOSE,1,0,0);

					re->ws.state=WSS_CLOSING;
				}

				close_connection_cleanly(re);

				*got_data_frame=0;
			}
			return 1;
		}
	}

bad:
	close_connection_forcibly(re,__FUNCTION__);
	return 0;
}

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

static int begin_recv_websocket_frame(yhsRequest *re,int *is_text)
{
	int got_data_frame;

	if(!do_control_frames(re,&re->ws.recv.fh,&got_data_frame,DCFM_POLL_OR_READ_DATA))
		return 0;

	if(!got_data_frame)
		return 0;

	if(re->ws.recv.fh.opcode==WSO_TEXT)
		re->ws.recv.is_text=1;
	else if(re->ws.recv.fh.opcode==WSO_BINARY)
		re->ws.recv.is_text=0;
	else
	{
 		close_connection_forcibly(re,__FUNCTION__);
 		return 0;
	}

	re->ws.recv.state=WSRS_RECV;
	re->ws.recv.is_fragmented=!re->ws.recv.fh.fin;
	re->ws.recv.offset=0;

	re->ws.recv.utf8_char=0;
	re->ws.recv.utf8_count=0;
	re->ws.recv.utf8_left=0;

	if(is_text)
		*is_text=re->ws.recv.is_text;

	return 1;
}

int yhs_begin_recv_websocket_frame(yhsRequest *re,int *is_text)
{
	ensure_websocket_handshake_finished(re);

	if(!yhs_is_websocket_open(re))
		return 0;

	return begin_recv_websocket_frame(re,is_text);
}

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

void yhs_end_recv_websocket_frame(yhsRequest *re)
{
	if(re->ws.recv.state!=WSRS_NONE)
	{
		// there's some data hanging around, so just discard it.
		for(;;)
		{
			char tmp;
			size_t n;
			int good=yhs_recv_websocket_data(re,&tmp,1,&n);
			if(!good)
				return;

			if(n==0)
				break;
		}

		assert(re->ws.recv.state==WSRS_DONE);
	}
}

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

static int recv_websocket_data(yhsRequest *re,void *buf,size_t buf_size,size_t *n)
{
	//int result=-1;
	int rr;
	uint8_t *dest;
	int dest_size;

	assert(buf_size<=INT_MAX);
	assert(buf);

	dest=(uint8_t *)buf;
	dest_size=(int)buf_size;

	// loop on incoming packets.
	for(;;)
	{
		switch(re->ws.recv.state)
		{
		default:
		case WSRS_NONE:
			assert(0);
			break;

		case WSRS_RECV:
			{
				int num_to_recv;

				assert(re->ws.recv.fh.opcode==WSO_CONTINUATION||re->ws.recv.fh.opcode==WSO_TEXT||re->ws.recv.fh.opcode==WSO_BINARY);

				// how many bytes to recv?
				{
					int num_left=re->ws.recv.fh.len-re->ws.recv.offset;

					num_to_recv=dest_size;
					if(num_to_recv>num_left)
						num_to_recv=num_left;
				}

				// recv that many.
				if(num_to_recv==0)
					rr=0;
				else
				{
					rr=recv_websocket_bytes(re,dest,num_to_recv,"recv web socket data frame payload");
					if(rr<=0)
						goto bad;
				}

				// unmask
				if(re->ws.recv.fh.mask)
				{
					int i;

					for(i=0;i<rr;++i)
						dest[i]^=re->ws.recv.fh.masking_key[(re->ws.recv.offset+i)&3];
				}

				// validate UTF-8
				if(re->ws.recv.is_text)
				{
					int i;

					for(i=0;i<rr;++i)
					{
						//printf("i=%d: dest[i]=%d (0x%X); utf8_count=%d; utf8_left=%d; utf8_char=%d (0x%X).\n",i,dest[i],dest[i],re->ws.recv.utf8_count,re->ws.recv.utf8_left,re->ws.recv.utf8_char,re->ws.recv.utf8_char);

						if(re->ws.recv.utf8_left==0)
						{
							re->ws.recv.utf8_char=0;

							if((dest[i]&0x80)==0)
							{
								// <pre>
								//   7   6   5   4   3   2   1   0
								// +---+---+---+---+---+---+---+---+
								// | 0 |         value             |
								// +---+---+---+---+---+---+---+---+
								re->ws.recv.utf8_count=1;
								//re->ws.recv.utf8_char=dest[i]&0x7F;

								// no validation is required in this case.
								//
								// all 7-bit values are valid.
							}
							else if((dest[i]>>5)==6)
							{
								// <pre>
								//   7   6   5   4   3   2   1   0
								// +---+---+---+---+---+---+---+---+
								// | 1   1   0 |       value       |
								// +---+---+---+---+---+---+---+---+
								re->ws.recv.utf8_count=2;
								re->ws.recv.utf8_char=dest[i]&0x1F;
							}
							else if((dest[i]>>4)==14)
							{
								// <pre>
								//   7   6   5   4   3   2   1   0
								// +---+---+---+---+---+---+---+---+
								// | 1   1   1   0 |     value     |
								// +---+---+---+---+---+---+---+---+
								re->ws.recv.utf8_count=3;
								re->ws.recv.utf8_char=dest[i]&0x0F;
							}
							else if((dest[i]>>3)==30)
							{
								// <pre>
								//   7   6   5   4   3   2   1   0
								// +---+---+---+---+---+---+---+---+
								// | 1   1   1   1   0 |   value   |
								// +---+---+---+---+---+---+---+---+
								re->ws.recv.utf8_count=4;
								re->ws.recv.utf8_char=dest[i]&7;
							}
							else
							{
								SERVER_ERROR(re->server,"received bad UTF-8 byte 1");
								goto bad;
							}

							re->ws.recv.utf8_left=re->ws.recv.utf8_count-1;
						}
						else
						{
							// <pre>
							//   7   6   5   4   3   2   1   0
							// +---+---+---+---+---+---+---+---+
							// | 1   0 |       value           |
							// +---+---+---+---+---+---+---+---+
							if((dest[i]>>6)==2)
							{
								re->ws.recv.utf8_char<<=6;
								re->ws.recv.utf8_char|=dest[i]&63;
							}
							else
							{
								SERVER_ERROR(re->server,"received bad UTF-8 byte 2+");
								goto bad;
							}
							
							--re->ws.recv.utf8_left;

							if(re->ws.recv.utf8_left==0)
							{
								// Char. number range  |        UTF-8 octet sequence
								//    (hexadecimal)    |              (binary)
								// --------------------+---------------------------------------------
								// 0000 0000-0000 007F | 0xxxxxxx
								// 0000 0080-0000 07FF | 110xxxxx 10xxxxxx
								// 0000 0800-0000 FFFF | 1110xxxx 10xxxxxx 10xxxxxx
								// 0001 0000-0010 FFFF | 11110xxx 10xxxxxx 10xxxxxx 10xxxxxx

								if(re->ws.recv.utf8_count==2)
								{
									assert(re->ws.recv.utf8_char<=0x7FF);
									if(re->ws.recv.utf8_char<0x80)
									{
										SERVER_ERROR(re->server,"received overlong 2-byte UTF-8 sequence");
										goto bad;
									}
								}
								else if(re->ws.recv.utf8_count==3)
								{
									assert(re->ws.recv.utf8_char<=0xFFFF);
									if(re->ws.recv.utf8_char<0x800)
									{
										SERVER_ERROR(re->server,"received overlong 3-byte UTF-8 sequence");
										goto bad;
									}
									else if(re->ws.recv.utf8_char>=0xD800&&re->ws.recv.utf8_char<=0xDFFF)
									{
										SERVER_ERROR(re->server,"received UTF-16 surrogate");
										goto bad;
									}
								}
								else if(re->ws.recv.utf8_count==4)
								{
									if(re->ws.recv.utf8_char<0x10000)
									{
										SERVER_ERROR(re->server,"received overlong 4-byte UTF-8 sequence");
										goto bad;
									}
									else if(re->ws.recv.utf8_char>0x10FFFF)
									{
										SERVER_ERROR(re->server,"received non-Unicode char");
										goto bad;
									}
								}
							}
						}
					}
				}

				// adjust frame length.
				re->ws.recv.offset+=rr;
				assert(re->ws.recv.offset<=re->ws.recv.fh.len);

				// bump bufferstuff.
				if(dest)
					dest+=rr;

				assert(dest_size>=rr);
				dest_size-=rr;

				// if frame is finished, set up state for the next one, if any.
				if(re->ws.recv.offset==re->ws.recv.fh.len)
				{
					if(!re->ws.recv.is_fragmented||re->ws.recv.fh.fin)
					{
						// done - no fragments, or all fragments received.

						if(re->ws.recv.is_text)
						{
							if(re->ws.recv.utf8_left!=0)
							{
								SERVER_ERROR(re->server,"received truncated UTF-8 char");
								goto bad;
							}
						}

						re->ws.recv.state=WSRS_DONE;

						*n=dest-(uint8_t *)buf;
						return 1;
					}
					else
					{
						// more fragments to come, presumably.
						re->ws.recv.state=WSRS_NEXT_FRAGMENT;
					}
				}

				// if buffer is full, done, and stay in this state.
				if(dest_size==0)
				{
					*n=dest-(uint8_t *)buf;
					return 1;
				}

				// go round again...
			}
			break;

		case WSRS_NEXT_FRAGMENT:
			{
				int got_data_frame;
				if(!do_control_frames(re,&re->ws.recv.fh,&got_data_frame,DCFM_BLOCK_AND_READ_DATA))
					goto bad;

				if(!got_data_frame)
					return 0;

				if(re->ws.recv.fh.opcode!=WSO_CONTINUATION)
				{
					SERVER_ERROR(re->server,"received data frame while processing fragmented frame");
					goto bad;
				}

				re->ws.recv.state=WSRS_RECV;
				re->ws.recv.offset=0;
			}
			break;

		case WSRS_DONE:
			{
				*n=0;
				return 1;
			}
			break;
		}
	}

bad:
	close_connection_forcibly(re,__FUNCTION__);
	return 0;
}

int yhs_recv_websocket_data(yhsRequest *re,void *buf,size_t buf_size,size_t *n)
{
	ensure_websocket_handshake_finished(re);

	if(!yhs_is_websocket_open(re))
	{
		// must have been closed in do_control_frames.

		return 0;
	}

	return recv_websocket_data(re,buf,buf_size,n);
}

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

static void do_websocket_closing_handshake(yhsRequest *re)
{
	assert(re->type==RT_WEBSOCKET);

	SERVER_DEBUG(re->server,"%s: ws.state is %d.\n",__FUNCTION__,(int)re->ws.state);

	if(re->ws.state==WSS_OPEN)
	{
		int got_data_frame;

		SERVER_DEBUG(re->server,"%s: send unbuffered CLOSE frame.\n",__FUNCTION__);

		send_unbuffered_frame(re,WSO_CLOSE,1,0,0);

		re->ws.state=WSS_CLOSING;

		// just poll repeatedly, dropping data frames, until the connection dies
        // or do_control_frame returns without a data frame ready, indicating a
        // close was received.
		SERVER_DEBUG(re->server,"%s: wait for CLOSE frame.\n",__FUNCTION__);
		do_control_frames(re,&re->ws.recv.fh,&got_data_frame,DCFM_WAIT_FOR_CLOSE);
	}

	re->ws.state=WSS_CLOSED;
}

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

void yhs_begin_send_websocket_frame(yhsRequest *re,int is_text)
{
	assert(re->type==RT_WEBSOCKET);

	ensure_websocket_handshake_finished(re);

	//flush_write_buf(re);

	assert(re->ws.send.state==WSSS_NONE);
	re->ws.send.state=WSSS_SEND;

	re->ws.send.opcode=is_text?WSO_TEXT:WSO_BINARY;
	re->ws.send.fin=0;
}

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

void yhs_end_send_websocket_frame(yhsRequest *re)
{
	assert(re->type==RT_WEBSOCKET);
	assert(re->ws.send.state==WSSS_SEND);

	re->ws.send.fin=1;

	flush_write_buf(re);

	re->ws.send.state=WSSS_NONE;
}

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

void yhs_header_field(yhsRequest *re,const char *name,const char *value)
{
	assert(re->state==RS_HEADER);

	send_string(re,name);
	send_string(re,": ");
	send_string(re,value);
	send_string(re,"\r\n");
}

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

int yhs_defer_response(yhsRequest *re,yhsRequest **chain)
{
	yhsRequest *dre;
	char *new_header_data;

	// TODO - tidy this up. There's no reason a deferred response couldn't be
    // deferred again, even though it would be a bit pointless.
	assert(!(re->flags&(RF_DEFERRED|RF_OWN_HEADER_DATA)));

	dre=(yhsRequest *)MALLOC(sizeof *dre);
	new_header_data=(char *)MALLOC(re->hdr.data_size);

	if(!dre||!new_header_data)
	{
		// this is no good, but the original response should still be usable.
		FREE(dre);
		FREE(new_header_data);

		return 0;
	}

	*dre=*re;
	dre->flags|=RF_DEFERRED;

	// take a copy of the header data.
	dre->hdr.data=new_header_data;
	memcpy(dre->hdr.data,re->hdr.data,re->hdr.data_size);
	dre->flags|=RF_OWN_HEADER_DATA;

	// add to the links.
	dre->prev_deferred=0;
 	dre->next_deferred=dre->server->first_deferred;

	if(dre->next_deferred)
		dre->next_deferred->prev_deferred=dre;

 	dre->server->first_deferred=dre;

	//
	dre->next_deferred_in_chain=*chain;
	*chain=dre;

	// mark original request as deferred, so it can be discarded.
	reset_request(re);
	re->type=RT_DEFER;

	return 1;
}

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

void yhs_next_request_ptr(yhsRequest **re_ptr)
{
	if(*re_ptr)
		re_ptr=&(*re_ptr)->next_deferred_in_chain;
}

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

void yhs_end_deferred_response(yhsRequest **re_ptr)
{
	yhsRequest *re=*re_ptr;

	*re_ptr=re->next_deferred_in_chain;

	close_connection_cleanly(re);

	assert(re->flags&RF_DEFERRED);

	if(re->prev_deferred)
		re->prev_deferred->next_deferred=re->next_deferred;
	else
	{
		assert(re->server->first_deferred==re);
		re->server->first_deferred=re->next_deferred;
	}

	if(re->next_deferred)
		re->next_deferred->prev_deferred=re->prev_deferred;

	FREE(re);
}

// void yhs_end_deferred_response(yhsRequest *re)
// {
// 	assert(re->flags&RF_DEFERRED);
//     
//     finish_response(re);
// 
// 	FREE(re);
// }

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

yhsBool yhs_get_content_details(yhsRequest *re,const char **type,int *length)
{
	yhsBool got=0;
	const char *t=yhs_find_header_field(re,"Content-Type",0);
	const char *l_str=yhs_find_header_field(re,"Content-Length",0);
	int l=0;
	
	if(l_str)
		l=atoi(l_str);

	if(l>0)
	{
		if(type)
			*type=t;
		
		if(length)
			*length=l;
		
		got=1;
	}
	
	return got;
}

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

int yhs_get_content(yhsRequest *re,int num,char *buf)
{
    int num_recvd=0;
    
    while(num_recvd<num)
    {
        int r,is_readable;
        
        if(!select_socket(re->sock,EXPECTED_DATA_TIMEOUT,&is_readable,0))
        {
            SERVER_SOCKET_ERROR(re->server,"check socket readability.");
            return 0;
        }
        
        if(!is_readable)
            break;
        
        r=recv(re->sock,buf+num_recvd,num-num_recvd,0);
        
        if(r==-1)
        {
            SERVER_SOCKET_ERROR(re->server,"recv.");
            return 0;
        }
        else if(r==0)
        {
            // Other side closed connection...
            return 0;
        }
        
        num_recvd+=r;
    }
    
    if(num_recvd<num)
        return 0;
    
    return 1;
}

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

YHS_EXTERN int yhs_read_form_content(yhsRequest *re)
{
	const char *content_type;
	const char *content_length_str;
	int content_length;
    int good=0;

	// Check there's actually some content attached.
	content_type=yhs_find_header_field(re,"Content-Type",0);
	content_length_str=yhs_find_header_field(re,"Content-Length",0);
	if(!content_type||!content_length_str)
		goto done;
    
    // Sorry, only application/x-www-form-urlencoded for now.
    if(strcmp(content_type,"application/x-www-form-urlencoded")!=0)
        goto done;
    
	//
	content_length=atoi(content_length_str);
    if(content_length==0)
        goto done;
    
    // Get form data and pop a \0x at the end.
	assert(!re->form.controls_data_buffer);
    re->form.controls_data_buffer=(char *)MALLOC(content_length+1);
    if(!re->form.controls_data_buffer)
        goto done;
    
    if(!yhs_get_content(re,content_length,re->form.controls_data_buffer))
        goto done;
    
    re->form.controls_data_buffer[content_length]=0;
    
    // Count controls.
    re->form.num_controls=1;
    {
        int i;
        
        for(i=0;re->form.controls_data_buffer[i]!=0;++i)
        {
            if(re->form.controls_data_buffer[i]=='&')
                ++re->form.num_controls;
        }
    }
    
    // Controls...
    re->form.controls=(KeyValuePair *)MALLOC(re->form.num_controls*sizeof *re->form.controls);
	if(!re->form.controls)
		goto done;
    
    //
    {
        KeyValuePair *control=re->form.controls;
        char *dest=re->form.controls_data_buffer;
        const char *src=re->form.controls_data_buffer;
        
        while(src<re->form.controls_data_buffer+content_length)
        {
            assert(control<re->form.controls+re->form.num_controls);
            
            // Store control name
            control->key=dest;
            
            while(*src!='=')
                *dest++=*src++;
            
            ++src;//skip '='
            *dest++=0;//terminate name
            
            // Store control value
            control->value=dest;
            
            while(*src!='&'&&*src!=0)
            {
                char c=*src++;
                
                switch(c)
                {
                case '+':
                    *dest++=' ';
                    break;
                    
                case '%':
                    {
                        int h=unhex(*src++);
                        int l=unhex(*src++);
                        
                        *dest++=(char)((h<<4)|(l<<0));
                    }
                    break;
                    
                default:
                    *dest++=c;
                    break;
                }
            }
            
            ++src;//skip '&'
            *dest++=0;//terminate value
            
            ++control;//next control
        }
        
        assert(control==re->form.controls+re->form.num_controls);
    }
    
    good=1;
    
done:
    if(!good)
    {
        FREE(re->form.controls_data_buffer);
		re->form.controls_data_buffer=NULL;
        
        FREE(re->form.controls);
        re->form.controls=NULL;
		
        re->form.num_controls=0;
    }
    
    return good;
}

YHS_EXTERN const char *yhs_find_control_value(yhsRequest *re,const char *control_name)
{
    size_t i;
    
    for(i=0;i<re->form.num_controls;++i)
    {
        const KeyValuePair *kvp=&re->form.controls[i];
        
        if(strcmp(kvp->key,control_name)==0)
            return kvp->value;
    }
    
    return NULL;
}

YHS_EXTERN size_t yhs_get_num_controls(yhsRequest *re)
{
    return re->form.num_controls;
}

YHS_EXTERN const char *yhs_get_control_name(yhsRequest *re,size_t index)
{
    assert(index<re->form.num_controls);
    
    return re->form.controls[index].key;
}

YHS_EXTERN const char *yhs_get_control_value(yhsRequest *re,size_t index)
{
    assert(index<re->form.num_controls);
    
    return re->form.controls[index].value;
}

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

static int path_before(const yhsHandler *a,const yhsHandler *b)
{
    if(a->res_path_len<b->res_path_len)
        return 1;
    else if(b->res_path_len<a->res_path_len)
        return 0;
    
    return strcmp(a->res_path,b->res_path)<0;//though actually they don't need to be in alphabetical order.
}

yhsHandler *yhs_add_res_path_handler(yhsServer *server,const char *res_path,yhsResPathHandlerFn handler_fn,void *context)
{
    yhsHandler *h=(yhsHandler *)MALLOC(sizeof *h);
	char *h_res_path=yhs_strdup(res_path);
    yhsHandler *prev;
    
	if(!h||!h_res_path)
	{
		FREE(h);
		FREE(h_res_path);

		return 0;
	}
    
    memset(h,0,sizeof *h);

    h->res_path=h_res_path;
	h->res_path_len=strlen(h->res_path);
    
    h->handler_fn=handler_fn;
    h->context=context;

	// TODO: right decision? (probably...)
	h->valid_methods=YHS_METHOD_GET|YHS_METHOD_HEAD;
    
    for(prev=server->handlers.next;prev->handler_fn;prev=prev->next)
    {
        if(path_before(prev,h))
            break;
    }
    
    h->prev=prev;
    h->next=prev->next;
    
    h->next->prev=h;
    h->prev->next=h;

	return h;
}

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

yhsHandler *yhs_add_to_toc(yhsHandler *handler)
{
	handler->flags|=HF_TOC;

	return handler;
}

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

yhsHandler *yhs_set_handler_description(const char *description,yhsHandler *handler)
{
	char *new_description=yhs_strdup(description);
	
	if(new_description)
	{
		FREE(handler->description);

		handler->description=new_description;
	}

	return handler;
}

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

yhsHandler *yhs_set_valid_methods(unsigned valid_methods,yhsHandler *handler)
{
	handler->valid_methods=valid_methods;

	if(handler->valid_methods&YHS_METHOD_GET)
		handler->valid_methods|=YHS_METHOD_HEAD;

	return handler;
}

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

static int is_path_separator(char c)
{
	return c=='/'||c=='\\';
}

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

static const char *find_path_extension(const char *path)
{
	const char *e;

	for(e=path+strlen(path);e>=path&&!is_path_separator(*e);--e)
	{
		if(*e=='.')
			return e+1;
	}
	
	return 0;
}

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

static int is_folder_path(const char *path)
{
	size_t n=strlen(path);
	
	if(n>0)
	{
		if(is_path_separator(path[n-1]))
			return 1;
	}
	
	return 0;
}

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

static int join_paths(char *dest,const char *a,const char *b)
{
	if(!a&&!b)
		strcpy(dest,"");
	else if((a&&!b)||(b&&!a))
	{
		const char *src=a?a:b;
		
		if(strlen(src)>=MAX_PATH_SIZE)
			return 0;
		
		strcpy(dest,src);
	}
	else
	{
		if(is_path_separator(b[0]))
		{
			if(strlen(b)>=MAX_PATH_SIZE)
				return 0;
			
			strcpy(dest,b);
		}
		else
		{
			int sep_len=0;
			if(!is_folder_path(a))
				sep_len=1;
			
			if(strlen(a)+sep_len+strlen(b)>=MAX_PATH_SIZE)
				return 0;
			
			strcpy(dest,a);
			
			if(sep_len>0)
				strcat(dest,"/");
			
			strcat(dest,b);
		}
	}
	
	return 1;
}

// TODO: actually, opera does this bit for you! is this opera-specific, or is
// this foolish me for not checking first?
//
// - replace '\\' with '/'
//
// - remove ".." and "." appropriately
static int normalize_path(char *dest,const char *src)
{
	size_t num_to_skip=0;
	
	size_t src_idx;
	size_t dest_idx=0;
	
	int e=strlen(src);
	
	while(e>=0)
	{
		int b=e;
		while(b>0&&!is_path_separator(src[b-1]))
			--b;
		
		if(e-b==2&&src[b]=='.'&&src[b+1]=='.')
		{
			++num_to_skip;
		}
		else if(e-b==1&&src[b]=='.')
		{
			// skip...
		}
		else
		{
			if(num_to_skip>0)
				--num_to_skip;
			else
			{
				int i;

				if(is_path_separator(src[e]))
					dest[dest_idx++]='/';
				
				for(i=0;i<e-b;++i)
					dest[dest_idx++]=src[e-1-i];
			}
		}
		
		e=b-1;
	}
	
	if(num_to_skip>0)
	{
		// excess ".."s.
		return 0;
	}
	
	dest[dest_idx]=0;
	
	src_idx=0;
	
	while(src_idx<dest_idx)
	{
		char tmp;

		//std::swap(dest[src_idx++],dest[--dest_idx]);
		
		--dest_idx;
		
		tmp=dest[dest_idx];
		dest[dest_idx]=dest[src_idx];
		dest[src_idx]=tmp;
		
		++src_idx;
	}
	
	return 1;
}

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

#ifdef WIN32

#pragma comment(lib,"shlwapi.lib")

struct dirent
{
	char *d_name;
};

struct DIR
{
	struct dirent ent;
	HANDLE hFind;
	WIN32_FIND_DATAA cur_fd,next_fd;
};
typedef struct DIR DIR;

static DIR *opendir(const char *name)
{
	char wildcard[MAX_PATH_SIZE];
	DIR *d=(DIR *)MALLOC(sizeof *d);
	if(!d)
		return 0;

	memset(d,0,sizeof *d);
	
	join_paths(wildcard,name,"*");
	
	d->hFind=FindFirstFileA(wildcard,&d->next_fd);
	
	if(d->hFind==INVALID_HANDLE_VALUE)
	{
		FREE(d);
		d=0;
	}
	
	return d;
}

static struct dirent *readdir(DIR *d)
{
	if(d->hFind==INVALID_HANDLE_VALUE)
		return 0;
	
	d->cur_fd=d->next_fd;
	
	if(d->hFind!=INVALID_HANDLE_VALUE)
	{
		if(!FindNextFileA(d->hFind,&d->next_fd))
		{
			FindClose(d->hFind);
			d->hFind=INVALID_HANDLE_VALUE;
		}
	}
	
	d->ent.d_name=d->cur_fd.cFileName;
	return &d->ent;
}

static void closedir(DIR *d)
{
	if(d->hFind!=INVALID_HANDLE_VALUE)
	{
		FindClose(d->hFind);
		d->hFind=INVALID_HANDLE_VALUE;
	}
	
	FREE(d);
}

#endif

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

struct MIMEType
{
	const char *ext,*type;
};
typedef struct MIMEType MIMEType;

// see supplied make_mime_types_table.py.

static MIMEType g_mime_types[]={
	{"123","application/vnd.lotus-1-2-3"},{"3dml","text/vnd.in3d.3dml"},{"3ds","image/x-3ds"},{"3g2","video/3gpp2"},
	{"3gp","video/3gpp"},{"7z","application/x-7z-compressed"},{"aab","application/x-authorware-bin"},{"aac","audio/x-aac"},
	{"aam","application/x-authorware-map"},{"aas","application/x-authorware-seg"},{"abw","application/x-abiword"},
	{"ac","application/pkix-attr-cert"},{"acc","application/vnd.americandynamics.acc"},
	{"ace","application/x-ace-compressed"},{"acu","application/vnd.acucobol"},{"acutc","application/vnd.acucorp"},
	{"adp","audio/adpcm"},{"aep","application/vnd.audiograph"},{"afm","application/x-font-type1"},
	{"afp","application/vnd.ibm.modcap"},{"ahead","application/vnd.ahead.space"},{"ai","application/postscript"},
	{"aif","audio/x-aiff"},{"aifc","audio/x-aiff"},{"aiff","audio/x-aiff"},
	{"air","application/vnd.adobe.air-application-installer-package+zip"},{"ait","application/vnd.dvb.ait"},
	{"ami","application/vnd.amiga.ami"},{"apk","application/vnd.android.package-archive"},
	{"appcache","text/cache-manifest"},{"application","application/x-ms-application"},
	{"apr","application/vnd.lotus-approach"},{"arc","application/x-freearc"},{"asc","application/pgp-signature"},
	{"asf","video/x-ms-asf"},{"asm","text/x-asm"},{"aso","application/vnd.accpac.simply.aso"},{"asx","video/x-ms-asf"},
	{"atc","application/vnd.acucorp"},{"atom","application/atom+xml"},{"atomcat","application/atomcat+xml"},
	{"atomsvc","application/atomsvc+xml"},{"atx","application/vnd.antix.game-component"},{"au","audio/basic"},
	{"avi","video/x-msvideo"},{"aw","application/applixware"},{"azf","application/vnd.airzip.filesecure.azf"},
	{"azs","application/vnd.airzip.filesecure.azs"},{"azw","application/vnd.amazon.ebook"},
	{"bat","application/x-msdownload"},{"bcpio","application/x-bcpio"},{"bdf","application/x-font-bdf"},
	{"bdm","application/vnd.syncml.dm+wbxml"},{"bed","application/vnd.realvnc.bed"},
	{"bh2","application/vnd.fujitsu.oasysprs"},{"bin","application/octet-stream"},{"blb","application/x-blorb"},
	{"blorb","application/x-blorb"},{"bmi","application/vnd.bmi"},{"bmp","image/bmp"},{"book","application/vnd.framemaker"},
	{"box","application/vnd.previewsystems.box"},{"boz","application/x-bzip2"},{"bpk","application/octet-stream"},
	{"btif","image/prs.btif"},{"bz","application/x-bzip"},{"bz2","application/x-bzip2"},{"c","text/x-c"},
	{"c11amc","application/vnd.cluetrust.cartomobile-config"},{"c11amz","application/vnd.cluetrust.cartomobile-config-pkg"},
	{"c4d","application/vnd.clonk.c4group"},{"c4f","application/vnd.clonk.c4group"},{"c4g","application/vnd.clonk.c4group"},
	{"c4p","application/vnd.clonk.c4group"},{"c4u","application/vnd.clonk.c4group"},
	{"cab","application/vnd.ms-cab-compressed"},{"caf","audio/x-caf"},{"cap","application/vnd.tcpdump.pcap"},
	{"car","application/vnd.curl.car"},{"cat","application/vnd.ms-pki.seccat"},{"cb7","application/x-cbr"},
	{"cba","application/x-cbr"},{"cbr","application/x-cbr"},{"cbt","application/x-cbr"},{"cbz","application/x-cbr"},
	{"cc","text/x-c"},{"cct","application/x-director"},{"ccxml","application/ccxml+xml"},
	{"cdbcmsg","application/vnd.contact.cmsg"},{"cdf","application/x-netcdf"},
	{"cdkey","application/vnd.mediastation.cdkey"},{"cdmia","application/cdmi-capability"},
	{"cdmic","application/cdmi-container"},{"cdmid","application/cdmi-domain"},{"cdmio","application/cdmi-object"},
	{"cdmiq","application/cdmi-queue"},{"cdx","chemical/x-cdx"},{"cdxml","application/vnd.chemdraw+xml"},
	{"cdy","application/vnd.cinderella"},{"cer","application/pkix-cert"},{"cfs","application/x-cfs-compressed"},
	{"cgm","image/cgm"},{"chat","application/x-chat"},{"chm","application/vnd.ms-htmlhelp"},
	{"chrt","application/vnd.kde.kchart"},{"cif","chemical/x-cif"},
	{"cii","application/vnd.anser-web-certificate-issue-initiation"},{"cil","application/vnd.ms-artgalry"},
	{"cla","application/vnd.claymore"},{"class","application/java-vm"},{"clkk","application/vnd.crick.clicker.keyboard"},
	{"clkp","application/vnd.crick.clicker.palette"},{"clkt","application/vnd.crick.clicker.template"},
	{"clkw","application/vnd.crick.clicker.wordbank"},{"clkx","application/vnd.crick.clicker"},
	{"clp","application/x-msclip"},{"cmc","application/vnd.cosmocaller"},{"cmdf","chemical/x-cmdf"},
	{"cml","chemical/x-cml"},{"cmp","application/vnd.yellowriver-custom-menu"},{"cmx","image/x-cmx"},
	{"cod","application/vnd.rim.cod"},{"com","application/x-msdownload"},{"conf","text/plain"},
	{"cpio","application/x-cpio"},{"cpp","text/x-c"},{"cpt","application/mac-compactpro"},
	{"crd","application/x-mscardfile"},{"crl","application/pkix-crl"},{"crt","application/x-x509-ca-cert"},
	{"cryptonote","application/vnd.rig.cryptonote"},{"csh","application/x-csh"},{"csml","chemical/x-csml"},
	{"csp","application/vnd.commonspace"},{"css","text/css"},{"cst","application/x-director"},{"csv","text/csv"},
	{"cu","application/cu-seeme"},{"curl","text/vnd.curl"},{"cww","application/prs.cww"},{"cxt","application/x-director"},
	{"cxx","text/x-c"},{"dae","model/vnd.collada+xml"},{"daf","application/vnd.mobius.daf"},{"dart","application/vnd.dart"},
	{"dataless","application/vnd.fdsn.seed"},{"davmount","application/davmount+xml"},{"dbk","application/docbook+xml"},
	{"dcr","application/x-director"},{"dcurl","text/vnd.curl.dcurl"},{"dd2","application/vnd.oma.dd2+xml"},
	{"ddd","application/vnd.fujixerox.ddd"},{"deb","application/x-debian-package"},{"def","text/plain"},
	{"deploy","application/octet-stream"},{"der","application/x-x509-ca-cert"},{"dfac","application/vnd.dreamfactory"},
	{"dgc","application/x-dgc-compressed"},{"dic","text/x-c"},{"dir","application/x-director"},
	{"dis","application/vnd.mobius.dis"},{"dist","application/octet-stream"},{"distz","application/octet-stream"},
	{"djv","image/vnd.djvu"},{"djvu","image/vnd.djvu"},{"dll","application/x-msdownload"},
	{"dmg","application/x-apple-diskimage"},{"dmp","application/vnd.tcpdump.pcap"},{"dms","application/octet-stream"},
	{"dna","application/vnd.dna"},{"doc","application/msword"},{"docm","application/vnd.ms-word.document.macroenabled.12"},
	{"docx","application/vnd.openxmlformats-officedocument.wordprocessingml.document"},{"dot","application/msword"},
	{"dotm","application/vnd.ms-word.template.macroenabled.12"},
	{"dotx","application/vnd.openxmlformats-officedocument.wordprocessingml.template"},{"dp","application/vnd.osgi.dp"},
	{"dpg","application/vnd.dpgraph"},{"dra","audio/vnd.dra"},{"dsc","text/prs.lines.tag"},{"dssc","application/dssc+der"},
	{"dtb","application/x-dtbook+xml"},{"dtd","application/xml-dtd"},{"dts","audio/vnd.dts"},{"dtshd","audio/vnd.dts.hd"},
	{"dump","application/octet-stream"},{"dvb","video/vnd.dvb.file"},{"dvi","application/x-dvi"},{"dwf","model/vnd.dwf"},
	{"dwg","image/vnd.dwg"},{"dxf","image/vnd.dxf"},{"dxp","application/vnd.spotfire.dxp"},{"dxr","application/x-director"},
	{"ecelp4800","audio/vnd.nuera.ecelp4800"},{"ecelp7470","audio/vnd.nuera.ecelp7470"},
	{"ecelp9600","audio/vnd.nuera.ecelp9600"},{"ecma","application/ecmascript"},{"edm","application/vnd.novadigm.edm"},
	{"edx","application/vnd.novadigm.edx"},{"efif","application/vnd.picsel"},{"ei6","application/vnd.pg.osasli"},
	{"elc","application/octet-stream"},{"emf","application/x-msmetafile"},{"eml","message/rfc822"},
	{"emma","application/emma+xml"},{"emz","application/x-msmetafile"},{"eol","audio/vnd.digital-winds"},
	{"eot","application/vnd.ms-fontobject"},{"eps","application/postscript"},{"epub","application/epub+zip"},
	{"es3","application/vnd.eszigno3+xml"},{"esa","application/vnd.osgi.subsystem"},{"esf","application/vnd.epson.esf"},
	{"et3","application/vnd.eszigno3+xml"},{"etx","text/x-setext"},{"eva","application/x-eva"},
	{"evy","application/x-envoy"},{"exe","application/x-msdownload"},{"exi","application/exi"},
	{"ext","application/vnd.novadigm.ext"},{"ez","application/andrew-inset"},{"ez2","application/vnd.ezpix-album"},
	{"ez3","application/vnd.ezpix-package"},{"f","text/x-fortran"},{"f4v","video/x-f4v"},{"f77","text/x-fortran"},
	{"f90","text/x-fortran"},{"fbs","image/vnd.fastbidsheet"},{"fcdt","application/vnd.adobe.formscentral.fcdt"},
	{"fcs","application/vnd.isac.fcs"},{"fdf","application/vnd.fdf"},{"fe_launch","application/vnd.denovo.fcselayout-link"},
	{"fg5","application/vnd.fujitsu.oasysgp"},{"fgd","application/x-director"},{"fh","image/x-freehand"},
	{"fh4","image/x-freehand"},{"fh5","image/x-freehand"},{"fh7","image/x-freehand"},{"fhc","image/x-freehand"},
	{"fig","application/x-xfig"},{"flac","audio/x-flac"},{"fli","video/x-fli"},{"flo","application/vnd.micrografx.flo"},
	{"flv","video/x-flv"},{"flw","application/vnd.kde.kivio"},{"flx","text/vnd.fmi.flexstor"},{"fly","text/vnd.fly"},
	{"fm","application/vnd.framemaker"},{"fnc","application/vnd.frogans.fnc"},{"for","text/x-fortran"},
	{"fpx","image/vnd.fpx"},{"frame","application/vnd.framemaker"},{"fsc","application/vnd.fsc.weblaunch"},
	{"fst","image/vnd.fst"},{"ftc","application/vnd.fluxtime.clip"},
	{"fti","application/vnd.anser-web-funds-transfer-initiation"},{"fvt","video/vnd.fvt"},
	{"fxp","application/vnd.adobe.fxp"},{"fxpl","application/vnd.adobe.fxp"},{"fzs","application/vnd.fuzzysheet"},
	{"g2w","application/vnd.geoplan"},{"g3","image/g3fax"},{"g3w","application/vnd.geospace"},
	{"gac","application/vnd.groove-account"},{"gam","application/x-tads"},{"gbr","application/rpki-ghostbusters"},
	{"gca","application/x-gca-compressed"},{"gdl","model/vnd.gdl"},{"geo","application/vnd.dynageo"},
	{"gex","application/vnd.geometry-explorer"},{"ggb","application/vnd.geogebra.file"},
	{"ggt","application/vnd.geogebra.tool"},{"ghf","application/vnd.groove-help"},{"gif","image/gif"},
	{"gim","application/vnd.groove-identity-message"},{"gml","application/gml+xml"},{"gmx","application/vnd.gmx"},
	{"gnumeric","application/x-gnumeric"},{"gph","application/vnd.flographit"},{"gpx","application/gpx+xml"},
	{"gqf","application/vnd.grafeq"},{"gqs","application/vnd.grafeq"},{"gram","application/srgs"},
	{"gramps","application/x-gramps-xml"},{"gre","application/vnd.geometry-explorer"},
	{"grv","application/vnd.groove-injector"},{"grxml","application/srgs+xml"},{"gsf","application/x-font-ghostscript"},
	{"gtar","application/x-gtar"},{"gtm","application/vnd.groove-tool-message"},{"gtw","model/vnd.gtw"},
	{"gv","text/vnd.graphviz"},{"gxf","application/gxf"},{"gxt","application/vnd.geonext"},{"h","text/x-c"},
	{"h261","video/h261"},{"h263","video/h263"},{"h264","video/h264"},{"hal","application/vnd.hal+xml"},
	{"hbci","application/vnd.hbci"},{"hdf","application/x-hdf"},{"hh","text/x-c"},{"hlp","application/winhlp"},
	{"hpgl","application/vnd.hp-hpgl"},{"hpid","application/vnd.hp-hpid"},{"hps","application/vnd.hp-hps"},
	{"hqx","application/mac-binhex40"},{"htke","application/vnd.kenameaapp"},{"htm","text/html"},{"html","text/html"},
	{"hvd","application/vnd.yamaha.hv-dic"},{"hvp","application/vnd.yamaha.hv-voice"},
	{"hvs","application/vnd.yamaha.hv-script"},{"i2g","application/vnd.intergeo"},{"icc","application/vnd.iccprofile"},
	{"ice","x-conference/x-cooltalk"},{"icm","application/vnd.iccprofile"},{"ico","image/x-icon"},{"ics","text/calendar"},
	{"ief","image/ief"},{"ifb","text/calendar"},{"ifm","application/vnd.shana.informed.formdata"},{"iges","model/iges"},
	{"igl","application/vnd.igloader"},{"igm","application/vnd.insors.igm"},{"igs","model/iges"},
	{"igx","application/vnd.micrografx.igx"},{"iif","application/vnd.shana.informed.interchange"},
	{"imp","application/vnd.accpac.simply.imp"},{"ims","application/vnd.ms-ims"},{"in","text/plain"},
	{"ink","application/inkml+xml"},{"inkml","application/inkml+xml"},{"install","application/x-install-instructions"},
	{"iota","application/vnd.astraea-software.iota"},{"ipfix","application/ipfix"},
	{"ipk","application/vnd.shana.informed.package"},{"irm","application/vnd.ibm.rights-management"},
	{"irp","application/vnd.irepository.package+xml"},{"iso","application/x-iso9660-image"},
	{"itp","application/vnd.shana.informed.formtemplate"},{"ivp","application/vnd.immervision-ivp"},
	{"ivu","application/vnd.immervision-ivu"},{"jad","text/vnd.sun.j2me.app-descriptor"},{"jam","application/vnd.jam"},
	{"jar","application/java-archive"},{"java","text/x-java-source"},{"jisp","application/vnd.jisp"},
	{"jlt","application/vnd.hp-jlyt"},{"jnlp","application/x-java-jnlp-file"},{"joda","application/vnd.joost.joda-archive"},
	{"jpe","image/jpeg"},{"jpeg","image/jpeg"},{"jpg","image/jpeg"},{"jpgm","video/jpm"},{"jpgv","video/jpeg"},
	{"jpm","video/jpm"},{"js","application/javascript"},{"json","application/json"},{"jsonml","application/jsonml+json"},
	{"kar","audio/midi"},{"karbon","application/vnd.kde.karbon"},{"kfo","application/vnd.kde.kformula"},
	{"kia","application/vnd.kidspiration"},{"kml","application/vnd.google-earth.kml+xml"},
	{"kmz","application/vnd.google-earth.kmz"},{"kne","application/vnd.kinar"},{"knp","application/vnd.kinar"},
	{"kon","application/vnd.kde.kontour"},{"kpr","application/vnd.kde.kpresenter"},{"kpt","application/vnd.kde.kpresenter"},
	{"kpxx","application/vnd.ds-keypoint"},{"ksp","application/vnd.kde.kspread"},{"ktr","application/vnd.kahootz"},
	{"ktx","image/ktx"},{"ktz","application/vnd.kahootz"},{"kwd","application/vnd.kde.kword"},
	{"kwt","application/vnd.kde.kword"},{"lasxml","application/vnd.las.las+xml"},{"latex","application/x-latex"},
	{"lbd","application/vnd.llamagraphics.life-balance.desktop"},
	{"lbe","application/vnd.llamagraphics.life-balance.exchange+xml"},{"les","application/vnd.hhe.lesson-player"},
	{"lha","application/x-lzh-compressed"},{"link66","application/vnd.route66.link66+xml"},{"list","text/plain"},
	{"list3820","application/vnd.ibm.modcap"},{"listafp","application/vnd.ibm.modcap"},{"lnk","application/x-ms-shortcut"},
	{"log","text/plain"},{"lostxml","application/lost+xml"},{"lrf","application/octet-stream"},
	{"lrm","application/vnd.ms-lrm"},{"ltf","application/vnd.frogans.ltf"},{"lvp","audio/vnd.lucent.voice"},
	{"lwp","application/vnd.lotus-wordpro"},{"lzh","application/x-lzh-compressed"},{"m13","application/x-msmediaview"},
	{"m14","application/x-msmediaview"},{"m1v","video/mpeg"},{"m21","application/mp21"},{"m2a","audio/mpeg"},
	{"m2v","video/mpeg"},{"m3a","audio/mpeg"},{"m3u","audio/x-mpegurl"},{"m3u8","application/vnd.apple.mpegurl"},
	{"m4u","video/vnd.mpegurl"},{"m4v","video/x-m4v"},{"ma","application/mathematica"},{"mads","application/mads+xml"},
	{"mag","application/vnd.ecowin.chart"},{"maker","application/vnd.framemaker"},{"man","text/troff"},
	{"mar","application/octet-stream"},{"mathml","application/mathml+xml"},{"mb","application/mathematica"},
	{"mbk","application/vnd.mobius.mbk"},{"mbox","application/mbox"},{"mc1","application/vnd.medcalcdata"},
	{"mcd","application/vnd.mcd"},{"mcurl","text/vnd.curl.mcurl"},{"mdb","application/x-msaccess"},
	{"mdi","image/vnd.ms-modi"},{"me","text/troff"},{"mesh","model/mesh"},{"meta4","application/metalink4+xml"},
	{"metalink","application/metalink+xml"},{"mets","application/mets+xml"},{"mfm","application/vnd.mfmp"},
	{"mft","application/rpki-manifest"},{"mgp","application/vnd.osgeo.mapguide.package"},
	{"mgz","application/vnd.proteus.magazine"},{"mid","audio/midi"},{"midi","audio/midi"},{"mie","application/x-mie"},
	{"mif","application/vnd.mif"},{"mime","message/rfc822"},{"mj2","video/mj2"},{"mjp2","video/mj2"},
	{"mk3d","video/x-matroska"},{"mka","audio/x-matroska"},{"mks","video/x-matroska"},{"mkv","video/x-matroska"},
	{"mlp","application/vnd.dolby.mlp"},{"mmd","application/vnd.chipnuts.karaoke-mmd"},{"mmf","application/vnd.smaf"},
	{"mmr","image/vnd.fujixerox.edmics-mmr"},{"mng","video/x-mng"},{"mny","application/x-msmoney"},
	{"mobi","application/x-mobipocket-ebook"},{"mods","application/mods+xml"},{"mov","video/quicktime"},
	{"movie","video/x-sgi-movie"},{"mp2","audio/mpeg"},{"mp21","application/mp21"},{"mp2a","audio/mpeg"},
	{"mp3","audio/mpeg"},{"mp4","video/mp4"},{"mp4a","audio/mp4"},{"mp4s","application/mp4"},{"mp4v","video/mp4"},
	{"mpc","application/vnd.mophun.certificate"},{"mpe","video/mpeg"},{"mpeg","video/mpeg"},{"mpg","video/mpeg"},
	{"mpg4","video/mp4"},{"mpga","audio/mpeg"},{"mpkg","application/vnd.apple.installer+xml"},
	{"mpm","application/vnd.blueice.multipass"},{"mpn","application/vnd.mophun.application"},
	{"mpp","application/vnd.ms-project"},{"mpt","application/vnd.ms-project"},{"mpy","application/vnd.ibm.minipay"},
	{"mqy","application/vnd.mobius.mqy"},{"mrc","application/marc"},{"mrcx","application/marcxml+xml"},{"ms","text/troff"},
	{"mscml","application/mediaservercontrol+xml"},{"mseed","application/vnd.fdsn.mseed"},{"mseq","application/vnd.mseq"},
	{"msf","application/vnd.epson.msf"},{"msh","model/mesh"},{"msi","application/x-msdownload"},
	{"msl","application/vnd.mobius.msl"},{"msty","application/vnd.muvee.style"},{"mts","model/vnd.mts"},
	{"mus","application/vnd.musician"},{"musicxml","application/vnd.recordare.musicxml+xml"},
	{"mvb","application/x-msmediaview"},{"mwf","application/vnd.mfer"},{"mxf","application/mxf"},
	{"mxl","application/vnd.recordare.musicxml"},{"mxml","application/xv+xml"},{"mxs","application/vnd.triscape.mxs"},
	{"mxu","video/vnd.mpegurl"},{"n-gage","application/vnd.nokia.n-gage.symbian.install"},{"n3","text/n3"},
	{"nb","application/mathematica"},{"nbp","application/vnd.wolfram.player"},{"nc","application/x-netcdf"},
	{"ncx","application/x-dtbncx+xml"},{"nfo","text/x-nfo"},{"ngdat","application/vnd.nokia.n-gage.data"},
	{"nitf","application/vnd.nitf"},{"nlu","application/vnd.neurolanguage.nlu"},{"nml","application/vnd.enliven"},
	{"nnd","application/vnd.noblenet-directory"},{"nns","application/vnd.noblenet-sealer"},
	{"nnw","application/vnd.noblenet-web"},{"npx","image/vnd.net-fpx"},{"nsc","application/x-conference"},
	{"nsf","application/vnd.lotus-notes"},{"ntf","application/vnd.nitf"},{"nzb","application/x-nzb"},
	{"oa2","application/vnd.fujitsu.oasys2"},{"oa3","application/vnd.fujitsu.oasys3"},
	{"oas","application/vnd.fujitsu.oasys"},{"obd","application/x-msbinder"},{"obj","application/x-tgif"},
	{"oda","application/oda"},{"odb","application/vnd.oasis.opendocument.database"},
	{"odc","application/vnd.oasis.opendocument.chart"},{"odf","application/vnd.oasis.opendocument.formula"},
	{"odft","application/vnd.oasis.opendocument.formula-template"},{"odg","application/vnd.oasis.opendocument.graphics"},
	{"odi","application/vnd.oasis.opendocument.image"},{"odm","application/vnd.oasis.opendocument.text-master"},
	{"odp","application/vnd.oasis.opendocument.presentation"},{"ods","application/vnd.oasis.opendocument.spreadsheet"},
	{"odt","application/vnd.oasis.opendocument.text"},{"oga","audio/ogg"},{"ogg","audio/ogg"},{"ogv","video/ogg"},
	{"ogx","application/ogg"},{"omdoc","application/omdoc+xml"},{"onepkg","application/onenote"},
	{"onetmp","application/onenote"},{"onetoc","application/onenote"},{"onetoc2","application/onenote"},
	{"opf","application/oebps-package+xml"},{"opml","text/x-opml"},{"oprc","application/vnd.palm"},
	{"org","application/vnd.lotus-organizer"},{"osf","application/vnd.yamaha.openscoreformat"},
	{"osfpvg","application/vnd.yamaha.openscoreformat.osfpvg+xml"},
	{"otc","application/vnd.oasis.opendocument.chart-template"},{"otf","application/x-font-otf"},
	{"otg","application/vnd.oasis.opendocument.graphics-template"},{"oth","application/vnd.oasis.opendocument.text-web"},
	{"oti","application/vnd.oasis.opendocument.image-template"},
	{"otp","application/vnd.oasis.opendocument.presentation-template"},
	{"ots","application/vnd.oasis.opendocument.spreadsheet-template"},
	{"ott","application/vnd.oasis.opendocument.text-template"},{"oxps","application/oxps"},
	{"oxt","application/vnd.openofficeorg.extension"},{"p","text/x-pascal"},{"p10","application/pkcs10"},
	{"p12","application/x-pkcs12"},{"p7b","application/x-pkcs7-certificates"},{"p7c","application/pkcs7-mime"},
	{"p7m","application/pkcs7-mime"},{"p7r","application/x-pkcs7-certreqresp"},{"p7s","application/pkcs7-signature"},
	{"p8","application/pkcs8"},{"pas","text/x-pascal"},{"paw","application/vnd.pawaafile"},
	{"pbd","application/vnd.powerbuilder6"},{"pbm","image/x-portable-bitmap"},{"pcap","application/vnd.tcpdump.pcap"},
	{"pcf","application/x-font-pcf"},{"pcl","application/vnd.hp-pcl"},{"pclxl","application/vnd.hp-pclxl"},
	{"pct","image/x-pict"},{"pcurl","application/vnd.curl.pcurl"},{"pcx","image/x-pcx"},{"pdb","application/vnd.palm"},
	{"pdf","application/pdf"},{"pfa","application/x-font-type1"},{"pfb","application/x-font-type1"},
	{"pfm","application/x-font-type1"},{"pfr","application/font-tdpfr"},{"pfx","application/x-pkcs12"},
	{"pgm","image/x-portable-graymap"},{"pgn","application/x-chess-pgn"},{"pgp","application/pgp-encrypted"},
	{"pic","image/x-pict"},{"pkg","application/octet-stream"},{"pki","application/pkixcmp"},
	{"pkipath","application/pkix-pkipath"},{"plb","application/vnd.3gpp.pic-bw-large"},{"plc","application/vnd.mobius.plc"},
	{"plf","application/vnd.pocketlearn"},{"pls","application/pls+xml"},{"pml","application/vnd.ctc-posml"},
	{"png","image/png"},{"pnm","image/x-portable-anymap"},{"portpkg","application/vnd.macports.portpkg"},
	{"pot","application/vnd.ms-powerpoint"},{"potm","application/vnd.ms-powerpoint.template.macroenabled.12"},
	{"potx","application/vnd.openxmlformats-officedocument.presentationml.template"},
	{"ppam","application/vnd.ms-powerpoint.addin.macroenabled.12"},{"ppd","application/vnd.cups-ppd"},
	{"ppm","image/x-portable-pixmap"},{"pps","application/vnd.ms-powerpoint"},
	{"ppsm","application/vnd.ms-powerpoint.slideshow.macroenabled.12"},
	{"ppsx","application/vnd.openxmlformats-officedocument.presentationml.slideshow"},
	{"ppt","application/vnd.ms-powerpoint"},{"pptm","application/vnd.ms-powerpoint.presentation.macroenabled.12"},
	{"pptx","application/vnd.openxmlformats-officedocument.presentationml.presentation"},{"pqa","application/vnd.palm"},
	{"prc","application/x-mobipocket-ebook"},{"pre","application/vnd.lotus-freelance"},{"prf","application/pics-rules"},
	{"ps","application/postscript"},{"psb","application/vnd.3gpp.pic-bw-small"},{"psd","image/vnd.adobe.photoshop"},
	{"psf","application/x-font-linux-psf"},{"pskcxml","application/pskc+xml"},{"ptid","application/vnd.pvi.ptid1"},
	{"pub","application/x-mspublisher"},{"pvb","application/vnd.3gpp.pic-bw-var"},
	{"pwn","application/vnd.3m.post-it-notes"},{"pya","audio/vnd.ms-playready.media.pya"},
	{"pyv","video/vnd.ms-playready.media.pyv"},{"qam","application/vnd.epson.quickanime"},
	{"qbo","application/vnd.intu.qbo"},{"qfx","application/vnd.intu.qfx"},{"qps","application/vnd.publishare-delta-tree"},
	{"qt","video/quicktime"},{"qwd","application/vnd.quark.quarkxpress"},{"qwt","application/vnd.quark.quarkxpress"},
	{"qxb","application/vnd.quark.quarkxpress"},{"qxd","application/vnd.quark.quarkxpress"},
	{"qxl","application/vnd.quark.quarkxpress"},{"qxt","application/vnd.quark.quarkxpress"},{"ra","audio/x-pn-realaudio"},
	{"ram","audio/x-pn-realaudio"},{"rar","application/x-rar-compressed"},{"ras","image/x-cmu-raster"},
	{"rcprofile","application/vnd.ipunplugged.rcprofile"},{"rdf","application/rdf+xml"},
	{"rdz","application/vnd.data-vision.rdz"},{"rep","application/vnd.businessobjects"},
	{"res","application/x-dtbresource+xml"},{"rgb","image/x-rgb"},{"rif","application/reginfo+xml"},{"rip","audio/vnd.rip"},
	{"ris","application/x-research-info-systems"},{"rl","application/resource-lists+xml"},
	{"rlc","image/vnd.fujixerox.edmics-rlc"},{"rld","application/resource-lists-diff+xml"},
	{"rm","application/vnd.rn-realmedia"},{"rmi","audio/midi"},{"rmp","audio/x-pn-realaudio-plugin"},
	{"rms","application/vnd.jcp.javame.midlet-rms"},{"rmvb","application/vnd.rn-realmedia-vbr"},
	{"rnc","application/relax-ng-compact-syntax"},{"roa","application/rpki-roa"},{"roff","text/troff"},
	{"rp9","application/vnd.cloanto.rp9"},{"rpss","application/vnd.nokia.radio-presets"},
	{"rpst","application/vnd.nokia.radio-preset"},{"rq","application/sparql-query"},{"rs","application/rls-services+xml"},
	{"rsd","application/rsd+xml"},{"rss","application/rss+xml"},{"rtf","application/rtf"},{"rtx","text/richtext"},
	{"s","text/x-asm"},{"s3m","audio/s3m"},{"saf","application/vnd.yamaha.smaf-audio"},{"sbml","application/sbml+xml"},
	{"sc","application/vnd.ibm.secure-container"},{"scd","application/x-msschedule"},
	{"scm","application/vnd.lotus-screencam"},{"scq","application/scvp-cv-request"},{"scs","application/scvp-cv-response"},
	{"scurl","text/vnd.curl.scurl"},{"sda","application/vnd.stardivision.draw"},{"sdc","application/vnd.stardivision.calc"},
	{"sdd","application/vnd.stardivision.impress"},{"sdkd","application/vnd.solent.sdkm+xml"},
	{"sdkm","application/vnd.solent.sdkm+xml"},{"sdp","application/sdp"},{"sdw","application/vnd.stardivision.writer"},
	{"see","application/vnd.seemail"},{"seed","application/vnd.fdsn.seed"},{"sema","application/vnd.sema"},
	{"semd","application/vnd.semd"},{"semf","application/vnd.semf"},{"ser","application/java-serialized-object"},
	{"setpay","application/set-payment-initiation"},{"setreg","application/set-registration-initiation"},
	{"sfd-hdstx","application/vnd.hydrostatix.sof-data"},{"sfs","application/vnd.spotfire.sfs"},{"sfv","text/x-sfv"},
	{"sgi","image/sgi"},{"sgl","application/vnd.stardivision.writer-global"},{"sgm","text/sgml"},{"sgml","text/sgml"},
	{"sh","application/x-sh"},{"shar","application/x-shar"},{"shf","application/shf+xml"},{"sid","image/x-mrsid-image"},
	{"sig","application/pgp-signature"},{"sil","audio/silk"},{"silo","model/mesh"},
	{"sis","application/vnd.symbian.install"},{"sisx","application/vnd.symbian.install"},{"sit","application/x-stuffit"},
	{"sitx","application/x-stuffitx"},{"skd","application/vnd.koan"},{"skm","application/vnd.koan"},
	{"skp","application/vnd.koan"},{"skt","application/vnd.koan"},
	{"sldm","application/vnd.ms-powerpoint.slide.macroenabled.12"},
	{"sldx","application/vnd.openxmlformats-officedocument.presentationml.slide"},{"slt","application/vnd.epson.salt"},
	{"sm","application/vnd.stepmania.stepchart"},{"smf","application/vnd.stardivision.math"},{"smi","application/smil+xml"},
	{"smil","application/smil+xml"},{"smv","video/x-smv"},{"smzip","application/vnd.stepmania.package"},
	{"snd","audio/basic"},{"snf","application/x-font-snf"},{"so","application/octet-stream"},
	{"spc","application/x-pkcs7-certificates"},{"spf","application/vnd.yamaha.smaf-phrase"},
	{"spl","application/x-futuresplash"},{"spot","text/vnd.in3d.spot"},{"spp","application/scvp-vp-response"},
	{"spq","application/scvp-vp-request"},{"spx","audio/ogg"},{"sql","application/x-sql"},
	{"src","application/x-wais-source"},{"srt","application/x-subrip"},{"sru","application/sru+xml"},
	{"srx","application/sparql-results+xml"},{"ssdl","application/ssdl+xml"},{"sse","application/vnd.kodak-descriptor"},
	{"ssf","application/vnd.epson.ssf"},{"ssml","application/ssml+xml"},{"st","application/vnd.sailingtracker.track"},
	{"stc","application/vnd.sun.xml.calc.template"},{"std","application/vnd.sun.xml.draw.template"},
	{"stf","application/vnd.wt.stf"},{"sti","application/vnd.sun.xml.impress.template"},{"stk","application/hyperstudio"},
	{"stl","application/vnd.ms-pki.stl"},{"str","application/vnd.pg.format"},
	{"stw","application/vnd.sun.xml.writer.template"},{"sub","image/vnd.dvb.subtitle"},{"sub","text/vnd.dvb.subtitle"},
	{"sus","application/vnd.sus-calendar"},{"susp","application/vnd.sus-calendar"},{"sv4cpio","application/x-sv4cpio"},
	{"sv4crc","application/x-sv4crc"},{"svc","application/vnd.dvb.service"},{"svd","application/vnd.svd"},
	{"svg","image/svg+xml"},{"svgz","image/svg+xml"},{"swa","application/x-director"},
	{"swf","application/x-shockwave-flash"},{"swi","application/vnd.aristanetworks.swi"},
	{"sxc","application/vnd.sun.xml.calc"},{"sxd","application/vnd.sun.xml.draw"},
	{"sxg","application/vnd.sun.xml.writer.global"},{"sxi","application/vnd.sun.xml.impress"},
	{"sxm","application/vnd.sun.xml.math"},{"sxw","application/vnd.sun.xml.writer"},{"t","text/troff"},
	{"t3","application/x-t3vm-image"},{"taglet","application/vnd.mynfc"},
	{"tao","application/vnd.tao.intent-module-archive"},{"tar","application/x-tar"},{"tcap","application/vnd.3gpp2.tcap"},
	{"tcl","application/x-tcl"},{"teacher","application/vnd.smart.teacher"},{"tei","application/tei+xml"},
	{"teicorpus","application/tei+xml"},{"tex","application/x-tex"},{"texi","application/x-texinfo"},
	{"texinfo","application/x-texinfo"},{"text","text/plain"},{"tfi","application/thraud+xml"},
	{"tfm","application/x-tex-tfm"},{"tga","image/x-tga"},{"thmx","application/vnd.ms-officetheme"},{"tif","image/tiff"},
	{"tiff","image/tiff"},{"tmo","application/vnd.tmobile-livetv"},{"torrent","application/x-bittorrent"},
	{"tpl","application/vnd.groove-tool-template"},{"tpt","application/vnd.trid.tpt"},{"tr","text/troff"},
	{"tra","application/vnd.trueapp"},{"trm","application/x-msterminal"},{"tsd","application/timestamped-data"},
	{"tsv","text/tab-separated-values"},{"ttc","application/x-font-ttf"},{"ttf","application/x-font-ttf"},
	{"ttl","text/turtle"},{"twd","application/vnd.simtech-mindmapper"},{"twds","application/vnd.simtech-mindmapper"},
	{"txd","application/vnd.genomatix.tuxedo"},{"txf","application/vnd.mobius.txf"},{"txt","text/plain"},
	{"u32","application/x-authorware-bin"},{"udeb","application/x-debian-package"},{"ufd","application/vnd.ufdl"},
	{"ufdl","application/vnd.ufdl"},{"ulx","application/x-glulx"},{"umj","application/vnd.umajin"},
	{"unityweb","application/vnd.unity"},{"uoml","application/vnd.uoml+xml"},{"uri","text/uri-list"},
	{"uris","text/uri-list"},{"urls","text/uri-list"},{"ustar","application/x-ustar"},{"utz","application/vnd.uiq.theme"},
	{"uu","text/x-uuencode"},{"uva","audio/vnd.dece.audio"},{"uvd","application/vnd.dece.data"},
	{"uvf","application/vnd.dece.data"},{"uvg","image/vnd.dece.graphic"},{"uvh","video/vnd.dece.hd"},
	{"uvi","image/vnd.dece.graphic"},{"uvm","video/vnd.dece.mobile"},{"uvp","video/vnd.dece.pd"},
	{"uvs","video/vnd.dece.sd"},{"uvt","application/vnd.dece.ttml+xml"},{"uvu","video/vnd.uvvu.mp4"},
	{"uvv","video/vnd.dece.video"},{"uvva","audio/vnd.dece.audio"},{"uvvd","application/vnd.dece.data"},
	{"uvvf","application/vnd.dece.data"},{"uvvg","image/vnd.dece.graphic"},{"uvvh","video/vnd.dece.hd"},
	{"uvvi","image/vnd.dece.graphic"},{"uvvm","video/vnd.dece.mobile"},{"uvvp","video/vnd.dece.pd"},
	{"uvvs","video/vnd.dece.sd"},{"uvvt","application/vnd.dece.ttml+xml"},{"uvvu","video/vnd.uvvu.mp4"},
	{"uvvv","video/vnd.dece.video"},{"uvvx","application/vnd.dece.unspecified"},{"uvvz","application/vnd.dece.zip"},
	{"uvx","application/vnd.dece.unspecified"},{"uvz","application/vnd.dece.zip"},{"vcard","text/vcard"},
	{"vcd","application/x-cdlink"},{"vcf","text/x-vcard"},{"vcg","application/vnd.groove-vcard"},{"vcs","text/x-vcalendar"},
	{"vcx","application/vnd.vcx"},{"vis","application/vnd.visionary"},{"viv","video/vnd.vivo"},{"vob","video/x-ms-vob"},
	{"vor","application/vnd.stardivision.writer"},{"vox","application/x-authorware-bin"},{"vrml","model/vrml"},
	{"vsd","application/vnd.visio"},{"vsf","application/vnd.vsf"},{"vss","application/vnd.visio"},
	{"vst","application/vnd.visio"},{"vsw","application/vnd.visio"},{"vtu","model/vnd.vtu"},
	{"vxml","application/voicexml+xml"},{"w3d","application/x-director"},{"wad","application/x-doom"},{"wav","audio/x-wav"},
	{"wax","audio/x-ms-wax"},{"wbmp","image/vnd.wap.wbmp"},{"wbs","application/vnd.criticaltools.wbs+xml"},
	{"wbxml","application/vnd.wap.wbxml"},{"wcm","application/vnd.ms-works"},{"wdb","application/vnd.ms-works"},
	{"wdp","image/vnd.ms-photo"},{"weba","audio/webm"},{"webm","video/webm"},{"webp","image/webp"},
	{"wg","application/vnd.pmi.widget"},{"wgt","application/widget"},{"wks","application/vnd.ms-works"},
	{"wm","video/x-ms-wm"},{"wma","audio/x-ms-wma"},{"wmd","application/x-ms-wmd"},{"wmf","application/x-msmetafile"},
	{"wml","text/vnd.wap.wml"},{"wmlc","application/vnd.wap.wmlc"},{"wmls","text/vnd.wap.wmlscript"},
	{"wmlsc","application/vnd.wap.wmlscriptc"},{"wmv","video/x-ms-wmv"},{"wmx","video/x-ms-wmx"},
	{"wmz","application/x-ms-wmz"},{"wmz","application/x-msmetafile"},{"woff","application/x-font-woff"},
	{"wpd","application/vnd.wordperfect"},{"wpl","application/vnd.ms-wpl"},{"wps","application/vnd.ms-works"},
	{"wqd","application/vnd.wqd"},{"wri","application/x-mswrite"},{"wrl","model/vrml"},{"wsdl","application/wsdl+xml"},
	{"wspolicy","application/wspolicy+xml"},{"wtb","application/vnd.webturbo"},{"wvx","video/x-ms-wvx"},
	{"x32","application/x-authorware-bin"},{"x3d","model/x3d+xml"},{"x3db","model/x3d+binary"},{"x3dbz","model/x3d+binary"},
	{"x3dv","model/x3d+vrml"},{"x3dvz","model/x3d+vrml"},{"x3dz","model/x3d+xml"},{"xaml","application/xaml+xml"},
	{"xap","application/x-silverlight-app"},{"xar","application/vnd.xara"},{"xbap","application/x-ms-xbap"},
	{"xbd","application/vnd.fujixerox.docuworks.binder"},{"xbm","image/x-xbitmap"},{"xdf","application/xcap-diff+xml"},
	{"xdm","application/vnd.syncml.dm+xml"},{"xdp","application/vnd.adobe.xdp+xml"},{"xdssc","application/dssc+xml"},
	{"xdw","application/vnd.fujixerox.docuworks"},{"xenc","application/xenc+xml"},{"xer","application/patch-ops-error+xml"},
	{"xfdf","application/vnd.adobe.xfdf"},{"xfdl","application/vnd.xfdl"},{"xht","application/xhtml+xml"},
	{"xhtml","application/xhtml+xml"},{"xhvml","application/xv+xml"},{"xif","image/vnd.xiff"},
	{"xla","application/vnd.ms-excel"},{"xlam","application/vnd.ms-excel.addin.macroenabled.12"},
	{"xlc","application/vnd.ms-excel"},{"xlf","application/x-xliff+xml"},{"xlm","application/vnd.ms-excel"},
	{"xls","application/vnd.ms-excel"},{"xlsb","application/vnd.ms-excel.sheet.binary.macroenabled.12"},
	{"xlsm","application/vnd.ms-excel.sheet.macroenabled.12"},
	{"xlsx","application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"},{"xlt","application/vnd.ms-excel"},
	{"xltm","application/vnd.ms-excel.template.macroenabled.12"},
	{"xltx","application/vnd.openxmlformats-officedocument.spreadsheetml.template"},{"xlw","application/vnd.ms-excel"},
	{"xm","audio/xm"},{"xml","application/xml"},{"xo","application/vnd.olpc-sugar"},{"xop","application/xop+xml"},
	{"xpi","application/x-xpinstall"},{"xpl","application/xproc+xml"},{"xpm","image/x-xpixmap"},
	{"xpr","application/vnd.is-xpr"},{"xps","application/vnd.ms-xpsdocument"},{"xpw","application/vnd.intercon.formnet"},
	{"xpx","application/vnd.intercon.formnet"},{"xsl","application/xml"},{"xslt","application/xslt+xml"},
	{"xsm","application/vnd.syncml+xml"},{"xspf","application/xspf+xml"},{"xul","application/vnd.mozilla.xul+xml"},
	{"xvm","application/xv+xml"},{"xvml","application/xv+xml"},{"xwd","image/x-xwindowdump"},{"xyz","chemical/x-xyz"},
	{"xz","application/x-xz"},{"yang","application/yang"},{"yin","application/yin+xml"},{"z1","application/x-zmachine"},
	{"z2","application/x-zmachine"},{"z3","application/x-zmachine"},{"z4","application/x-zmachine"},
	{"z5","application/x-zmachine"},{"z6","application/x-zmachine"},{"z7","application/x-zmachine"},
	{"z8","application/x-zmachine"},{"zaz","application/vnd.zzazz.deck+xml"},{"zip","application/zip"},
	{"zir","application/vnd.zul"},{"zirz","application/vnd.zul"},{"zmm","application/vnd.handheld-entertainment+xml"},
};
static int g_mime_types_sorted=0;

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

static int MIMETypesCompare(const void *a_a,const void *b_a)
{
	const MIMEType *a=(const MIMEType *)a_a;
	const MIMEType *b=(const MIMEType *)b_a;
	
	return STRICMP(a->ext,b->ext);
}

static const char *FindMIMETypeByExtension(const char *ext)
{
	MIMEType key={ext,0};
	MIMEType *m;
	
	if(!g_mime_types_sorted)
	{
		qsort(g_mime_types,sizeof g_mime_types/sizeof g_mime_types[0],sizeof g_mime_types[0],&MIMETypesCompare);
		
		g_mime_types_sorted=1;
	}
	
	m=(MIMEType *)bsearch(&key,g_mime_types,sizeof g_mime_types/sizeof g_mime_types[0],sizeof g_mime_types[0],&MIMETypesCompare);
	
	if(!m)
		return 0;
	
	return m->type;
}

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

static void get_size_string(char *str,double n)
{
	if(n<1024.*1024.)
		sprintf(str,"%.1fKB",n/1024.);
	else if(n<1024.*1024.*1024.)
		sprintf(str,"%.1fMB",n/1024./1024.);
	else
		sprintf(str,"%.1fGB",n/1024./1024./1024.);
}

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

void yhs_file_server_handler(yhsRequest *re)
{
	if(yhs_get_method(re)&(YHS_METHOD_GET|YHS_METHOD_HEAD))
	{
		const char *root=(char *)yhs_get_handler_context(re);
		char rel_path[MAX_PATH_SIZE];
		char local_path[MAX_PATH_SIZE];

		if(!normalize_path(rel_path,yhs_get_path_handler_relative(re)))
			return;
		
		if(!join_paths(local_path,root,rel_path))
			return;
		
		if(is_folder_path(local_path))
		{
			unsigned num_files=0,num_folders=0;
			double total_size=0.;
			DIR *d=opendir(local_path);
			char size_str[100];
			
			yhs_begin_data_response(re,"text/html");
			
			yhs_html_textf(re,"<html><head><title>Contents of \a+%s\a-</title></head><body>",strlen(rel_path)==0?"/":rel_path);
			
			yhs_html_textf(re,"<pre>");
			
			if(d)
			{
				struct dirent *de;
				
				while((de=readdir(d))!=0)
				{
					char size[100];
					char de_local_path[MAX_PATH_SIZE];
					struct stat st;
					
					if(de->d_name[0]=='.')
						continue;
					
					if(!join_paths(de_local_path,local_path,de->d_name))
						continue;
					
					if(stat(de_local_path,&st)!=0)
						continue;
					
					if(st.st_mode&S_IFDIR)
					{
						strcpy(size,"");
						
						++num_folders;
					}
					else
					{
						get_size_string(size,st.st_size);
						
						total_size+=st.st_size;
						
						++num_files;
					}
					
					yhs_html_textf(re,"%-10s<a href=\"%s%s\">\a+%s\a-</a>\n",size,de->d_name,st.st_mode&S_IFDIR?"/":"",de->d_name);
				}

				closedir(d);
				d=0;
			}
			
			get_size_string(size_str,total_size);
			
			yhs_html_textf(re,"</pre>%s in %u file(s) and %u folder(s)</body></html>",size_str,num_files,num_folders);
		}
		else
		{
			const char *ext=find_path_extension(local_path);
			const char *mime_type=0;
			FILE *f;
			int c;
			
			if(ext)
				mime_type=FindMIMETypeByExtension(ext);
			
			if(!mime_type)
				mime_type="text/plain";
			
			f=fopen(local_path,"rb");
			if(!f)
				return;
			
			yhs_begin_data_response(re,mime_type);
			
			while((c=fgetc(f))!=EOF)
				yhs_data_byte(re,(unsigned char)c);
			
			fclose(f);
			f=0;
		}
	}
}

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

#if ENABLE_UNIT_TESTS
#define CHECK(EXPR) ((EXPR)?(void)0:(DEBUG_BREAK(),(void)0))
#endif//ENABLE_UNIT_TESTS

#if ENABLE_UNIT_TESTS
static void check_same(const void *a_a,const void *b_a,size_t n)
{
	const uint8_t *a=(const uint8_t *)a_a;
	const uint8_t *b=(const uint8_t *)b_a;
	size_t i;

	for(i=0;i<n;++i)
		CHECK(a[i]==b[i]);
}
#endif//ENABLE_UNIT_TESTS

void yhs_run_unit_tests(void)
{
#if ENABLE_UNIT_TESTS

	// test basic packing of field headers
	{
		char input[]=
			"Key:Value\r\n"
			"Key: Value\r\n"
			"Key: Value \r\n";

		char expected[]=
			"Key\x0Value\x0"
			"Key\x0Value\x0"
			"Key\x0Value \x0";

		CHECK(pack_request_fields(input));
		check_same(input,expected,sizeof expected);
	}

	// test continuation lines
	{
		char input[]=
			"Key:Value\r\n"
			"Key2:Value2\r\n"
			" Value3\r\n"
			"\tValue4\r\n"
			" \t Value5\r\n"
			"Key3:Value6\r\n";

		char expected[]=
			"Key\x0Value\x0"
			"Key2\x0Value2 Value3 Value4 Value5\x0"
			"Key3\x0Value6\x0";

		CHECK(pack_request_fields(input));
		check_same(input,expected,sizeof expected);
	}

	// test normalize path
	{
		const char *data[][2]={
			{"..",0,},
			{".","",},
			{"..",0,},
			{".","",},
			{"path1/path2","path1/path2",},
			{"/path1/path2","/path1/path2",},
			{"path1/path2/","path1/path2/",},
			{"/path1/path2/","/path1/path2/",},
			{"/path1/path2/..","/path1/",},
			{"/path1/path2/../..","/",},
			{"path1/path2/../..","",},
		};
		size_t i;
		
		for(i=0;i<sizeof data/sizeof data[0];++i)
		{
			char *nrm=(char *)MALLOC(strlen(data[i][0])+1);
			
			int good=normalize_path(nrm,data[i][0]);
			
			if(!data[i][1])
			{
				CHECK(!good);
			}
			else
			{
				CHECK(good);
				CHECK(strcmp(nrm,data[i][1])==0);
			}
			
			FREE(nrm);
			nrm=0;
		}
	}

	// test websocket key
	{
		const char *data[][2]={
			{"rmb3IfpAZ/ruc2Ho8h/TwQ==","buN6O1ew5kH/hWVhDeN+o0WWW9U="},
			{"vZWhxaF3mVaTWb47cIulwg==","k6PjXkoz5jdjDcVYhrAmLWd5pvI="},
		};
		size_t i;

		for(i=0;i<sizeof data/sizeof data[0];++i)
		{
			char tmp[SEC_WEBSOCKET_ACCEPT_LEN+1];
			make_ws_accept(tmp,data[i][0]);
			CHECK(strcmp(tmp,data[i][1])==0);
		}
	}

// 	// test sha1
// 	{
// 		const char *data[][2]={
// 			{"","da39a3ee5e6b4b0d3255bfef95601890afd80709"},
// 			{"fred","31017a722665e4afce586950f42944a6d331dabf"},
// 			{"The quick brown fox jumps over the lazy dog","2fd4e1c67a2d28fced849ee1bb76e7391b93eb12"},
// 			{"The quick brown fox jumps over the lazy cog","de9f2c7fd25e1b3afad3e85a0bd17d9b100db4b3"},
// 		};
// 		size_t i;
// 
// 		for(i=0;i<sizeof data/sizeof data[0];++i)
// 		{
// 			size_t j;
// 			uint8_t hash[20];
// 
// 			sha1(hash,data[i][0],strlen(data[i][0]));
// 
// 			char hash_str[41];
// 			for(j=0;j<20;++j)
// 				sprintf(hash_str+j*2,"%02x",hash[j]);
// 
// 			CHECK(strcmp(hash_str,data[i][1])==0);
// 		}
// 	}
#endif//ENABLE_UNIT_TESTS
}
