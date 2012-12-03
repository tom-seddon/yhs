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
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <ifaddrs.h>

#define STRNICMP(X,Y,N) (strncasecmp((X),(Y),(N)))
#define CLOSESOCKET(X) (close(X))

typedef int SOCKET;

#define INVALID_SOCKET (-1)

#define DEBUG_BREAK() (assert(0))

#endif

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

// Windows portajunk
#ifdef WIN32

#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <windows.h>

typedef unsigned __int32 uint32_t;
typedef unsigned __int16 uint16_t;
typedef unsigned __int8 uint8_t;

#define STRNICMP(X,Y,N) (strnicmp((X),(Y),(N)))
#define CLOSESOCKET(X) (closesocket(X))

typedef int socklen_t;

#ifdef _MSC_VER
#pragma warning(error:4020)//too many actual parameters
#endif//_MSC_VER

#define DEBUG_BREAK() (__debugbreak())

#endif

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

#include <ctype.h>
#include <assert.h>
#include <stdlib.h>

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

#ifndef NDEBUG

#define ENABLE_UNIT_TESTS 1

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
// - Support HEAD. Should be easy enough. Could be made transparent to the
//   request handler by discarding the response data.
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
    
    // Size of write buffer
    WRITE_BUF_SIZE=8192,
	
	// Max size of server name
	MAX_SERVER_NAME_SIZE=64,
};

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

// Macro wrappers for info and error messages.

//#define YHS_DEBUG_MSG(...) (printf(__VA_ARGS__),(void)0)
#define YHS_DEBUG_MSG(...) ((void)0)

#define YHS_INFO_MSG(...) (printf(__VA_ARGS__),(void)0)

#define YHS_ERR_MSG(...) (fprintf(stderr,__VA_ARGS__),(void)0)

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

// Memory allocation wrappers.

#define MALLOC(SIZE) (malloc(SIZE))
#define FREE(PTR) (free(PTR))

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

static char *yhs_strdup(const char *str)
{
	size_t n;
	char *s;

	assert(str);

	n=strlen(str)+1;

	s=MALLOC(n);

	if(s)
		memcpy(s,str,n);

	return s;
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
    
    char *res_path;
    size_t res_path_len;

	char *description;
    
    yhsResPathHandlerFn handler_fn;
    void *context;
};

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

struct PNGWriteState
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
typedef struct PNGWriteState PNGWriteState;

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

enum yhsResponseFlags
{
	RF_DEFERRED=1,
	RF_OWN_HEADER_DATA=2,
};

enum yhsResponseType
{
    RT_NONE_SET,
    RT_DEFER,

	// TEXT and IMAGE are distinguished for asserting purposes. 
	RT_TEXT,
	RT_IMAGE,
};
typedef enum yhsResponseType yhsResponseType;

enum yhsResponseState
{
	RS_NONE,
	RS_HEADER,
	RS_DATA,
};
typedef enum yhsResponseState yhsResponseState;

struct KeyValuePair
{
    const char *key;
    const char *value;
};
typedef struct KeyValuePair KeyValuePair;

// SCHEME://HOST/PATH;PARAMS?QUERY#FRAGMENT
// \____/   \__/\___/ \____/ \___/ \______/

struct yhsRequest
{
	yhsRequest *next_deferred;

	unsigned flags;
    yhsServer *server;
    
    SOCKET sock;
    yhsResponseType type;
	yhsResponseState state;

	// pngstuff
    PNGWriteState png;

    // form data
    size_t num_controls;
    KeyValuePair *controls;
    char *controls_data_buffer;

	// header data
	char *header_data;
	size_t header_data_size;
	size_t method_pos;
	size_t path_pos;
	size_t first_field_pos;
};

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

struct yhsServer
{
    // socket that listens for incoming connections.
    SOCKET listen_sock;
    
    // doubly-linked. terminator has NULL handler_fn.
    yhsHandler handlers;

	// singly-linked.
	yhsRequest *first_deferred;
    
    // buffer for pending writes.
    char write_buf[WRITE_BUF_SIZE];
    size_t write_buf_data_size;

    // server name
	char name[MAX_SERVER_NAME_SIZE];
};

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

#ifdef WIN32
#define YHS_ERR(MSG) (yhs_err(__FILE__,__LINE__,WSAGetLastError(),(MSG)),(void)0)
#else
#define YHS_ERR(MSG) (yhs_err(__FILE__,__LINE__,errno,(MSG)),(void)0)
#endif

static void yhs_err(const char *file,int line,int err,const char *msg)
{
    YHS_ERR_MSG("YHS: Error:\n");
    YHS_ERR_MSG("    %s(%d): %s: %s\n",file,line,__FUNCTION__,msg);
    
#ifdef WIN32
    {
        char msg[1000];
        
        FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM,0,err,0,msg,sizeof msg,0);
        
        while(strlen(msg)>=0&&isspace(msg[strlen(msg)-1]))
            msg[strlen(msg)-1]=0;
        
        YHS_ERR_MSG("    %d - %s\n",err,msg);
    }
#else
    YHS_ERR_MSG("    %d - %s\n",err,strerror(err));
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

static SOCKET create_listen_socket(int port)
{
    int good=0;
    const int reuse_addr=1;
    struct sockaddr_in listen_addr;
    SOCKET sock=socket(PF_INET,SOCK_STREAM,IPPROTO_TCP);
    
    if(sock<0)
    {
        YHS_ERR("Create listen socket.");
        goto done;
    }
    
    if(setsockopt(sock,SOL_SOCKET,SO_REUSEADDR,(const char *)&reuse_addr,sizeof reuse_addr)<0)
    {
        YHS_ERR("Set REUSEADDR.");
        goto done;
    }
    
    // Bind
    memset(&listen_addr,0,sizeof listen_addr);
    
    listen_addr.sin_family=AF_INET;
    listen_addr.sin_addr.s_addr=htonl(INADDR_ANY);
    
    assert(port>=0&&port<65536);
    listen_addr.sin_port=htons((u_short)port);
    
    if(bind(sock,(struct sockaddr *)&listen_addr,sizeof(listen_addr))<0)
    {
        YHS_ERR("Bind listen socket.");
        goto done;
    }
    
    // Listen
    if(listen(sock,LISTEN_SOCKET_BACKLOG)<0)
    {
        YHS_ERR("Set listen socket to listen mode.");
        goto done;
    }
    
    good=1;
    
done:
    if(!good)
    {
        CLOSESOCKET(sock);
        sock=INVALID_SOCKET;
    }
    
    return sock;
}

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

static void print_likely_urls(int port)
{
    YHS_INFO_MSG("YHS: Likely URLs for this system are:\n");
    YHS_INFO_MSG("\n");
    
#ifdef WIN32
    
    {
        char computer_name[500];
        DWORD computer_name_size=sizeof computer_name;
        
        if(!GetComputerNameExA(ComputerNameDnsHostname,computer_name,&computer_name_size))
            YHS_INFO_MSG("YHS: Failed to get computer name.\n");
        else
        {
            YHS_INFO_MSG("    http://%s",computer_name);
            
            if(port!=80)
                YHS_INFO_MSG(":%d",port);
            
            YHS_INFO_MSG("/\n");
        }
    }
    
#else
    
    {
        struct ifaddrs *interfaces;
        if(getifaddrs(&interfaces)<0)
        {
            YHS_ERR("Get network interfaces.");
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
                
                YHS_INFO_MSG("    http://%d.%d.%d.%d",(addr>>24)&0xFF,(addr>>16)&0xFF,(addr>>8)&0xFF,(addr>>0)&0xFF);
                
                if(port!=80)
                    YHS_INFO_MSG(":%d",port);
                
                YHS_INFO_MSG("/\n");
            }
        }
        
        freeifaddrs(interfaces);
        interfaces=NULL;
        
        YHS_INFO_MSG("\n");
    }
    
#endif
}

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

yhsServer *yhs_new_server(int port)
{
    int good=0;
    
    yhsServer *server=(yhsServer *)MALLOC(sizeof *server);

	if(!server)
		goto done;

    memset(server,0,sizeof *server);
    
    server->handlers.next=&server->handlers;
    server->handlers.prev=&server->handlers;
    
    server->listen_sock=create_listen_socket(port);
    if(server->listen_sock<0)
        goto done;
    
    print_likely_urls(port);
	
	yhs_set_server_name(server,"yhs");
    
    good=1;
    
done:
    if(!good)
    {
        yhs_delete_server(server);
        server=NULL;
    }
    
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
        
        FREE(h->res_path);
        FREE(h);
        
        h=next;
    }
    
    if(server->listen_sock>=0)
        CLOSESOCKET(server->listen_sock);
    
    FREE(server);
}

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

static int check_socket_readability(SOCKET sock,int num_seconds,int *is_readable)
{
    struct timeval timeout;
    fd_set read_fds;
    int nfds=0;
    
    timeout.tv_sec=num_seconds;
    timeout.tv_usec=0;
    
    FD_ZERO(&read_fds);
#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable:4127)
#endif
    FD_SET(sock,&read_fds);
#ifdef _MSC_VER
#pragma warning(pop)
#endif
    
#ifndef WIN32
    nfds=sock+1;
#endif//WIN32
    
    if(select(nfds,&read_fds,NULL,NULL,&timeout)<0)
        return 0;
    
    *is_readable=FD_ISSET(sock,&read_fds);
    return 1;
}

// Accepts request and stores header. *data_size is set to total data read,
// maybe including part of the payload; *request_size points just after the
// \r\n\r\n that terminates the request header.
static int accept_request(SOCKET listen_sock,SOCKET *accepted_sock)
{
    struct sockaddr_in client_addr;
    socklen_t client_addr_size=sizeof client_addr;
    int is_accept_waiting;
    
    // Maybe accept request?
    if(!check_socket_readability(listen_sock,0,&is_accept_waiting))
    {
        YHS_ERR("Check listen socket readability.");
        // @TODO: Should close and re-open socket if this happens.
        return 0;
    }
    
    if(!is_accept_waiting)
        return 0;//nobody waiting.
    
    // Accept socket.
    *accepted_sock=accept(listen_sock,(struct sockaddr *)&client_addr,&client_addr_size);
    if(*accepted_sock<0)
    {
        YHS_ERR("Accept incoming connection on listen socket.");
        return 0;
    }
    
    return 1;
}

static int read_request_header(SOCKET sock,char *buf,size_t buf_size,size_t *request_size)
{
    // Keep reading until the data ends with the \r\n\r\n that signifies the
    // end of the request, or there's no more buffer space.
    int good=0;
    
    *request_size=0;
    
    for(;;)
    {
        int is_data_waiting,n;
        
        if(!check_socket_readability(sock,10,&is_data_waiting))
        {
            YHS_ERR("Check accepted socket readability.");
            break;
        }
        
        if(!is_data_waiting)
        {
            // The polling timeout is deliberately set high; if there's no
            // data waiting in that time, the client must have given up.
            YHS_ERR("Timed out waiting for client to send request.");
            break;
        }
        
        if(*request_size==buf_size)
        {
            // Too much data in request header.
            YHS_ERR_MSG("Request too large.");
            break;
        }
        
        n=recv(sock,buf+*request_size,1,0);
        if(n<=0)
        {
            // Error, or client closed connection prematurely.
            if(n<0)
                YHS_ERR("Read accepted socket.");
            
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
static int find_handler_for_res_path(yhsServer *server,yhsResPathHandlerFn *handler_fn,void **context,const char *res_path)
{
    yhsHandler *h;
    size_t res_path_len=strlen(res_path);
    
    for(h=server->handlers.prev;h->handler_fn;h=h->prev)
    {
        if(res_path_len>=h->res_path_len)
        {
            if(strncmp(h->res_path,res_path,h->res_path_len)==0)
            {
                if(res_path_len==h->res_path_len||
                   (h->res_path[h->res_path_len-1]=='/'&&!strchr(res_path+h->res_path_len,'/')))
                {
                    *handler_fn=h->handler_fn;
                    *context=h->context;
                    
                    return 1;
                }
            }
        }
    }

    return 0;
}

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

// send data to client, with some buffering.

static void flush_write_buf(yhsRequest *re)
{
	if(re->server->write_buf_data_size>0)
	{
		int n=send(re->sock,re->server->write_buf,re->server->write_buf_data_size,0);
		if(n<0||(size_t)n!=re->server->write_buf_data_size)
			YHS_ERR("write.");

		re->server->write_buf_data_size=0;
	}
}

static void send_byte(yhsRequest *re,uint8_t value)
{
	assert(re->server->write_buf_data_size<sizeof re->server->write_buf);
	re->server->write_buf[re->server->write_buf_data_size++]=value;

	if(re->server->write_buf_data_size==sizeof re->server->write_buf)
		flush_write_buf(re);
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

static void finish_response(yhsRequest *re)
{
    if(re->type==RT_IMAGE)
        assert(re->png.y==re->png.h);
    
    flush_write_buf(re);
    
    CLOSESOCKET(re->sock);

	FREE(re->controls);
	FREE(re->controls_data_buffer);

	if(re->flags&RF_OWN_HEADER_DATA)
		FREE(re->header_data);

	reset_request(re);
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

static void send_response_byte(yhsRequest *re,uint8_t value)
{
	assert(re->state==RS_HEADER||re->state==RS_DATA);

	// If still sending the header, finish it off.
	if(re->state==RS_HEADER)
	{
		send_string(re,"\r\n");

		re->state=RS_DATA;
	}

	send_byte(re,value);
}

static void debug_dump_string(const char *str,int max_len)
{
    int i;
    
    for(i=0;(max_len<0||i<max_len)&&str[i]!=0;++i)
    {
        switch(str[i])
        {
        case '\n':
            YHS_DEBUG_MSG("\\n");
            break;
            
        case '\r':
            YHS_DEBUG_MSG("\\r");
            break;
            
        case '\t':
            YHS_DEBUG_MSG("\\t");
            break;
            
        case '"':
            YHS_DEBUG_MSG("\\\"");
            break;
            
        default:
            YHS_DEBUG_MSG("%c",str[i]);
            break;
        }
    }
}

static void toc_handler(yhsRequest *re,void *context)
{
	yhsHandler *h;

	(void)context;

	yhs_data_response(re,"text/html");
	
	yhs_textf(re,"<html>\n");
	yhs_html_textf(re,YHS_HEF_OFF," <head><title>\x1by%s\x1bn - Contents</title></head>\n",re->server->name);
	yhs_textf(re," <body>\n");
	yhs_html_textf(re,YHS_HEF_OFF," <h1>\x1by%s\x1bn - Contents</h1>\n",re->server->name);
	
	for(h=re->server->handlers.next;h->handler_fn;h=h->next)
	{
		if(h->flags&HF_TOC)
		{
			yhs_html_textf(re,YHS_HEF_OFF," <p><a href=\"\x1by%s\x1bn\">",h->res_path);
			
			if(h->description)
				yhs_html_textf(re,0,"%s (",h->description);

			yhs_html_textf(re,YHS_HEF_OFF,"<tt>\x1by%s\x1bn</tt>",h->res_path);

			if(h->description)
				yhs_textf(re,")");

			yhs_textf(re,"\n");
		}
	}
	
	yhs_textf(re," </body>\n");
	yhs_textf(re,"</html>\n");
}

const char *yhs_get_path(yhsRequest *re)
{
	const char *path=re->header_data+re->path_pos;
	return path;
}

const char *yhs_get_method(yhsRequest *re)
{
	const char *method=re->header_data+re->method_pos;
	return method;
}

const char *yhs_find_header_field(yhsRequest *re,const char *key,const char *last_result)
{
	const char *field;
	
	if(last_result)
	{
		assert(last_result>=re->header_data+re->first_field_pos&&last_result<re->header_data+re->header_data_size);
		field=last_result+strlen(last_result)+1;
	}
	else
		field=re->header_data+re->first_field_pos;

	for(;;)
	{
		const char *k=field;
		size_t n=strlen(k);
		const char *v=k+n+1;
		
		if(n==0)
			return 0;

		if(strcmp(k,key)==0)
			return v;

		field=v+strlen(v)+1;
	}
}

int yhs_update(yhsServer *server)
{
    int any=0;
    
    if(!server)
        return 0;
    
    for(;;)
    {
        // response gunk
        const char *response_line=NULL;
        yhsResPathHandlerFn handler_fn=NULL;
        void *context=NULL;
        yhsRequest re;
        
        // request and parts
		const char *path;
        char header_data_buf[MAX_REQUEST_SIZE+1];
        
		reset_request(&re);

        if(!accept_request(server->listen_sock,&re.sock))
            break;
        
        any=1;
        re.server=server;

		re.server=server;
        re.header_data=header_data_buf;

		// read header and 0-terminate so that it ends with a single \r\n.
        if(!read_request_header(re.sock,re.header_data,MAX_REQUEST_SIZE,&re.header_data_size))
        {
            response_line="500 Internal Server Error";
            goto respond;
        }
        
        YHS_DEBUG_MSG("REQUEST(RAW): %u/%u bytes:\n---8<---\n",(unsigned)re.header_data_size,(unsigned)re.header_data);
        debug_dump_string(re.header_data,-1);
        YHS_DEBUG_MSG("\n---8<---\n");
        
        if(!process_request_header(re.header_data,&re.method_pos,&re.path_pos,&re.first_field_pos))
        {
            response_line="400 Bad Request";
            goto respond;
        }

		path=yhs_get_path(&re);
        
        YHS_INFO_MSG("REQUEST: Method: %s\n",yhs_get_method(&re));
        YHS_INFO_MSG("         Res Path: \"%s\"\n",path);

        if(!find_handler_for_res_path(server,&handler_fn,&context,path))
        {
			if(strcmp(path,"/")==0)
			{
				handler_fn=&toc_handler;
				context=NULL;
			}
			else
			{
				response_line="404 Not Found";
				goto respond;
			}
        }
        
    respond:
		if(!response_line)
		{
			(*handler_fn)(&re,context);
		
			if(re.type==RT_NONE_SET)
				response_line="404 Not Found";
		}
		
		if(response_line)
			yhs_error_response(&re,response_line);
		
		if(re.type!=RT_DEFER)
			finish_response(&re);
    }

    return any;
}

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

void yhs_data_response(yhsRequest *re,const char *type)
{
    assert(re->type==RT_NONE_SET);
	
	header(re,RT_TEXT,"200 OK");//,"Content-Type",type,(char *)0);
	yhs_header_field(re,"Content-Type",type);
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

void yhs_html_textf(yhsRequest *re,unsigned escape_flags,const char *fmt,...)
{
    va_list v;
    va_start(v,fmt);
    yhs_html_textv(re,escape_flags,fmt,v);
    va_end(v);
}

void yhs_html_textv(yhsRequest *re,unsigned escape_flags,const char *fmt,va_list v)
{
    char text[MAX_TEXT_LEN];
    
    vsnprintf(text,sizeof text,fmt,v);
	text[sizeof text-1]=0;
    
    yhs_html_text(re,escape_flags,text);
}

void yhs_html_text(yhsRequest *re,unsigned escape_flags,const char *text)
{
	int escape=1;//@TODO make this configurable with a flag again??
	int br=!!(escape_flags&YHS_HEF_BR);
	int on=!(escape_flags&YHS_HEF_OFF);
	int esc=0;
	const char *c;
	
	for(c=text;*c!=0;++c)
	{
		if(esc)
		{
			if(*c=='y')
				on=1;
			else if(*c=='n')
				on=0;
			else
			{
				// umm...
			}
			
			esc=0;
		}
		else
		{
			if(*c=='\x1b')
				esc=1;
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
		send_response_byte(re,p[i]);
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

void yhs_image_response(yhsRequest *re,int width,int height,int ncomp)
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
	header(re,RT_TEXT,status_line);
	yhs_header_field(re,"Content-Type","text/html");
    
    yhs_textf(re,"<html>\n");
    yhs_textf(re," <head>\n");
    yhs_textf(re,"  <title>%s - %s</title>\n",re->server->name,status_line);
    yhs_textf(re," </head>\n");
    yhs_textf(re," <body>\n");
    yhs_textf(re,"  <h1>%s - %s</h1>",re->server->name,status_line);
    yhs_textf(re,"  <hr>\n");
	
	yhs_textf(re,"  <p>HTTP Method: <tt>%s</tt></p>",yhs_get_method(re));
	yhs_textf(re,"  <p>Resource Path: <tt>%s</tt></p>",yhs_get_path(re));
	
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

yhsRequest *yhs_defer_response(yhsRequest *re)
{
	yhsRequest *dre;
	char *new_header_data;

	// TODO - tidy this up. There's no reason a deferred response couldn't be
    // deferred again, even though it would be a bit pointless.
	assert(!(re->flags&(RF_DEFERRED|RF_OWN_HEADER_DATA)));

	dre=(yhsRequest *)MALLOC(sizeof *dre);
	new_header_data=(char *)MALLOC(re->header_data_size);

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
	dre->header_data=new_header_data;
	memcpy(dre->header_data,re->header_data,re->header_data_size);
	dre->flags|=RF_OWN_HEADER_DATA;

	// add to the links.
	dre->next_deferred=dre->server->first_deferred;
	dre->server->first_deferred=dre;

	// mark original request as deferred, so it can be discarded.
	reset_request(re);
	re->type=RT_DEFER;

	return dre;
}

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

void yhs_end_deferred_response(yhsRequest *re)
{
	assert(re->flags&RF_DEFERRED);
    
    finish_response(re);

	FREE(re);
}

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

int yhs_get_content(yhsRequest *re,int num,char *buf)
{
    int num_recvd=0;
    
    while(num_recvd<num)
    {
        int r,is_readable;
        
        if(!check_socket_readability(re->sock,0,&is_readable))
        {
            YHS_ERR("check socket readability.");
            return 0;
        }
        
        if(!is_readable)
            break;
        
        r=recv(re->sock,buf+num_recvd,num-num_recvd,0);
        
        if(r==-1)
        {
            YHS_ERR("recv.");
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
	assert(!re->controls_data_buffer);
    re->controls_data_buffer=(char *)MALLOC(content_length+1);
    if(!re->controls_data_buffer)
        goto done;
    
    if(!yhs_get_content(re,content_length,re->controls_data_buffer))
        goto done;
    
    re->controls_data_buffer[content_length]=0;
    
    // Count controls.
    re->num_controls=1;
    {
        int i;
        
        for(i=0;re->controls_data_buffer[i]!=0;++i)
        {
            if(re->controls_data_buffer[i]=='&')
                ++re->num_controls;
        }
    }
    
    // Controls...
    re->controls=(KeyValuePair *)MALLOC(re->num_controls*sizeof *re->controls);
	if(!re->controls)
		goto done;
    
    //
    {
        KeyValuePair *control=re->controls;
        char *dest=re->controls_data_buffer;
        const char *src=re->controls_data_buffer;
        
        while(src<re->controls_data_buffer+content_length)
        {
            assert(control<re->controls+re->num_controls);
            
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
        
        assert(control==re->controls+re->num_controls);
    }
    
    good=1;
    
done:
    if(!good)
    {
        FREE(re->controls_data_buffer);
		re->controls_data_buffer=NULL;
        
        FREE(re->controls);
        re->controls=NULL;
		
        re->num_controls=0;
    }
    
    return good;
}

YHS_EXTERN const char *yhs_find_control_value(yhsRequest *re,const char *control_name)
{
    size_t i;
    
    for(i=0;i<re->num_controls;++i)
    {
        const KeyValuePair *kvp=&re->controls[i];
        
        if(strcmp(kvp->key,control_name)==0)
            return kvp->value;
    }
    
    return NULL;
}

YHS_EXTERN size_t yhs_get_num_controls(yhsRequest *re)
{
    return re->num_controls;
}

YHS_EXTERN const char *yhs_get_control_name(yhsRequest *re,size_t index)
{
    assert(index<re->num_controls);
    
    return re->controls[index].key;
}

YHS_EXTERN const char *yhs_get_control_value(yhsRequest *re,size_t index)
{
    assert(index<re->num_controls);
    
    return re->controls[index].value;
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

#endif//ENABLE_UNIT_TESTS
}
