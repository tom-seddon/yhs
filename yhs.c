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

#endif

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

#include <ctype.h>
#include <assert.h>
#include <stdlib.h>

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

struct Handler
{
    struct Handler *next,*prev;
    
    char *res_path;
    size_t res_path_len;
    
    yhsResPathHandlerFn handler_fn;
    void *context;
};
typedef struct Handler Handler;

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

struct PNGWriteState
{
    // Dimensions of image and bytes/pixel
    int w,h,bypp;
    
    // Coords of next pixel to be written
    int x,y;
    
    // Chunk CRC so far
    uint32_t chunk_crc;
    
    // Adler sums for the Zlib encoding
    uint32_t adler32_s1,adler32_s2;
};
typedef struct PNGWriteState PNGWriteState;

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

enum yhsResponseType
{
    RT_NONE_SET,
    RT_TEXT,
    RT_IMAGE,
    RT_DEFER,
};
typedef enum yhsResponseType yhsResponseType;

struct KeyValuePair
{
    const char *key;
    const char *value;
};
typedef struct KeyValuePair KeyValuePair;

struct yhsResponse
{
    yhsServer *server;
    
    SOCKET sock;
    yhsResponseType type;
    
    PNGWriteState png;

    // pointer to first part of content.
    char *content;
    int content_size;
    
    // form data
    size_t num_controls;
    KeyValuePair *controls;
    char *controls_data_buffer;
};

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

struct yhsServer
{
    // socket that listens for incoming connections.
    SOCKET listen_sock;
    
    // doubly-linked. terminator has NULL handler_fn.
    Handler handlers;
    
    // Temporary yhsResponse for handling deferred responses.
    yhsResponse tmp_re;
    int is_tmp_re_in_use;

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
    Handler *h;
    
    if(!server)
        return;
    
    h=server->handlers.next;
    while(h->handler_fn)
    {
        Handler *next=h->next;
        
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

static int read_request_header(SOCKET sock,char *buf,size_t buf_size,size_t *data_size,size_t *request_size)
{
    // Keep reading until the data ends with the \r\n\r\n that signifies the
    // end of the request, or there's no more buffer space.
    int good=0;
    
    *data_size=0;
    
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
        
        if(*data_size==buf_size)
        {
            // Too much data in request header.
            YHS_ERR_MSG("Request too large.");
            break;
        }
        
        n=recv(sock,buf+*data_size,(int)(buf_size-*data_size),0);
        if(n<=0)
        {
            // Error, or client closed connection prematurely.
            if(n<0)
                YHS_ERR("Read accepted socket.");
            
            break;
        }
        
        *data_size+=n;
        
        // Is there a \r\n\r\n yet?
        if(*data_size>=4)
        {
            size_t i;
            
            for(i=0;i<*data_size-3;++i)
            {
                if(buf[i+0]=='\r'&&buf[i+1]=='\n'&&buf[i+2]=='\r'&&buf[i+3]=='\n')
                {
                    *request_size=i+4;
                    good=1;
                    
                    // Any associated data from the browser may be partly in
                    // the buffer after the end of the request, and partly in
                    // the socket's recv buffer.
                    
                    goto done;
                }
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

static const char *fix_up_uri(char *uri_arg)
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
            return "/";
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

// Splits an HTTP request line ("METHOD URI HTTP-Ver") into its method and
// URI path parts. *method and *res_path point into line[], which has 0s
// poked in as appropriate.
static int tokenize_request_line(char *line,const char **method,const char **res_path)
{
    const char *http_version;
    char *uri;
    
    *method=strtok(line," ");
    
    uri=strtok(NULL," ");
    
    http_version=strtok(NULL," ");
    (void)http_version;//but you might like to see it in the debugger.
    
    *res_path=fix_up_uri(uri);
    
    return 1;
}

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

// Splits an HTTP header line ("Key:Value") into its key and value parts.
// *key and *value point into line[], which has 0s poked in as appropriate.
static int tokenize_header_line(char *line,const char **key,const char **value)
{
    char *colon,*key_end;
    
    colon=strchr(line,':');
    if(!colon)
        return 0;
    
    key_end=colon;
    *key_end--=0;
    
    while(key_end>line&&isspace(*key_end))
        *key_end--=0;
    
    if(key_end==line)
        return 0;
    
    *key=line;
    
    *value=colon+1;
    while(**value!=0&&isspace(**value))
        ++*value;
    
    if(**value==0)
        return 0;
    
    return 1;
}

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

static char *do_line(char **pos)
{
    char *line_start=*pos;
    char *line_end=strstr(*pos,"\r\n");
    
    if(!line_end)
    {
        line_end=*pos+strlen(*pos);
        *pos=line_end;
    }
    else
    {
        *pos=line_end+2;
        *line_end=0;
    }
    
    return line_start;
}

// Takes an HTTP request (request line, then header lines) and fishes out the
// interesting parts: method, resource path, pointer to first header line.
static int parse_request(char *request,const char **method,const char **res_path,char **first_header_line)
{
    char *pos=request;
    char *request_line=do_line(&pos);
    
    if(!tokenize_request_line(request_line,method,res_path))
        return 0;
    
    *first_header_line=pos;
    
    return 1;
}

static int parse_request_header(char *first_header_line,const char *key0,...)
{
    char *pos=first_header_line;
    
    if(key0)
    {
        va_list v;
        const char *key;
        
        va_start(v,key0);
        
        for(key=key0;key;key=va_arg(v,const char *))
            *va_arg(v,const char **)=NULL;
        
        va_end(v);
    }
    
    for(;;)
    {
        const char *header_key,*header_value;
        char *header_line=do_line(&pos);
        
        if(strlen(header_line)==0)
            break;
        
        if(!tokenize_header_line(header_line,&header_key,&header_value))
            return 0;
        
        if(key0)
        {
            va_list v;
            const char *key;
            
            va_start(v,key0);
            
            for(key=key0;key;key=va_arg(v,const char *))
            {
                const char **value=va_arg(v,const char **);
                
                if(strcmp(header_key,key)==0)
                {
                    *value=header_value;
                    break;
                }
            }
            
            va_end(v);
        }
    }
    
    return 1;
}

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

// yhsResPathHandlerFn that prints a 404 message.
//static void error_handler(yhsResponse *re,void *context,yhsResPathHandlerArgs *args)
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
static int find_handler(yhsServer *server,const yhsResPathHandlerArgs *args,yhsResPathHandlerFn *handler_fn,void **context)
{
    Handler *h;
    size_t res_path_len=strlen(args->res_path);
    
    for(h=server->handlers.prev;h->handler_fn;h=h->prev)
    {
        if(res_path_len>=h->res_path_len)
        {
            if(strncmp(h->res_path,args->res_path,h->res_path_len)==0)
            {
                if(res_path_len==h->res_path_len||
                   (h->res_path[h->res_path_len-1]=='/'&&!strchr(args->res_path+h->res_path_len,'/')))
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

static void flush_write_buf(yhsResponse *re);

static void reset_response(yhsResponse *re,yhsServer *server,SOCKET sock)
{
    memset(re,0,sizeof *re);
    
    re->server=server;
    re->sock=sock;
}

static void finish_response(yhsResponse *re)
{
    if(re->type==RT_IMAGE)
        assert(re->png.y==re->png.h);
    
    flush_write_buf(re);
    
    CLOSESOCKET(re->sock);
}

static void header(yhsResponse *re,yhsResponseType type,const char *status,const char *key0,...)
{
	const char *key;
	va_list v;
	
	assert(re->type==RT_NONE_SET);
	re->type=type;
	
	yhs_textf(re,"HTTP/1.1 %s\r\n",status);
	
	va_start(v,key0);
	for(key=key0;key;key=va_arg(v,const char *))
	{
		const char *value=va_arg(v,const char *);
		
		if(key&&value)
			yhs_textf(re,"%s: %s\r\n",key,value);
	}
	
	yhs_textf(re,"\r\n");
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

static void toc_handler(yhsResponse *re,void *context,yhsResPathHandlerArgs *args)
{
	Handler *h;

	(void)args,(void)context;

	yhs_data_response(re,"text/html");
	
	yhs_textf(re,"<html>\n");
	yhs_html_textf(re,YHS_HEF_OFF," <head><title>\x1by%s\x1bn - Contents</title></head>\n",re->server->name);
	yhs_textf(re," <body>\n");
	yhs_html_textf(re,YHS_HEF_OFF," <h1>\x1by%s\x1bn - Contents</h1>\n",re->server->name);
	
	for(h=re->server->handlers.next;h->handler_fn;h=h->next)
		yhs_html_textf(re,YHS_HEF_OFF," <p><a href=\"\x1by%s\x1bn\">\x1by%s\x1bn</a></p>\n",h->res_path,h->res_path);
	
	yhs_textf(re," </body>\n");
	yhs_textf(re,"</html>\n");
}

int yhs_update(yhsServer *server)
{
    int any=0;
    
    if(!server)
        return 0;
    
    for(;;)
    {
        // incoming data socket
        SOCKET accepted_sock;
        
        // response gunk
        const char *response_line=NULL;
        yhsResPathHandlerFn handler_fn=NULL;
        void *context=NULL;
        yhsResPathHandlerArgs args={0};
        yhsResponse re;
        
        // request and parts
        char data[MAX_REQUEST_SIZE+1];
        size_t data_size,request_size;
        char *request_header;
        
        if(!accept_request(server->listen_sock,&accepted_sock))
            break;
        
        any=1;
        
        reset_response(&re,server,accepted_sock);
        
        if(!read_request_header(accepted_sock,data,sizeof data-1,&data_size,&request_size))
        {
            response_line="500 Internal Server Error";
            goto respond;
        }
        
        // 0-terminate the request; it now ends with a single \r\n.
        data[request_size-2]=0;
        
        YHS_DEBUG_MSG("REQUEST(RAW): %u/%u bytes:\n---8<---\n",(unsigned)request_size,(unsigned)data_size);
        debug_dump_string(data,-1);
        YHS_DEBUG_MSG("\n---8<---\n");
        
        // Store first part of content, if there is any
        if(request_size!=data_size)
        {
            YHS_DEBUG_MSG("BODY(RAW):\n---8<---\n");
            debug_dump_string(data+request_size,data_size-request_size);
            YHS_DEBUG_MSG("\n---8<---\n");
            
            re.content=data+request_size;
            re.content_size=data_size-request_size;
        }
        
        if(!parse_request(data,&args.method,&args.res_path,&request_header))
        {
            response_line="400 Bad Request";
            goto respond;
        }
        
        YHS_INFO_MSG("REQUEST: Method: %s\n",args.method);
        YHS_INFO_MSG("         Res Path: \"%s\"\n",args.res_path);

        if(!find_handler(server,&args,&handler_fn,&context))
        {
			if(strcmp(args.res_path,"/")==0)
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
        
		// Check method and perform any method-specific processing.
        if(strcmp(args.method,"GET")==0)
        {
        }
        else if(strcmp(args.method,"POST")==0)
        {
            const char *content_length;
            
            if(!parse_request_header(request_header,"Content-Type",&args.content_type,"Content-Length",&content_length,NULL))
            {
                response_line="400 Bad Request";
                goto respond;
            }
            
            if(content_length)
                args.content_length=atoi(content_length);
        }
        else
            response_line="501 Not Implemented";
        
    respond:
		if(!response_line)
		{
			(*handler_fn)(&re,context,&args);
		
			if(re.type==RT_NONE_SET)
				response_line="404 Not Found";
		}
		
		if(response_line)
			yhs_error_response(&re,response_line,&args);
		
		if(re.type!=RT_DEFER)
			finish_response(&re);
		
		FREE(re.controls_data_buffer);
		FREE(re.controls);
    }

    return any;
}

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

static void flush_write_buf(yhsResponse *re)
{
    if(re->server->write_buf_data_size>0)
    {
        int n=send(re->sock,re->server->write_buf,re->server->write_buf_data_size,0);
        if(n<0||(size_t)n!=re->server->write_buf_data_size)
            YHS_ERR("write.");
        
        re->server->write_buf_data_size=0;
    }
}

void yhs_data_response(yhsResponse *re,const char *type)
{
    assert(re->type==RT_NONE_SET);
	
	header(re,RT_TEXT,"200 OK","Content-Type",type,(char *)0);
}

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

void yhs_textf(yhsResponse *re,const char *fmt,...)
{
    va_list v;
    va_start(v,fmt);
    yhs_textv(re,fmt,v);
    va_end(v);
}

void yhs_textv(yhsResponse *re,const char *fmt,va_list v)
{
    char text[MAX_TEXT_LEN];
    
    vsnprintf(text,sizeof text,fmt,v);
	text[sizeof text-1]=0;
    
	// not amazing, as yhs_text calls strlen, even though
	// vsnprintf will usually return the right value. 
    yhs_text(re,text);
}

void yhs_text(yhsResponse *re,const char *text)
{
	yhs_data(re,text,strlen(text));
}

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

void yhs_html_textf(yhsResponse *re,unsigned escape_flags,const char *fmt,...)
{
    va_list v;
    va_start(v,fmt);
    yhs_html_textv(re,escape_flags,fmt,v);
    va_end(v);
}

void yhs_html_textv(yhsResponse *re,unsigned escape_flags,const char *fmt,va_list v)
{
    char text[MAX_TEXT_LEN];
    
    vsnprintf(text,sizeof text,fmt,v);
	text[sizeof text-1]=0;
    
    yhs_html_text(re,escape_flags,text);
}

void yhs_html_text(yhsResponse *re,unsigned escape_flags,const char *text)
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

void yhs_data(yhsResponse *re,const void *data,size_t data_size)
{
    size_t i;
    const uint8_t *p=(const uint8_t *)data;
    
//	// assume it's all going to be OK, if it's got this far and
//	// the status has yet to be sent.
//	maybe_send_status_code(re,"200 OK");
	
    for(i=0;i<data_size;++i)
    {
        re->server->write_buf[re->server->write_buf_data_size++]=p[i];
        
        if(re->server->write_buf_data_size==sizeof re->server->write_buf)
            flush_write_buf(re);
    }
}

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

static uint32_t yhs_crc_table[256];

static void png8(yhsResponse *re,uint8_t value)
{
    assert(yhs_crc_table[1]!=0);
    
    re->png.chunk_crc=(re->png.chunk_crc>>8)^yhs_crc_table[value^(re->png.chunk_crc&0xFF)];
    
    yhs_data(re,&value,1);
}

static void png8_adler(yhsResponse *re,uint8_t value)
{
    png8(re,value);
    
    re->png.adler32_s1+=value;
    re->png.adler32_s1%=65521;
    
    re->png.adler32_s2+=re->png.adler32_s1;
    re->png.adler32_s2%=65521;
}

static void png32(yhsResponse *re,uint32_t value)
{
    png8(re,(uint8_t)(value>>24));
    png8(re,(uint8_t)(value>>16));
    png8(re,(uint8_t)(value>>8));
    png8(re,(uint8_t)(value>>0));
}

static void start_png_chunk(yhsResponse *re,uint32_t length,const char *name)
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

static void end_png_chunk(yhsResponse *re)
{
    png32(re,~re->png.chunk_crc);
}

static const uint8_t png_sig[]={137,80,78,71,13,10,26,10,};

void yhs_image_response(yhsResponse *re,int width,int height,int ncomp)
{
    assert(ncomp==3||ncomp==4);
    assert(re->type==RT_NONE_SET);
	
	header(re,RT_IMAGE,"200 OK","Content-Type","image/png",(char *)0);
    
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
    
//    yhs_text(re,"Content-Type: image/png\r\n\r\n");
    
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

void yhs_pixel(yhsResponse *re,int r,int g,int b,int a)
{
    assert(re->type==RT_IMAGE);
    assert(re->png.y<re->png.h);
    
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

void yhs_error_response(yhsResponse *re,const char *status_line,yhsResPathHandlerArgs *args)
{
	header(re,RT_TEXT,status_line,"Content-Type","text/html",(char *)0);
    
    yhs_textf(re,"<html>\n");
    yhs_textf(re," <head>\n");
    yhs_textf(re,"  <title>%s - %s</title>\n",re->server->name,status_line);
    yhs_textf(re," </head>\n");
    yhs_textf(re," <body>\n");
    yhs_textf(re,"  <h1>%s - %s</h1>",re->server->name,status_line);
    yhs_textf(re,"  <hr>\n");
	
	if(args)
	{
		yhs_textf(re,"  <p>HTTP Method: <tt>%s</tt></p>",args->method);
		yhs_textf(re,"  <p>Resource Path: <tt>%s</tt></p>",args->res_path);
	}
	
    yhs_textf(re,"  <hr>\n");
    yhs_textf(re,"  <i>yocto HTTP server - compiled at %s on %s</i>\n",__TIME__,__DATE__);
    yhs_textf(re," </body>\n");
    yhs_textf(re,"</html>");
}

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

void yhs_see_other_response(yhsResponse *re,const char *destination)
{
	header(re,RT_TEXT,"303 See Other","Location",destination,(char *)0);
}

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

void yhs_defer_response(yhsResponse *re,yhsDeferredResponse *dre)
{
    assert(re->type==RT_NONE_SET);
    re->type=RT_DEFER;
    
    dre->server=re->server;
    dre->token=(void *)(size_t)re->sock;
}

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

yhsResponse *yhs_begin_deferred_response(yhsDeferredResponse *dre)
{
    yhsServer *server=dre->server;
    
    assert(!server->is_tmp_re_in_use);
    
    reset_response(&server->tmp_re,server,(SOCKET)(size_t)dre->token);
    server->is_tmp_re_in_use=1;
    
    memset(dre,0,sizeof *dre);
    
    return &server->tmp_re;
}

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

void yhs_end_deferred_response(yhsResponse *re)
{
    assert(re==&re->server->tmp_re);
    assert(re->server->is_tmp_re_in_use);
    
    finish_response(re);
    
    re->server->is_tmp_re_in_use=0;
}

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

int yhs_get_content(yhsResponse *re,int num,char *buf)
{
    int num_recvd=0;
    
    assert(!re->server->is_tmp_re_in_use);
    
    // Copy out of content buffer.
    if(re->content_size>0)
    {
        int n=num;
        if(n>re->content_size)
            n=re->content_size;
        
        memcpy(buf,re->content,n);
        
        re->content_size-=n;
        re->content+=n;
        num_recvd+=n;
        
        if(re->content_size==0)
            re->content=NULL;
    }
    
    // Fetch from socket.
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

YHS_EXTERN int yhs_read_form_content(yhsResponse *re,const yhsResPathHandlerArgs *args)
{
    int good=0;

	// Check there's actually some content attached.
	if(!args->content_type)
		goto done;
    
    // Sorry, only application/x-www-form-urlencoded for now.
    if(strcmp(args->content_type,"application/x-www-form-urlencoded")!=0)
        goto done;
    
    if(args->content_length==0)
        goto done;
    
    // Get form data and pop a \0x at the end.
	assert(!re->controls_data_buffer);
    re->controls_data_buffer=(char *)MALLOC(args->content_length+1);
    if(!re->controls_data_buffer)
        goto done;
    
    if(!yhs_get_content(re,args->content_length,re->controls_data_buffer))
        goto done;
    
    re->controls_data_buffer[args->content_length]=0;
    
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
    
    //
    {
        KeyValuePair *control=re->controls;
        char *dest=re->controls_data_buffer;
        const char *src=re->controls_data_buffer;
        
        while(src<re->controls_data_buffer+args->content_length)
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

YHS_EXTERN const char *yhs_find_control_value(yhsResponse *re,const char *control_name)
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

YHS_EXTERN size_t yhs_get_num_controls(yhsResponse *re)
{
    return re->num_controls;
}

YHS_EXTERN const char *yhs_get_control_name(yhsResponse *re,size_t index)
{
    assert(index<re->num_controls);
    
    return re->controls[index].key;
}

YHS_EXTERN const char *yhs_get_control_value(yhsResponse *re,size_t index)
{
    assert(index<re->num_controls);
    
    return re->controls[index].value;
}

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

static int path_before(const Handler *a,const Handler *b)
{
    if(a->res_path_len<b->res_path_len)
        return 1;
    else if(b->res_path_len<a->res_path_len)
        return 0;
    
    return strcmp(a->res_path,b->res_path)<0;//though actually they don't need to be in alphabetical order.
}

void yhs_add_res_path_handler(yhsServer *server,const char *res_path,yhsResPathHandlerFn handler_fn,void *context)
{
    Handler *h=(Handler *)MALLOC(sizeof *h);
    Handler *prev;
    
    assert(res_path);
    
    memset(h,0,sizeof *h);
    
    h->res_path_len=strlen(res_path);
    
    h->res_path=(char *)MALLOC(h->res_path_len+1);
    memcpy(h->res_path,res_path,h->res_path_len+1);
    
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
}

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////
