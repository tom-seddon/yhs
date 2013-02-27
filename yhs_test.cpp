#define _CRT_SECURE_NO_WARNINGS
#define _CRT_NONSTDC_NO_DEPRECATE

#include "yhs.h"

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

#ifdef WIN32

// Windows
#define _WIN32_WINNT 0x500
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <windows.h>
#include <shlwapi.h>
#include <direct.h>
#include <conio.h>

#endif

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

#ifdef __APPLE__

// Mac/iBlah
#include <unistd.h>

#endif

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

#include <stdlib.h>
#include <vector>
#include <algorithm>
#include <assert.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <time.h>

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

static const int PORT=35000;
static bool g_quit=false;

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

static void dump(const void *p_a,size_t n,const char *prefix)
{
	const unsigned char *p=(const unsigned char *)p_a;

	size_t n2=n==0?1:n;

	for(size_t i=0;i<n2;i+=16)
	{
		printf("%s%08X: ",prefix,(unsigned)i);

		for(size_t j=0;j<16;++j)
		{
			if(i+j<n)
				printf(" %02X",p[i+j]);
			else
				printf(" **");
		}

		printf("  ");

		for(size_t j=0;j<16;++j)
		{
			if(i+j<n)
				printf("%c",isprint(p[i+j])?p[i+j]:'.');
			else
				printf(" ");
		}

		printf("\n");
	}
}

// Simple YHS test.
//
// Creates server on port PORT. Visit it using a web browser. Pages:
//
// /folder/ - demonstration of folder handler
//
// /file - demonstration of file handler
//
// /redir - redirects you to /file
//
// /image.png - demonstration of image creation
//
// /defer.html - demonstration of deferred bits

static void HandleFolder(yhsRequest *re)
{
    yhs_begin_data_response(re,"text/html");
    
    yhs_text(re,"<html><head><title>Example Folder</title></head><body><p>Handler for folder.</p></body></html>");
}

static void HandleRedir(yhsRequest *re)
{
	yhs_see_other_response(re,"/file");
}

static void HandleFile(yhsRequest *re)
{
    yhs_begin_data_response(re,"text/plain");
    
    yhs_text(re,"Handler for individual file.");
}

static void HandleImage(yhsRequest *re)
{
    yhs_begin_image_response(re,512,512,3);
    
    for(size_t i=0;i<262144;++i)
    {
        size_t r=(i&63),g=(i>>6)&63,b=(i>>12)&63;
        
        yhs_pixel(re,(r<<2)|(r>>4),(g<<2)|(g>>4),(b<<2)|(b>>4),255);
    }
}

static void HandleFormHTML(yhsRequest *re)
{
	bool defer=!!yhs_get_handler_context(re);
    
	yhs_begin_data_response(re,"text/html");

	yhs_textf(re,"<html><head><title>Test form GET/POST%s</title></head>\n",defer?" (deferred)":"");
    yhs_text(re,"\n");
    yhs_text(re,"<!-- see http://www.w3.org/TR/REC-html40/interact/forms.html -->\n");
    yhs_text(re,"\n");
    yhs_text(re,"<body>\n");
    yhs_text(re,"\n");
	yhs_textf(re,"<FORM action=\"%s\" method=\"post\">\n",defer?"status_deferred":"status");
    yhs_text(re," <P>\n");
    yhs_text(re," <FIELDSET>\n");
    yhs_text(re,"  <LEGEND>Personal Information</LEGEND>\n");
    yhs_text(re,"  Last Name: <INPUT name=\"personal_lastname\" type=\"text\" tabindex=\"1\">\n");
    yhs_text(re,"  First Name: <INPUT name=\"personal_firstname\" type=\"text\" tabindex=\"2\">\n");
    yhs_text(re,"  Address: <INPUT name=\"personal_address\" type=\"text\" tabindex=\"3\">\n");
    yhs_text(re,"  ...more personal information...\n");
    yhs_text(re," </FIELDSET>\n");
    yhs_text(re," <FIELDSET>\n");
    yhs_text(re,"  <LEGEND>Medical History</LEGEND>\n");
    yhs_text(re,"  <INPUT name=\"history_illness\" \n");
    yhs_text(re,"         type=\"checkbox\" \n");
    yhs_text(re,"         value=\"Smallpox\" tabindex=\"20\"> Smallpox\n");
    yhs_text(re,"  <INPUT name=\"history_illness\" \n");
    yhs_text(re,"         type=\"checkbox\" \n");
    yhs_text(re,"         value=\"Mumps\" tabindex=\"21\"> Mumps\n");
    yhs_text(re,"  <INPUT name=\"history_illness\" \n");
    yhs_text(re,"         type=\"checkbox\" \n");
    yhs_text(re,"         value=\"Dizziness\" tabindex=\"22\"> Dizziness\n");
    yhs_text(re,"  <INPUT name=\"history_illness\" \n");
    yhs_text(re,"         type=\"checkbox\" \n");
    yhs_text(re,"         value=\"Sneezing\" tabindex=\"23\"> Sneezing\n");
    yhs_text(re,"  ...more medical history...\n");
    yhs_text(re," </FIELDSET>\n");
    yhs_text(re," <FIELDSET>\n");
    yhs_text(re,"  <LEGEND>Current Medication</LEGEND>\n");
    yhs_text(re,"  Are you currently taking any medication? \n");
    yhs_text(re,"  <INPUT name=\"medication_now\" \n");
    yhs_text(re,"         type=\"radio\" \n");
    yhs_text(re,"         value=\"Yes\" tabindex=\"35\">Yes\n");
    yhs_text(re,"  <INPUT name=\"medication_now\" \n");
    yhs_text(re,"         type=\"radio\" \n");
    yhs_text(re,"         value=\"No\" tabindex=\"35\">No\n");
    yhs_text(re,"\n");
    yhs_text(re,"  If you are currently taking medication, please indicate\n");
    yhs_text(re,"  it in the space below:\n");
    yhs_text(re,"  <TEXTAREA name=\"current_medication\" \n");
    yhs_text(re,"            rows=\"20\" cols=\"50\"\n");
    yhs_text(re,"            tabindex=\"40\">\n");
    yhs_text(re,"  </TEXTAREA>\n");
    yhs_text(re," </FIELDSET>\n");
    yhs_text(re,"\n");
    yhs_text(re,"<INPUT type=\"submit\" name=\"submit\">\n");
    yhs_text(re,"\n");
    yhs_text(re,"</FORM>\n");
    yhs_text(re,"\n");
    yhs_text(re,"\n");
    yhs_text(re,"</body>\n");
    yhs_text(re,"</html>\n");
}

static void HandleStatus(yhsRequest *re)
{
    if(yhs_read_form_content(re))
    {
        printf("%s: %u controls:\n",__FUNCTION__,unsigned(yhs_get_num_controls(re)));
        
        for(size_t i=0;i<yhs_get_num_controls(re);++i)
        {
            printf("%u. Name: \"%s\"\n",(unsigned)i,yhs_get_control_name(re,i));
            printf("    Value:\n");

			const char *value=yhs_get_control_value(re,i);
			dump(value,strlen(value),"        ");
			
// 			---8<---\n");
//             printf("%s\n",yhs_get_control_value(re,i));
//             printf("\n---8<---\n");
        }
    }

	yhs_see_other_response(re,"form.html");
}

struct Deferred
{
    unsigned when;
    yhsRequest *dre;
	void (*fn)(yhsRequest *);

	Deferred(unsigned when_a,yhsRequest *re,void (*fn_a)(yhsRequest *)):
	when(when_a),
	dre(0),
	fn(fn_a)
	{
		yhs_defer_response(re,&this->dre);
	}
};

static yhsRequest *g_deferred_chain;
static std::vector<Deferred> g_deferreds;
static unsigned g_now;

static void DeferredImage(yhsRequest *re)
{
	yhs_begin_image_response(re,64,64,3);
	for(int i=0;i<64*64;++i)
		yhs_pixel(re,rand()&0xFF,rand()&0xFF,rand()&0xFF,255);
}

static void DeferImage(yhsRequest *re)
{
	int delay=int(size_t(yhs_get_handler_context(re)));

	g_deferreds.push_back(Deferred(g_now+delay*100,re,&DeferredImage));
}

static void DeferImageChain(yhsRequest *re)
{
	yhs_defer_response(re,&g_deferred_chain);
}

static void DeferHTML(yhsRequest *re)
{
    yhs_begin_data_response(re,"text/html");
    
    yhs_text(re,"<html><head><title>Deferred Responses</title></head><body>");
    
	yhs_text(re,"<p>c1 <img src=\"chain1.png\"></p>");
	yhs_text(re,"<p>c2 <img src=\"chain2.png\"></p>");
	yhs_text(re,"<p>c3 <img src=\"chain3.png\"></p>");
    yhs_text(re,"<p>c4 <img src=\"chain4.png\"></p>");
    yhs_text(re,"<p>2 <img src=\"2.png\"></p>");
    yhs_text(re,"<p>3 <img src=\"3.png\"></p>");
    yhs_text(re,"<p>4 <img src=\"4.png\"></p>");
    yhs_text(re,"<p>5 <img src=\"5.png\"></p>");
    yhs_text(re,"<p>6 <img src=\"6.png\"></p>");
    yhs_text(re,"<p>7 <img src=\"7.png\"></p>");
    yhs_text(re,"<p>8 <img src=\"8.png\"></p>");
    yhs_text(re,"<p>9 <img src=\"9.png\"></p>");
    
    yhs_text(re,"</body></html>");
}

static void HandleTerminate(yhsRequest *re)
{
	(void)re;

	g_quit=true;
}

static std::vector<unsigned char> g_payload;

static void HandleWSEcho(yhsRequest *re)
{
	size_t num_bytes=0;
	clock_t begin_clock=clock();

	yhs_accept_websocket(re,0);

	while(yhs_is_websocket_open(re))
	{
		int is_text;
		if(yhs_begin_recv_websocket_frame(re,&is_text))
		{
			g_payload.clear();

			for(;;)
			{
				char buf[4096];

				size_t n;
				if(!yhs_recv_websocket_data(re,buf,sizeof buf,&n))
					return;

				if(n==0)
					break;
				
				g_payload.insert(g_payload.end(),buf,buf+n);
			}

			//printf("got %u bytes.\n",(unsigned)payload.size());

			yhs_end_recv_websocket_frame(re);

			yhs_begin_send_websocket_frame(re,is_text);

			if(!g_payload.empty())
				yhs_data(re,&g_payload[0],g_payload.size());

			yhs_end_send_websocket_frame(re);

			num_bytes+=g_payload.size();
		}
	}

	clock_t end_clock=clock();

	printf("%s: %u bytes in %.2f sec\n",__FUNCTION__,(unsigned)num_bytes,(end_clock-begin_clock)/(double)CLOCKS_PER_SEC);
}

static void HandleTestsEchoHeaderField(yhsRequest *re)
{
	yhs_begin_data_response(re,"text/plain");
	
	const char *field=yhs_get_path_handler_relative(re);
	
	const char *value=0;
	while((value=yhs_find_header_field(re,field,value))!=0)
		yhs_textf(re,"%s=%s\n",field,value);
}

static void HandleTestsHashContent(yhsRequest *re)
{
	const char *type;
	int length;
	if(yhs_get_content_details(re,&type,&length))
	{
		//printf("type=%s length=%d\n",type,length);
		
		//printf("reading...\n");
		std::vector<char> data(length);
		if(yhs_get_content(re,length,&data[0]))
		{
			//printf("done.\n");
			
			unsigned char sha1[20];
			yhs_sha1(sha1,&data[0],data.size());
			
			yhs_begin_data_response(re,"text/plain");
			
			for(int i=0;i<20;++i)
				yhs_textf(re,"%02X",sha1[i]);
		}
	}
}

static void Log(yhsLogCategory cat,const char *str,void *context)
{
	(void)context;

	switch(cat)
	{
	case YHS_LOG_ERROR:
		fputs(str,stderr);
		break;

	case YHS_LOG_INFO:
		fputs(str,stdout);
		break;

	case YHS_LOG_DEBUG:
		break;
	}

#ifdef _WIN32
	OutputDebugStringA(str);
#endif//_WIN32
}

#ifdef WIN32

static void WaitForKey()
{
	if(IsDebuggerPresent())
	{
		if(!g_quit)
		{
			fprintf(stderr,"press enter to exit.\n");
			getchar();
		}
	}
}
#endif

int main(int argc,char *argv[])
{
#ifdef WIN32
    atexit(&WaitForKey);

    WSADATA wd;
    if(WSAStartup(MAKEWORD(2,2),&wd)!=0)
    {
        fprintf(stderr,"FATAL: failed to initialize Windows Sockets.\n");
        return EXIT_FAILURE;
    }

	printf("Press Esc to finish.\n");
#endif

#ifdef _MSC_VER
	_CrtSetDbgFlag(_CrtSetDbgFlag(_CRTDBG_REPORT_FLAG)|_CRTDBG_LEAK_CHECK_DF);
//	_CrtSetDbgFlag(_CrtSetDbgFlag(_CRTDBG_REPORT_FLAG)|_CRTDBG_CHECK_ALWAYS_DF);
#endif

	yhs_run_unit_tests();
	
	{
		char cwd[1000];
		getcwd(cwd,sizeof cwd);
		printf("Working folder: \"%s\".\n",cwd);
	}
    
    yhsServer *server=yhs_new_server(PORT);
    
    if(!server)
    {
        fprintf(stderr,"FATAL: failed to start server.\n");
        return EXIT_FAILURE;
    }

	yhs_set_server_name(server,"Demo Server");

	yhs_set_server_log_callback(server,&Log,0);
	yhs_set_server_log_enabled(server,YHS_LOG_INFO,1);
	yhs_set_server_log_enabled(server,YHS_LOG_DEBUG,1);
    
    yhs_add_to_toc(yhs_add_res_path_handler(server,"/folder/",&HandleFolder,0));
	yhs_add_to_toc(yhs_add_res_path_handler(server,"/file",&HandleFile,0));
    yhs_add_to_toc(yhs_add_res_path_handler(server,"/redir",&HandleRedir,0));
    yhs_add_to_toc(yhs_add_res_path_handler(server,"/image.png",&HandleImage,0));
    yhs_add_res_path_handler(server,"/1.png",&DeferImage,(void *)1);
    yhs_add_res_path_handler(server,"/2.png",&DeferImage,(void *)2);
    yhs_add_res_path_handler(server,"/3.png",&DeferImage,(void *)3);
    yhs_add_res_path_handler(server,"/4.png",&DeferImage,(void *)4);
    yhs_add_res_path_handler(server,"/5.png",&DeferImage,(void *)5);
    yhs_add_res_path_handler(server,"/6.png",&DeferImage,(void *)6);
    yhs_add_res_path_handler(server,"/7.png",&DeferImage,(void *)7);
    yhs_add_res_path_handler(server,"/8.png",&DeferImage,(void *)8);
    yhs_add_res_path_handler(server,"/9.png",&DeferImage,(void *)9);
	yhs_add_res_path_handler(server,"/chain1.png",&DeferImageChain,0);
	yhs_add_res_path_handler(server,"/chain2.png",&DeferImageChain,0);
	yhs_add_res_path_handler(server,"/chain3.png",&DeferImageChain,0);
	yhs_add_res_path_handler(server,"/chain4.png",&DeferImageChain,0);
    yhs_add_to_toc(yhs_add_res_path_handler(server,"/defer.html",&DeferHTML,0));
	yhs_add_to_toc(yhs_add_res_path_handler(server,"/form.html",&HandleFormHTML,(void *)0));
    yhs_set_handler_description("form with deferred response",yhs_add_to_toc(yhs_add_res_path_handler(server,"/form.html",&HandleFormHTML,(void *)1)));
    yhs_set_valid_methods(YHS_METHOD_POST,yhs_add_res_path_handler(server,"/status",&HandleStatus,0));
	yhs_add_to_toc(yhs_add_res_path_handler(server,"/terminate",&HandleTerminate,0));
	yhs_set_valid_methods(YHS_METHOD_WEBSOCKET,yhs_add_res_path_handler(server,"/ws_echo/",&HandleWSEcho,0));
	yhs_add_res_path_handler(server,"/tests/echo_header_field/",&HandleTestsEchoHeaderField,0);
	yhs_set_valid_methods(YHS_METHOD_POST,yhs_add_res_path_handler(server,"/tests/hash_content",&HandleTestsHashContent,0));

	if(argc>1)
		yhs_add_to_toc(yhs_add_res_path_handler(server,"/files/",&yhs_file_server_handler,argv[1]));

    while(!g_quit)
    {
        yhs_update(server);
        
#ifdef WIN32
        Sleep(10);

		if(_kbhit())
		{
			if(_getch()==27)
			{
				g_quit=true;
				break;
			}
		}

#else
        usleep(10000);
#endif
        
        ++g_now;

		int num_res=0;

		yhsRequest **re_ptr=&g_deferred_chain;
		while(*re_ptr)
		{
			yhs_begin_image_response(*re_ptr,256,256,3);

			for(int y=0;y<256;++y)
			{
				for(int x=0;x<256;++x)
				{
					yhs_pixel(*re_ptr,x,y,x^y,255);
				}
			}

			yhs_end_deferred_response(re_ptr);

			++num_res;
		}

		if(num_res>0)
			printf("%d deferred responses in chain.\n",num_res);
        
        std::vector<Deferred>::iterator it=g_deferreds.begin();
        while(it!=g_deferreds.end())
        {
            if(g_now>=it->when)
            {
				(*it->fn)(it->dre);

                yhs_end_deferred_response(&it->dre);
                
                it=g_deferreds.erase(it);
            }
            else
                ++it;
        }
    }

	yhs_delete_server(server);
	server=0;

// #ifdef _MSC_VER
// 	_CrtDumpMemoryLeaks();
// #endif

	return EXIT_SUCCESS;
}
