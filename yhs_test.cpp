#include "yhs.h"

#ifdef WIN32

// Windows
#define _WIN32_WINNT 0x500
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <windows.h>

#endif

#ifdef __APPLE__

// Mac/iBlah
#include <unistd.h>

#endif

#include <stdlib.h>
#include <vector>

static const int PORT=35000;

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

static void HandleFolder(yhsResponse *re,void *context,yhsResPathHandlerArgs *args)
{
    (void)context,(void)args;
    
    yhs_data_response(re,"text/html");
    
    yhs_text(re,"<html><head><title>Example Folder</title></head><body><p>Handler for folder.</p></body></html>");
}

static void HandleRedir(yhsResponse *re,void *context,yhsResPathHandlerArgs *args)
{
	(void)context,(void)args;

	yhs_see_other_response(re,"/file");
}

static void HandleFile(yhsResponse *re,void *context,yhsResPathHandlerArgs *args)
{
    (void)context,(void)args;
    
    yhs_data_response(re,"text/plain");
    
    yhs_text(re,"Handler for individual file.");
}

static void HandleImage(yhsResponse *re,void *context,yhsResPathHandlerArgs *args)
{
    (void)context,(void)args;
    
    yhs_image_response(re,512,512,3);
    
    for(size_t i=0;i<262144;++i)
    {
        size_t r=(i&63),g=(i>>6)&63,b=(i>>12)&63;
        
        yhs_pixel(re,(r<<2)|(r>>4),(g<<2)|(g>>4),(b<<2)|(b>>4),255);
    }
}

static void HandleFormHTML(yhsResponse *re,void *context,yhsResPathHandlerArgs *args)
{
    (void)context,(void)args;
    
	yhs_data_response(re,"text/html");

    yhs_text(re,"<html><head><title>Some junk for testing form get/post etc.</title></head>\n");
    yhs_text(re,"\n");
    yhs_text(re,"<!-- stolen from http://www.w3.org/TR/REC-html40/interact/forms.html -->\n");
    yhs_text(re,"\n");
    yhs_text(re,"<body>\n");
    yhs_text(re,"\n");
    yhs_text(re,"<FORM action=\"status\" method=\"post\">\n");
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

static void HandleStatus(yhsResponse *re,void *context,yhsResPathHandlerArgs *args)
{
	(void)context;

    if(yhs_read_form_content(re,args))
    {
        printf("%s: %u controls:\n",__FUNCTION__,unsigned(yhs_get_num_controls(re)));
        
        for(size_t i=0;i<yhs_get_num_controls(re);++i)
        {
            printf("%u. Name: \"%s\"\n",(unsigned)i,yhs_get_control_name(re,i));
            printf("    Value:\n---8<---\n");
            printf("%s\n",yhs_get_control_value(re,i));
            printf("\n---8<---\n");
        }
    }

	yhs_see_other_response(re,"form.html");
}

struct Deferred
{
    unsigned when;
    yhsDeferredResponse dre;
};

static std::vector<Deferred> g_deferreds;
static unsigned g_now;

static void DeferImage(yhsResponse *re,void *context,yhsResPathHandlerArgs *args)
{
    (void)context,(void)args;
    
    Deferred d;
    
    d.when=g_now+int(size_t(context))*100;
    yhs_defer_response(re,&d.dre);
    
    g_deferreds.push_back(d);
}

static void DeferHTML(yhsResponse *re,void *context,yhsResPathHandlerArgs *args)
{
    (void)context,(void)args;
    
    yhs_data_response(re,"text/html");
    
    yhs_text(re,"<html><head><title>Deferred Responses</title></head><body>");
    
    yhs_text(re,"<p>1 <img src=\"1.png\"></p>");
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

#ifdef WIN32
static void WaitForKey()
{
    if(IsDebuggerPresent())
    {
        fprintf(stderr,"press enter to exit.\n");
        getchar();
    }
}
#endif

int main()
{
#ifdef WIN32
    atexit(&WaitForKey);
    
    WSADATA wd;
    if(WSAStartup(MAKEWORD(2,2),&wd)!=0)
    {
        fprintf(stderr,"FATAL: failed to initialize Windows Sockets.\n");
        return EXIT_FAILURE;
    }
#endif
    
    yhsServer *server=yhs_new_server(PORT);
    
    if(!server)
    {
        fprintf(stderr,"FATAL: failed to start server.\n");
        return EXIT_FAILURE;
    }

	yhs_set_server_name(server,"Demo Server");
    
    yhs_add_res_path_handler(server,YHS_RPF_TOC,"/folder/",&HandleFolder,0);
	yhs_add_res_path_handler(server,YHS_RPF_TOC,"/file",&HandleFile,0);
    yhs_add_res_path_handler(server,YHS_RPF_TOC,"/redir",&HandleRedir,0);
    yhs_add_res_path_handler(server,YHS_RPF_TOC,"/image.png",&HandleImage,0);
    yhs_add_res_path_handler(server,0,"/1.png",&DeferImage,(void *)1);
    yhs_add_res_path_handler(server,0,"/2.png",&DeferImage,(void *)2);
    yhs_add_res_path_handler(server,0,"/3.png",&DeferImage,(void *)3);
    yhs_add_res_path_handler(server,0,"/4.png",&DeferImage,(void *)4);
    yhs_add_res_path_handler(server,0,"/5.png",&DeferImage,(void *)5);
    yhs_add_res_path_handler(server,0,"/6.png",&DeferImage,(void *)6);
    yhs_add_res_path_handler(server,0,"/7.png",&DeferImage,(void *)7);
    yhs_add_res_path_handler(server,0,"/8.png",&DeferImage,(void *)8);
    yhs_add_res_path_handler(server,0,"/9.png",&DeferImage,(void *)9);
    yhs_add_res_path_handler(server,YHS_RPF_TOC,"/defer.html",&DeferHTML,0);
    yhs_add_res_path_handler(server,YHS_RPF_TOC,"/form.html",&HandleFormHTML,0);
    yhs_add_res_path_handler(server,0,"/status",&HandleStatus,0);
    
    for(;;)
    {
        yhs_update(server);
        
#ifdef WIN32
        Sleep(10);
#else
        usleep(10000);
#endif
        
        ++g_now;
        
        std::vector<Deferred>::iterator it=g_deferreds.begin();
        while(it!=g_deferreds.end())
        {
            if(g_now>=it->when)
            {
                yhsResponse *re=yhs_begin_deferred_response(&it->dre);
                
                yhs_image_response(re,64,64,3);
                for(int i=0;i<64*64;++i)
                    yhs_pixel(re,rand()&0xFF,rand()&0xFF,rand()&0xFF,255);
                
                yhs_end_deferred_response(re);
                
                it=g_deferreds.erase(it);
            }
            else
                ++it;
        }
    }
}
