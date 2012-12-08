#define _CRT_SECURE_NO_WARNINGS

#include "yhs.h"

#ifdef WIN32

// Windows
#define _WIN32_WINNT 0x500
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <windows.h>
#include <shlwapi.h>

#endif

#ifdef __APPLE__

// Mac/iBlah
#include <unistd.h>

#endif

#include <stdlib.h>
#include <vector>
#include <algorithm>
#include <assert.h>
#include <sys/types.h>
#include <sys/stat.h>

static const int PORT=35000;
static bool g_quit=false;

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

DIR *opendir(const char *name)
{
	DIR *d=new DIR;
	memset(d,0,sizeof *d);

	char wildcard[MAX_PATH];
	PathCombineA(wildcard,name,"*");

	d->hFind=FindFirstFileA(wildcard,&d->next_fd);

	if(d->hFind==INVALID_HANDLE_VALUE)
	{
		delete d;
		d=0;
	}

	return d;
}

struct dirent *readdir(DIR *d)
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

void closedir(DIR *d)
{
	if(d->hFind!=INVALID_HANDLE_VALUE)
	{
		FindClose(d->hFind);
		d->hFind=INVALID_HANDLE_VALUE;
	}

	delete d;
}

#endif

static void dump(const void *p_a,size_t n,const char *prefix)
{
	const unsigned char *p=(const unsigned char *)p_a;

	size_t n2=n==0?1:n;

	for(size_t i=0;i<n2;i+=16)
	{
		printf("%s%08X: ",prefix,i);

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

struct MIMEType
{
	const char *ext,*type;
};

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

static int MIMETypesCompare(const void *a_a,const void *b_a)
{
	const MIMEType *a=(const MIMEType *)a_a;
	const MIMEType *b=(const MIMEType *)b_a;

	return _stricmp(a->ext,b->ext);
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

enum
{
	MAX_PATH_SIZE=1000,
};

static bool is_path_separator(char c)
{
	return c=='/'||c=='\\';
}

static const char *find_path_extension(const char *path)
{
	for(const char *e=path+strlen(path);e>=path&&!is_path_separator(*e);--e)
	{
		if(*e=='.')
			return e+1;
	}

	return 0;
}

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
				if(is_path_separator(src[e]))
					dest[dest_idx++]='/';

				for(int i=0;i<e-b;++i)
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

	dest[dest_idx++]=0;

	_strrev(dest);

	return 1;
}

static void test_normalize_path(const char *path,const char *expected)
{
	char *npath=(char *)_alloca(strlen(path)+1);
	
	int result=normalize_path(npath,path);

	if(!expected)
		assert(!result);
	else
	{
		assert(result);
		assert(strcmp(npath,expected)==0);
	}
}

static void HandleFiles(yhsRequest *re)
{
	const char *root=(char *)yhs_get_handler_context(re);

	char rel_path[MAX_PATH_SIZE];
	if(!normalize_path(rel_path,yhs_get_path_handler_relative(re)))
		return;

	char local_path[MAX_PATH_SIZE];
	if(!join_paths(local_path,root,rel_path))
		return;

	if(is_folder_path(local_path))
	{
		DIR *d=opendir(local_path);

		yhs_begin_data_response(re,"text/html");

		yhs_html_textf(re,YHS_HEF_OFF,"<html><head><title>\x1by%s\x1bn</title></head><body>",rel_path);

		const char *colour="#E0E0E0";
		const char *othcolour="#FFFFFF";

		yhs_html_textf(re,YHS_HEF_OFF,"<pre>");

		while(struct dirent *de=readdir(d))
		{
			char size[100];
			char de_local_path[MAX_PATH_SIZE];
			struct _stat64 st;

			if(de->d_name[0]=='.')
				continue;

			if(!join_paths(de_local_path,root,de->d_name))
				continue;

			if(_stat64(de_local_path,&st)!=0)
				continue;

			if(st.st_mode&_S_IFDIR)
				strcpy(size,"");
			else
			{
				if(st.st_size<1024*1024)
					sprintf(size,"%.1fKB",st.st_size/1024.);
				else if(st.st_size<1024*1024*1024)
					sprintf(size,"%.1fMB",st.st_size/1024./1024.);
				else
					sprintf(size,"%.1fGB",st.st_size/1024./1024./1024.);
			}

			yhs_html_textf(re,YHS_HEF_OFF,"%-10s<a href=\"%s\">\x1by%s\x1bn</a>\n",size,de->d_name,de->d_name);
		}

		yhs_html_textf(re,YHS_HEF_OFF,"</pre></body></html>");
	}
	else
	{
		const char *ext=find_path_extension(local_path);

		const char *mime_type=0;

		if(ext)
			mime_type=FindMIMETypeByExtension(ext);

		if(!mime_type)
			mime_type="text/plain";

		FILE *f=fopen(local_path,"rb");
		if(!f)
			return;

		yhs_begin_data_response(re,mime_type);

		int c;
		while((c=fgetc(f))!=EOF)
			yhs_data_byte(re,(unsigned char)c);

		fclose(f);
		f=0;
	}
}

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

#ifdef _MSC_VER
	_CrtSetDbgFlag(_CrtSetDbgFlag(_CRTDBG_REPORT_FLAG)|_CRTDBG_LEAK_CHECK_DF|_CRTDBG_CHECK_ALWAYS_DF);
#endif

	{
		test_normalize_path("..",0);
		test_normalize_path(".","");
		test_normalize_path("path1/path2","path1/path2");
		test_normalize_path("/path1/path2","/path1/path2");
		test_normalize_path("path1/path2/","path1/path2/");
		test_normalize_path("/path1/path2/","/path1/path2/");
		test_normalize_path("/path1/path2/..","/path1/");
		test_normalize_path("/path1/path2/../..","/");
		test_normalize_path("path1/path2/../..","");
	}

	yhs_run_unit_tests();
    
    yhsServer *server=yhs_new_server(PORT);
    
    if(!server)
    {
        fprintf(stderr,"FATAL: failed to start server.\n");
        return EXIT_FAILURE;
    }

	yhs_set_server_name(server,"Demo Server");
    
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
	yhs_add_to_toc(yhs_add_res_path_handler(server,"/files/",&HandleFiles,(void *)"C:\\tom\\emacs\\elisp_html"));

    while(!g_quit)
    {
        yhs_update(server);
        
#ifdef WIN32
        Sleep(10);
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
