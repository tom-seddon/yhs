#!/usr/bin/python
import httplib,sys,random,hashlib,argparse

g_verbose=False
g_very_verbose=False

##########################################################################
##########################################################################

def v(str):
    global g_verbose
    global g_very_verbose
    
    if g_verbose or g_very_verbose:
        sys.stderr.write(str)

##########################################################################
##########################################################################
        
def vv(str):
    global g_very_verbose
    
    if g_very_verbose:
        sys.stderr.write(str)

##########################################################################
##########################################################################

class TestFail(Exception):
    def __init__(self,
                 what,
                 got,
                 expected):
        Exception.__init__(self,
                           "test failed")

        self.what=what
        self.got=got
        self.expected=expected

    def write(self,
              f,
              prefix):
        f.write(prefix+"    What: %s\n"%self.what)
        f.write(prefix+"Expected: ``%s'' (%s)\n"%(repr(self.expected),type(self.expected)))
        f.write(prefix+"     Got: ``%s'' (%s)\n"%(repr(self.got),type(self.got)))

##########################################################################
##########################################################################

class Test:
    def check_status(self,
                     expected_status):
        if self.resp.status!=expected_status:
            raise TestFail("status",self.resp.status,expected_status)

    def check_data(self,
                   expected_data):
        got_data=self.resp.read()
        if got_data!=expected_data:
            raise TestFail("data",got_data,expected_data)
    
##########################################################################
##########################################################################

class OversizedRequest(Test):
    DESC="""Send request with overly-large GET path."""

    def setup(self):
        self.conn.putrequest("GET","/tests/nonexistent/"+8192*"X")
        self.conn.endheaders()

    def check(self):
        self.check_status(500)

##########################################################################
##########################################################################

class EchoSingleHeaderField(Test):
    DESC="""Echo single header field."""

    def setup(self):
        self.conn.putrequest("GET","/tests/echo_header_field/testfield")
        self.conn.putheader("testfield","12345")
        self.conn.endheaders()

    def check(self):
        self.check_status(200)
        self.check_data("testfield=12345\n")

class EchoContinuedHeaderField(Test):
    DESC="""Echo continued header field."""

    def setup(self):
        self.conn.putrequest("GET","/tests/echo_header_field/testfield")
        self.conn.putheader("testfield","12345","67890")
        self.conn.endheaders()

    def check(self):
        self.check_status(200)
        self.check_data("testfield=12345 67890\n")

class EchoMultipleHeaderField(Test):
    DESC="""Echo header field given multiple times."""

    def setup(self):
        self.conn.putrequest("GET","/tests/echo_header_field/testfield")
        self.conn.putheader("testfield","12345")
        self.conn.putheader("testfield","67890")
        self.conn.endheaders()

    def check(self):
        self.check_status(200)
        self.check_data("testfield=12345\ntestfield=67890\n")

##########################################################################
##########################################################################

class HashContent(Test):
    DESC="""Hash content."""

    def __init__(self):
        # a longer string would be nice, but python is just comically
        # slow.
        
        self.data=""

        for i in range(65536):
            self.data+=chr(random.randint(0,255))

        hasher=hashlib.new("sha1")
        hasher.update(self.data)
        self.hash=hasher.hexdigest().upper()

    def setup(self):
        self.conn.request("POST","/tests/hash_content",self.data)

    def check(self):
        self.check_status(200)
        self.check_data(self.hash)
        
##########################################################################
##########################################################################
        
def main(args):
    tests=[
        OversizedRequest,
        EchoSingleHeaderField,
        EchoContinuedHeaderField,
        EchoMultipleHeaderField,
        HashContent,
    ]

    statuses=[]

    host,port=(args.host.split(":")+[None])[:2]
    if port is None:
        port="80"

    port=int(port)

    strict=True

    for test in tests:
        print "%s"%test.DESC

        v("    Construct")
        obj=test()

        obj.conn=httplib.HTTPConnection(host,
                                        port,
                                        strict)

        try:
            v(" Connect")
            obj.conn.connect()

            v(" Setup")
            obj.setup()

            #obj.conn.send()

            v(" GetResponse")
            obj.resp=obj.conn.getresponse()

            v(" Check")
            obj.check()

            v("\n")
            
        except TestFail,e:
            print "    Failed."
            e.write(sys.stdout,"    ")
            statuses.append(e)
        else:
            print "    Passed."
            statuses.append(None)

        obj.conn.close()

##########################################################################
##########################################################################

if __name__=="__main__":
    parser=argparse.ArgumentParser(description="HTTP server test")

    parser.add_argument("-v",
                        "--verbose",
                        action="store_true",
                        default=False,
                        help="If specified, verbosity.")

    parser.add_argument("-V",
                        "--very-verbose",
                        action="store_true",
                        default=False,
                        help="If specified, extra verbosity. (Implies -v.)")

    parser.add_argument("host",
                        metavar="HOST",
                        nargs="?",
                        default="127.0.0.1:35000",
                        help=
                        """Host/port to connect to. (Default: %(default)s.)""")

    main(parser.parse_args())
    
