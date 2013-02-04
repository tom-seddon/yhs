#!/usr/bin/python
import httplib,sys,random,hashlib

##########################################################################
##########################################################################

host="localhost"
port=35000
strict=True

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
        
def main():
    tests=[
        OversizedRequest,
        EchoSingleHeaderField,
        EchoContinuedHeaderField,
        EchoMultipleHeaderField,
        HashContent,
    ]

    statuses=[]

    for test in tests:
        print "%s..."%test.DESC
        
        obj=test()

        obj.conn=httplib.HTTPConnection(host,
                                        port,
                                        strict)

        try:
            obj.conn.connect()

            obj.setup()

            #obj.conn.send()

            obj.resp=obj.conn.getresponse()

            obj.check()
            
        except TestFail,e:
            print "    Failed."
            statuses.append(e)
        else:
            print "    Passed."
            statuses.append(None)

        obj.conn.close()

##########################################################################
##########################################################################

if __name__=="__main__":
    main()
    
