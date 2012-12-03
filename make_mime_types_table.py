#!/usr/bin/python

import sys

# a suitable mime.types is available from, e.g., http://svn.apache.org/repos/asf/httpd/httpd/branches/2.0.x/docs/conf/mime.types

f=open("mime.types","rb")
lines=[x.strip() for x in f.readlines()]
f.close()
del f

types=[]
counts={}

for line in lines:
    if line.startswith("#"):
        continue

    parts=line.split()

    for ext in parts[1:]:
        types.append((ext,parts[0]))
        counts[ext]=counts.get(ext,0)+1

types.sort(lambda x,y:cmp(x[0],y[0]))

col=0

print
print
print

for type in types:
    s="{\"%s\",\"%s\"},"%(type[0],type[1])

    if col+len(s)>120:
        sys.stdout.write("\n")
        col=0

    sys.stdout.write(s)
    col+=len(s)

print
print
print
