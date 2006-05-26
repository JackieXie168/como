#!/usr/bin/python
import sys
import os
import time
import sets
import math
from string import rfind
import printGraphlet

DOTCMD = sys.argv[1];
dafilename = sys.argv[2];

daily = {}
input = sys.stdin
tsm = 0
while 1:
    line = input.readline()
    if line=="":
       break
    l = line.split()
    if tsm==0: 
        tsm = float(l[0])

    lip = l[5]
    proto = int(l[2])
    if proto!=6 and proto!=17:
        continue

    lsport = l[6]
    ldstip = l[3]
    ldport = '_'+l[4]

    if not daily.has_key(lip):
	daily[lip] = {}

    f  = (str(proto), lsport, ldport, ldstip)
    daily[lip][f] = 1


for ip in daily.keys():
    g = printGraphlet.printGraphlet(daily[ip])
    g.dotprint(DOTCMD, ip, tsm, daily[ip], 0, dafilename)

