##############################################################################################
#
#Module to create graphlet images for a host. Module uses the 'dot' utility from graphviz.
#
#
#Usage: The dotprint method creates the data structure, the dot input file and generates the
#       image.
#
#dotprint Input: IP, timestamp, flow-table, cyclical (true/false).
#       The flow-table is a dictionary of IPs, each of which is a dictionary of 4-tuples.
#       4-tuples must be in the following order: (proto, sport, dport, dstip)
#
#***Flow-table example: *************************
#
#ft = {}  <- flow table
#while 1:
#   read flow data. (ip, proto, sport, dport, dip, pkts, bytes, etc..)
#
#   if not ft.has_key(ip):
#     ft[ip] = {}
#
#   flow = (proto, sport, dport, dstip) <- 4-tuple
#   if not ft[ip].has_key(flow):
#     ft[ip][flow] = (lpkts, lbytes) <- each flow entry may have wights in tuple form, (here bytes/pkts)
#   else:
#     ft[ip][flow] = (lpkts+ft[ip][flow][0], lbytes+ft[ip][flow][1])
#
#****dotprint example: ***************************
#  for ip in ft: ## generate graphlets for all ips in ft
#      g = printGraphlet.printGraphlet(ft[ip])  ##initialize 
#      g.dotprint(ip, tsm, ft[ip], 1)      ## call dotprint for a cyclical graphlet
#
#****Output ***************************
#dot input file: ip__time
#png (this can change) graphlet: ip__time.png
##############################################################################################



import sets
import os
import random 

DIP   = 0
SPORT = 1
DPORT = 2

#PATH = sys.argv[1];

def insert_to_dir(key, dir):
    if not dir.has_key(key):
        dir[key] = {}            

def print_path(output, fr, to,h,f):
        output.write("node[height="+str(h)+",fontsize="+str(f)+"]; \""+fr+"\" \""+to+"\";\n")
        output.write("\""+fr+"\"->\""+to+"\";\n")

def print_polygon_node(output, node):
        output.write("\""+node+"\" [shape=polygon,sides=5,peripheries=3,color=blue_light];\n")

def print_topnodes(output, d, parent, paths):	
        printed = []
        l = []
        for k in d.keys():	    
	    if type(d[k]) != type({}):
		return []
            l.append((len(d[k]),k))
        l.sort()
        l.reverse()
        #print l
        for i in range(0, 3):
                if i == len(l):
                        break
                #print parent, "->", l[i][1]
		if (parent, l[i][1]) not in paths:
	                print_path(output, parent, l[i][1], 0.8, 40)
			paths.append((parent, l[i][1]))
		printed.append(l[i][1])
        return printed


def restructure(parent, tree):
        #print parent, tree
        for k in parent.keys():
                if type(parent[k]) == type({}):
                        if not tree.has_key(k):
                                tree[k] = {}
                        restructure(parent[k], tree[k])
                else:
                        tree[k] = 1

def build_Nnode_tree(Nlist):
        t = {}
        #print
        for n in Nlist:
                if not t.has_key(n[0]):
                        t[n[0]] = {}
                restructure(n[1], t[n[0]])
        return t

def print_level(output, t, printlist):
	paths = []
	if type(printlist[0][1]) != type({}):
		return []
        ppp = []
        #print "ppp"
        #print printlist
        N_nodes = [f for f in printlist if 'N' in f[0]]
        #print N_nodes
        if len(N_nodes) > 0:
                printlist  = [f for f in printlist if 'N' not in f[0]]
                tree = build_Nnode_tree(N_nodes)
                #print tree
                for k in tree.keys():
                        printlist.append((k, tree[k]))
        for k in printlist:
            #if "N" in k[0]:
            #   print_most_sig_nodes(output, d, t, tnode)
            if len(k[1]) < t:
                for child in k[1].keys():
                    #print k[0], "->", child
		    if (k[0], child) not in paths:
	                    print_path(output, k[0], child, 0.8, 40)
			    paths.append((k[0], child))
               	    ppp.append((child, k[1][child]))
	                    #print k[0], "->", child
            else:
		if not 'N' in k[0]:
	                tnode = k[0]+"::N="+str(len(k[1]))
		else:
			tnode = "N="+str(len(k[1]))
			for i in range(0,random.randint(0,10)):
				tnode = " "+tnode			
                #print k[0], "->",tnode
		if k[0] == tnode:
			tnode= tnode +" "
                print_polygon_node(output, tnode)
                print_path(output, k[0], tnode, 3, 100)
                #print k[0], "->",tnode
                #print k
		#print k
                printed  = print_topnodes(output, k[1], k[0], paths)
                #print "PRINTED", printed
                for child in k[1].keys():
                    if child not in printed:
                            ppp.append((tnode, k[1][child]))
                    else:
                            ppp.append((child, k[1][child]))
                #    print child, k[1][child]
        return ppp




        
class printGraphlet:

    def __init__(self, ft):
        self.ft = ft  ### ft is flow table director. ft[flow] = entry. flow could be 3-tuple or 4-tuple
        self.dstips = {}
        self.dports = {}
        self.sports = {}
        self.all = sets.Set()
        self.snodes = {}

                

    def build_print_glet(self, ft, cyclical):

        g = {}
        gport  = {}
        gdport = {}
        gportip = {}
        for f in ft.keys():            
            #fs = f.split()
            if len(f) != 4:
                stderr.write("Wrong flow format: Flow should be 4-tuple: proto, dstip, sport, dport\n");
                sys.exit(0)
            sport = f[1]
            dport = f[2]
            dstip = f[3]
            proto = f[0]

            insert_to_dir(proto, g)
            insert_to_dir(dstip, g[proto])
            insert_to_dir(sport, g[proto][dstip])
	    if not cyclical:
	            g[proto][dstip][sport][dport] = 1
	    else:
	    	insert_to_dir(dport, g[proto][dstip][sport])
		g[proto][dstip][sport][dport]["_"+dstip] = 1
            
            #insert_to_dir(proto, gport)
            #insert_to_dir(sport, gport[proto])
            #gport[proto][sport][dstip] = 1

            #insert_to_dir(dstip, gdport)
            #insert_to_dir(dport, gdport[dstip])
            #gdport[dstip][dport][sport] = 1

            #insert_to_dir(dport, gportip)
            #gportip[dport][dstip] = 1
            
            #if dport not in ips[ip][proto][dstip][sport]:
        return g#,gport,gdport,gportip    

                            
    def dotprint(self, DOTCOMMAND, ip, tsm, ft, cyclical, dafilename):
        PRINTTHRES = 10
        printed = {}
	random.Random(tsm)
        
        g = self.build_print_glet(ft, cyclical) #, gport, gdport, gportip = self.build_print_glet(ft)
        
        if len(g) > 0:
            #fname = dapath + "/" +ip+"__"+str(int(tsm))
            fname = dafilename;
            output = open(fname,'w')
            output.write("digraph G {\n")
            output.write("rankdir=LR;\nsize=\"20,15\";\ncenter=true;\nratio=fill;\n")
            output.write("node [fontsize=20, weight=100, color=black, style=bold];\n")
            output.write("edge [weight=100, color=black, style=bold];\n")

            clevel = g
            printlist = [(ip, g)]
            tnodes = []
            while len(printlist) > 0:
		#print prinlist
                printlist= print_level(output, PRINTTHRES, printlist)
                
	    output.write("}\n")
            output.close()
            #command = "/san/graid1/people/tkaragia/tmp/bin/dot -Tpng "+fname+" -o "+fname+".png"
            command = DOTCOMMAND + " -Tpng " + fname + " -o " + fname + ".png"
            #print command
            os.system(command)            
            
        
