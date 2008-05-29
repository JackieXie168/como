# $Id$
# This is a sample configuration file for CoMo.
# Blank lines are ignored.
# Syntax for comments allows both single line comment
# using the # character and multi line comment using
# /* and */ as delimiters.
# Long lines can be split with a \ at the end of the line.

# Directory where the output data of all modules reside.
# Default: @DEFAULT_DBDIR@

#db-path	"/where/to/store/data"

# Directory where the modules reside.
# Default: @DEFAULT_LIBDIR@

#librarydir	"/where/are/modules"

# Path to como-storage

storage-path "@CMAKE_INSTALL_PREFIX@@INST_BINDIR@/como-storage"


# File in MRT format (see draft-ietf-grow-mrt-03.txt) that
# gives the IP address ranges announced by each autonomous
# system (AS) [eg a global routing table]. See the RIS
# project for one source of such files:
#       http://www.ripe.net/ris/rawdata.html
# NB: AS 65535 is predefined to be RFC1918 address space
# (ie 10/8, 172.16/12, 192.168/16) and if no file is
# specified that will be all that is known about.

#asnfile = "bview.20060901.0000.gz"

# Memory allocated to the CAPTURE process to maintain the
# state used by all modules. The more modules, the more memory
# is needed. KB, MB and GB suffixes understood.
# Default: 64MB

#memsize	64MB

# TCP port number the QUERY process uses to accept new 
# requests from users.
# Default: 44444

#query-port	44444

# Node information. The following information is reported 
# by the node when it receives a ?status query. 

#name		"CoMo Node"
#location	"Unknown" 
#type		"Unknown"
#comment	"None"

# Virtual nodes. It is possible to define virtual nodes 
# that run the same set of modules of the main node but 
# on a subset of traffic. The virtual nodes would reply 
# to queries on a dedicated port number. For the syntax
# of the filter expression see the description of the
# module filter below.
# Modules on virtual nodes always run on-demand, so a
# source module must be specified.

#virtual-node	"Virtual Node"
#  location	"Unknown"
#  type		"Unknown"
#  query-port	55555
#  filter	"port 80"
#  source-module "trace"
#end

# Sniffer(s) to be used
# The syntax is: 
# sniffer <sniffer_type> <device/file> [<arguments>] 
# Available sniffers are:

# bpf		- Captures live from a device using bpf.
#sniffer	"bpf" "xl0"

# pcap		- Reads packets from a trace file in tcpdump format.
#sniffer	"pcap" "/path/to/trace"

# libpcap	- Captures live from a device using libpcap.
#sniffer	"libpcap" "eth0" "snaplen=112 promisc=1 timeout=1"

# dag		- Captures live from a DAG card.
#sniffer	"dag" "/dev/dag0" "slen=1536 varlen"

# erf		- Reads packets from a trace file in erf format.
#sniffer	"erf" "/path/to/trace"

# flowtools	- Reads packets from files collected with flow-tools.
#sniffer	"flowtools" "/path/to/trace/*" "iface=57 sampling=1000 stream"

# netflow	- Receives NetFlow datagrams.
#sniffer	"netflow" "10.0.0.2" "port=9991 compact"

# sflow		- Receives SFlow datagrams.
#sniffer	"sflow" "10.0.0.1" "port=6343 flow_type_tag=HEADER"

# radio		- Captures live from a wifi device.
#sniffer	"radio" "wlan0" "monitor=hostap"

# como		- Receives packet from another CoMo node.
#sniffer	"como" "http://como:44444/?module=trace&format=como&time=-5m:0"

# NOTE: some of them may not be present in your system.

sniffer		"pcap" "@EXAMPLE_TRACE@"

# Live sniffers synchronization threshold.
# It specifies the threshold used by CoMo to synchronize multiple live
# sniffers.
# The unit is microseconds.
# Default: 10000

#live-threshold	10000

# Set the maximum size of each individual file in the
# stream for each module. Any denominator (KB,MB,GB) can be
# used, however filesize must be less than 1GB.
# Default: 128MB

#filesize	128MB

# Modules. 
# This is an example with all keywords currently implemented. 
#
# module "example"
#   description	"Config sample"	# description (default: <empty>)
#   source	"example"	# name of module shared object, e.g. 'example'
#                               #   means example.so (and example.dll if
#                               #   it exists. default: example)
#   output	"example"	# output file (default: example)
#   filter      "tcp"		# select packets of interest (default: ALL)
#   streamsize	256MB		# max output file size (default: 256MB)
#   hashsize	1		# estimated concurrent entries (default: 1)
#   memsize	1024		# private memory in bytes (default: 0)
#   streamsize  10GB		# stream size on disk (default: 256MB)
#   args	"name" = "value"# arguments to be passed to the module. 
#   args-file	"path/to/file"	# specify a file from where to read arguments.
#   running	"on-demand"	# specify running mode (default: normal)
#   shed-method "pkt"           # specify the load shedding method
#                               #   (default: pkt, options: pkt/flow)
# end

#
# Syntax of the filter for a module:
#
# The following expressions can be combined with
# "not", "and", "or" keywords and parenthesis:
#
# - protocol:
#       ip/tcp/udp/icmp
# - ip address and netmask:
#       direction xxx.xxx.xxx.xxx (only dots and numbers: host IP)
#       direction xxx.xxx.xxx.xxx/yy (dots and numbers/CIDR notation)
#       direction asn xxxxx (address announced by an autonomous system)
#       where direction must be one of
#           src   the source address matches the value/range
#           dst   the destination address matches the value/range
#           addr  either source or destination matches
#           host  synonym for addr
# - port: 
#       sport/dport xxxxx (just 1 port)
#       sport/dport xxxxx:yyyyy (a set of ports)
# - interfaces: 
#       input/output xxxxx (it only works with NetFlow data)
# - from_ds / to_ds:
#       IEEE 802.11 packets coming from or going to access point
#
# The "all" keyword can also be used to specify an all-pass filter.
#
# Examples:
#
#   filter  "all"
#   filter  "ip"
#   filter  "tcp"
#   filter  "src 192.168.1.0/24 and dst 192.168.1.1"
#   filter  "tcp and src 10.213.54.6 and sport 5000:6000"
#   filter  "udp and (not(sport 21) or src 64.32.234.9/31)"
#   filter  "input 53 and udp"
#   filter  "src asn 2529 or addr asn 65535" 
#

#
# The traffic module computes the number of captured packets and bytes
#
# Arguments:
# - interval:	the measurement interval (secs)
#		syntax: interval=<value>
#		<value> = integer
#		default: 1
#
# - interface:	the NetFlow input/output interface of the monitored link
#		syntax: interface=<index>
#		<integer> = integer
#		default: unused

module "traffic"
  source        "trafficCC"             # implemented by trafficCC.so
  description	"Packet/Bytes counter"
  args		"interval" = "1"
# args		"interface=1"
end

module "flowcount"
    source "flowcountCC"
    description "Flow counter"
    # aggregate flows using the 5-tuple
    args "flowdef" = "src_ip|dst_ip|proto|src_port|dst_port"
end

module "protocol"
    source "protocolCC"
    description "Protocol breakdown"
end

module "topaddr"
    source "topaddrCC"
    description "Popular destination IP Addresses"
    args "use-dst" = "1"
    on-demand
end

#module "tophwaddr"
#    source "tophwaddrCC"
#    description "Popular destination HW Addresses"
#    args "use-dst"
#end

module "topports"
    source      "topportsCC"
    description "Top destination port numbers in bytes"
    args        "interval" = "5", "topn" = "10"
end

module "trace"
    source      "traceCC"
    description "Packet trace"
    streamsize  1GB
end

#module "trafficCCS"
#    source "trafficCCS"
#end

module "tuple"
    source "tupleCC"
end

module "apps"
    args "classes" = "web=tcp 80,tcp 443
                      dns=udp 53,tcp 53"
end


# The ethtypes module computes the number of packets and bytes divided by
# ethertype. Each individual ethertype has to be specified in the
# configuration. The packets have an ethertype which is not declared in the
# configuration are counted into the "Other" (0x0000) ethertype.
#
# Arguments:
# - interval:	the measurement interval (secs)
#		syntax: interval=<value>
#		<value> = integer
#		default: 1
#
# - ethtype:	definition of an ethtype
#		syntax: ethtype <name>=<value>
#		<name> = any printable charactes
#		<value> = integer in base 10 or 16 (0x prefix)
#		default: IP,IPv6,ARP
/*
module "ethtypes"
  source "ethtypesCC"
  description	"Ethertypes breakdown"
  args		"interval" = "60"
  args		"ethtypes" = "IP=0x0800,
                              IPv6=0x86DD,
                              ARP=0x0806,
                              RARP=0x8035,
                              AppleTalk=0x809b,
                              AppleTalk ARP=0x80f3,
                              Novell IPX=0x8137,
                              Novell=0x8138,
                              MPLS unicast=0x8847,
                              MPLS multicast=0x8848,
                              PPPoE Discovery Stage=0x8863,
                              PPPoE Session Stage=0x8864,
                              ATA over Ethernet=0x88A2,
                              EAP over LAN (IEEE 802.1X)=0x888E"
end  
*/
