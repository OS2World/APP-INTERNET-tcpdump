tcpdump 3.4 (with SMB patches) ported to OS/2

original archive:
ftp://ftp.ee.lbl.gov/tcpdump.tar.Z
tcpdump@ee.lbl.gov

What is it?

tcpdump is a tool for network monitoring and data acquisition, supporting
promiscuous mode, ethernet, SLIP, PPP and loopback. Captured packets can be
analyzed on-the-fly or dumped to file.

Requirements

 * OS/2 Warp (tested with 3.0 and 4.0, various fixpack levels)
 * TCP/IP (tested with 4.0 and 4.1)
 * HPFS (or long filename support, at least for source files)
 * IpSpy, look for ipspy140.zip on leo (www.leo.org) or
   hobbes (ftp-os2.nmsu.edu)

Installation

Follow the instructions provided by IpSpy's README and copy the tcpdump
executable somewhere to your %PATH%.

Improvements over previous ports

 * PPP works now, added some protocol analyzation stuff to tcpdump;
   however, filtering of a PPP link does not work
 * dumping and reading to capture files fixed
 * some code cleanups

Compiling

Modifications required for EMX and/or OS/2 only are #defined with __EMX__,
some functional enhancements where added to the PPP analyzer (print-ppp.c).
The port of the libpcap 0.4 library and Holger Veit's rpcdev.zip are
required to recompile tcpdump, these archives are available from
leo (www.leo.org) or hobbes (ftp-os2.nmsu.edu) as lpcap04a.zip and
rpcdev.zip, respectively.
The SMB patches supplied by Andrew.Tridgell@anu.edu.au have been included.

Ported by:
Peter Meerwald
pmeerw@bgnet.bgsu.edu
seawood@very.priv.at
