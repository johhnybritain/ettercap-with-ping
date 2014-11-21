# If you don't like the prefix '/usr' you can override it like this:
# rpm -ba|--rebuild --define 'prefix /usr/local'
%{?!prefix:%define prefix %{prefixdef}}

Name:		lft
Version:	3.2
Release:	1
Vendor:		VOSTROM
Packager:	Victor Oppleman <lft@oppleman.com>
URL:		http://pwhois.org/lft/
Source:		%{name}-%{version}.tar.gz
Group:		Applications/Internet
License:	VOSTROM Public License
Provides:	lft whob
Requires:	libpcap
BuildRoot:	%{_tmppath}/root-%{name}-%{version}
Prefix:		%{_prefix}
Summary:	Alternative traceroute and whois tools for network (reverse) engineers

BuildRequires: libpcap
Obsoletes: fft

%description
LFT, short for Layer Four Traceroute, is a sort of 'traceroute' that
often works much faster (than the commonly-used Van Jacobson method) and
goes through many configurations of packet-filter based firewalls. LFT is the
all-in-one traceroute tool because it can use many different trace methods
and protocols such as ICMP, TCP, and UDP, as well as the RFC-1393 trace. More
importantly, LFT implements numerous other features including AS number
lookups based on global table prefix (not just the RIR), loose source routing, 
netblock name lookups, et al.  Also inlcudes a nifty whois client named 'whob'.

%prep
%setup

%build
%configure
%{__make} %{?_smp_mflags}

%install
%{__rm} -rf %{buildroot}
%makeinstall DESTDIR="%{buildroot}%{_bindir}" MANDIR="%{buildroot}%{_mandir}/man8"

%clean
%{__rm} -rf %{buildroot}

%files
%defattr(-, root, root, 0755)
%{_mandir}/man8/*
%doc CHANGELOG COPYING README TODO

%attr(4755, root, root) %{_bindir}/lft
%attr(0755, root, root) %{_bindir}/whob

%changelog
* Mon Aug 22 2005 Victor Oppleman <lft@oppleman.com>
- Added -z option to pseudo-randomize source port
- Added behavior to automatically select the most appropriate interface
  based on routing (this was on the most wanted list)
- Improved OpenBSD compatibility (IP length nonzero)
- OpenBSD is now detected by autoconf (for configuring the above)
- Darwin is now detected by autoconf and its definition disables
  some BSD features to make it compatible with MacOS X and Darwin
- LFT now indicates it has reached the target by printing a 'T'
  character in the status display (if status is enabled)
- Cleanups were made to the verbose output levels (-VVV)
- Significantly revamped whois framework makes it easy to include
  whois functionality into other programs
- Added -C and -R and -r options to force alternate ASN sources:
    - (r)IPE RIS 
    - (C)ymru 
    - (R)ADB 
- Default ASN source (-A) is now Prefix WhoIs (see pwhois.org)
- LFT now queries for ASNs in bulk format after completing
  a trace if pwhois (default), RIPE NCC RIS, or Cymru is selected
- Added dst/src port autoselection based on user-supplied hostname
- Vastly improved standalone whois client "whob" see whob.8 (whob manpage)
- Makefile now installs 'whob' no-frills whois client (try ./whob)
- "Smart" mode is now referred to as "Adaptive" mode (-E)

* Fri Nov 26 2004 Victor Oppleman <lft@oppleman.com>
- Cleaned up various files, updated to support LFT 2.3

* Sun Apr 20 2003 Nils McCarthy <nils@shkoo.com>
- Incorporated changes from Dag Wieers <dag@wieers.com> cleaning up
- a lot of the build process.

* Thu Mar 06 2003 Nils McCarthy <nils@shkoo.com>
- revised to work with autoconf

* Mon Oct 28 2002 Florin Andrei <florin@sgi.com>
- first version
- v2.0-1

