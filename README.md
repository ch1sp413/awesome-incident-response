# Awesome Incident Response

A curated list of tools, services, and resources for Security Operations and Incident Response practitioners. Each entry includes a brief synopsis to help you quickly identify its purpose.

## Table of Contents

- [Online Reputation Tools](#online-reputation-tools)
- [Online Multi-Purpose Tools](#online-multi-purpose-tools)
- [Online Anti-Spam](#online-anti-spam)
- [Online Sandboxing](#online-sandboxing)
- [Not Distribute](#not-distribute)
- [Malware Analysis](#malware-analysis)
  - [Ransomware](#ransomware)
  - [Rootkits](#rootkits)
- [TOR](#tor)
- [Cyber Threat Intelligence (CTI)](#cyber-threat-intelligence-cti)
- [CERTs](#certs)
- [Capture The Flag (CTF)](#ctfs)
- [IDS/IPS Tools](#idsips-tools)
- [Incident Response Distros](#incident-response-distros)
- [Tracker Services](#tracker-services)
- [Real-Time Response](#real-time-response)

---

## Online Reputation Tools

- [Spamhaus](https://www.spamhaus.org/) - Provides anti-spam databases and DNSBLs to identify and block spam sources.
- [URLVoid](https://www.urlvoid.com/) - Checks URLs against multiple reputation engines to identify malicious or suspicious websites.
- [URIBL](https://admin.uribl.com/) - Domain and URL reputation check against known spam and phishing sources.
- [MultiRBL](http://multirbl.valli.org/) - Aggregates multiple DNS-based blacklists (RBLs) for email and IP reputation checks.
- [Dan.me.uk](https://www.dan.me.uk/) - Offers tools and resources related to network security, blocklists, and TOR exit node information.

## Online Multi-Purpose Tools

- [Robtex](https://www.robtex.com/) - Multi-purpose DNS, IP, and routing information lookup.
- [DNSDumpster](https://dnsdumpster.com/) - Performs DNS reconnaissance and creates domain mapping data.
- [Who.is](https://who.is/) - WHOIS lookup for domain registration details.
- [IPVoid](https://www.ipvoid.com/) - IP reputation checker and blacklist lookup tool.
- [Talos Intelligence](https://talosintelligence.com/) - Cisco’s intelligence platform for threat intelligence and reputation data.
- [IPInfo.io](https://ipinfo.io/) - Geolocation and WHOIS data for IP addresses.
- [BGP.he.net](https://bgp.he.net/) - BGP routing data and IP prefix lookup service by Hurricane Electric.
- [Hosts-file.net](https://hosts-file.net/) - Repository of host and domain-based blocklists for malicious content.
- [RiskIQ Community](https://community.riskiq.com/) - Threat intelligence and attack surface monitoring platform.
- [ThreatMiner](https://www.threatminer.org/) - Research platform for threat intelligence, indicators, and malware analysis.
- [ANY.RUN](https://app.any.run/) - Interactive online malware sandbox for dynamic analysis.
- [Nibbler](https://nibbler.silktide.com/) - Website quality and performance testing tool.
- [SSL Labs](https://www.ssllabs.com/ssltest/) - SSL/TLS configuration analyzer by Qualys.
- [ThrowAwayMail](https://www.throwawaymail.com/) - Temporary email addresses for anonymous testing.
- [JavaTester](https://javatester.org/javascript.html) - Tests and validates JavaScript and browser capabilities.
- [GeoPeeker](https://geopeeker.com/) - Website preview from multiple global locations.
- [Browserling](https://www.browserling.com/) - Cross-browser testing service in real-time.
- [MAC Vendors Lookup](https://macvendors.com/) - Identifies vendor details from a MAC address.
- [Punycoder](https://www.punycoder.com/) - Convert internationalized domain names (IDNs) to punycode and vice versa.
- [CentralOps](https://centralops.net/co/) - Network utilities (WHOIS, traceroute, DNS lookups) in a web interface.
- [DNSTwister](https://dnstwister.report/) - Domain permutation engine to detect phishing or typosquatting domains.
- [crt.sh](https://crt.sh/) - Certificate Transparency log search engine for SSL certificates.
- [Beautifier.io](https://beautifier.io/) - Formats and beautifies source code (HTML, JS, CSS, JSON).
- [CyberChef (GCHQ)](https://gchq.github.io/CyberChef/) - All-in-one web tool for encoding/decoding, encryption/decryption, and data manipulation.
- [Base64 Decode](https://www.base64decode.org/) - Base64 encoding/decoding utility.
- [Synalyze It!](https://www.synalysis.net/) - Binary file analysis and reverse engineering platform.
- [Microsoft Update Catalog](https://www.catalog.update.microsoft.com/Home.aspx) - Official Microsoft updates and patches repository.
- [Openwall](https://www.openwall.com/) - Security hardening, password auditing tools, and related resources.
- [MiTeC System Information](http://www.mitec.cz/ssv.html) - Windows system analysis and forensics tools.
- [Have I Been Pwned?](https://haveibeenpwned.com/) - Checks if email addresses have appeared in known data breaches.
- [PrivateBin](https://privatebin.net/) - Encrypted pastebin service for secure information sharing.
- [Web Forensics Tool (foolmoon)](http://www.foolmoon.net/security/wft/index.html) - Basic web content analysis tool.
- [OpenSOC](https://opensoc.github.io/) - Platform for security event analysis and real-time threat detection (educational resources).
- [CIDR Calculator](https://www.ipaddressguide.com/cidr) - Tool for calculating IP subnets and CIDR notations.
- [AIDE](https://aide.github.io/) - Host-based intrusion detection system that checks file integrity.
- [RandomUser](https://randomuser.me/) - Generates random user data for testing and sampling.
- [Inoreader](https://www.inoreader.com/) - RSS reader and content aggregator.
- [TreeSize Free](https://www.jam-software.com/treesize_free/) - Disk space analysis tool for Windows.

## Online Anti-Spam

- [Spamcop](https://www.spamcop.net) - Spam reporting service and blacklist data provider.
- [Spamrats](http://www.spamrats.com/) - DNS-based blacklists for email spam sources.
- [EmailSherlock](https://www.emailsherlock.com/) - Email address investigation and lookup service.

## Online Sandboxing

- [Hybrid Analysis](https://www.hybrid-analysis.com/) - Cloud-based malware sandbox by CrowdStrike.
- [Joe Security](https://www.joesecurity.org/) - Automated malware analysis systems and reports.
- [VirusTotal](https://www.virustotal.com) - Aggregates antivirus engines and reputation checks for files and URLs.
- [Metadefender (OPSWAT)](https://metadefender.opswat.com/#!/) - Multiscanning and data sanitization platform.
- [Sandboxie](https://www.sandboxie.com/) - Sandbox tool for running programs securely and isolating changes.

## Not Distribute

- [NoDistribute](https://nodistribute.com/) - Malware scanning service that attempts to avoid detection by antivirus engines.

## Malware Analysis

- [VirusBay (Beta)](https://beta.virusbay.io/) - Community-driven malware repository and analysis platform.
- [BinDiff (zynamics)](https://www.zynamics.com/bindiff.html) - Binary comparison tool for vulnerability research.
- [ClamAV](https://www.clamav.net/) - Open-source antivirus engine for detecting malware.
- [VirusShare](https://virusshare.com/) - Malware sample repository for security researchers.

### Ransomware

- [File Signatures Reference - Ransomware](https://fsrm.experiant.ca/) - Reference library of ransomware signatures.
- [NoMoreRansom](https://www.nomoreransom.org/) - Decryption tools and resources for ransomware victims.

### Rootkits

- [Rootkit Revealer (Sysinternals)](https://docs.microsoft.com/en-us/sysinternals/downloads/rootkit-revealer) - Rootkit detection tool for Windows systems.
- [McAfee Rootkit Remover](https://www.mcafee.com/enterprise/en-gb/downloads/free-tools/rootkitremover.html) - Free tool to remove complex rootkits from infected systems.
- [Sophos Anti-Rootkit](https://www.sophos.com/en-us/products/free-tools/sophos-anti-rootkit.aspx) - Detects and removes rootkits from Windows machines.
- [rkhunter](http://rkhunter.sourceforge.net/) - Unix-based rootkit, backdoor, and local exploit scanner.

## TOR

- [TOR Status (blutmagie)](https://torstatus.blutmagie.de/) - Lists and monitors TOR network nodes.
- [Dan.me.uk TOR Nodes](https://www.dan.me.uk/tornodes) - Information on current TOR exit nodes and statistics.

## Cyber Threat Intelligence (CTI)

- [OSINT Framework](https://osintframework.com/) - Collection of OSINT tools and resources for investigations.
- [Hunter.io](https://hunter.io/) - Finds and verifies email addresses from domain names.
- [start.me](https://start.me/) - Personalized start pages, often used for OSINT link collections.
- [Email Format](https://www.email-format.com/) - Suggests likely email formats for company domains.
- [Crunchbase](https://www.crunchbase.com/) - Business and company intelligence for profiling organizations.

## CERTs

- [NCSC (UK)](https://www.ncsc.gov.uk/) - UK’s National Cyber Security Centre resources and advisories.
- [US-CERT](https://www.us-cert.gov/) - US Cybersecurity and Infrastructure Security Agency’s threat alerts and guidance.
- [CCN-CERT (Spain)](https://www.ccn-cert.cni.es/en/) - Spanish National Cryptologic Center’s incident response and security advisories.
- [CESICAT (Catalonia)](https://ciberseguretat.gencat.cat/ca/inici) - Catalan Cybersecurity Agency’s resources and advisories.
- [Australian Cyber Security Centre](https://www.cyber.gov.au/) - Cybersecurity guidelines and threat information for Australia.
- [CIRCL (Luxembourg)](https://www.circl.lu/) - Cybersecurity Incident Response Center Luxembourg information and services.
- [SecurityFocus](https://www.securityfocus.com/) - News, vulnerability database, and security advisories.
- [SANS ISC](https://isc.sans.edu/) - Internet Storm Center: threat intelligence and daily security diaries.
- [ECSIRT.net](http://www.ecsirt.net/) - European network of CERTs and security teams.

## CTFs

- [VulnHub](https://www.vulnhub.com/) - Vulnerable VMs and CTF challenges for security training.
- [HackTheBox](https://www.hackthebox.eu/) - Platform offering real-world penetration testing labs and challenges.
- [SocBattle](https://www.socbattle.com/) - Security operations center (SOC) simulation game and competitions.
- [YETI Platform](https://yeti-platform.github.io/) - Open-source platform for sharing and analyzing threat intelligence data.

## IDS/IPS Tools

- [Zeek](https://www.zeek.org/) - Network security monitoring tool and analysis framework.
- [Suricata](https://suricata-ids.org/) - Open-source IDS/IPS and network security monitoring tool.
- [Snort](https://www.snort.org/) - Popular IDS/IPS engine with a rules-based language for traffic analysis.
- [Xplico](https://www.xplico.org/) - Network forensic analysis tool for reconstructing network sessions.
- [OSSEC](https://www.ossec.net/) - Host-based intrusion detection system for log analysis and rootkit detection.

## Incident Response Distros

- [Qubes OS](https://www.qubes-os.org/) - Security-focused operating system using compartmentalization.
- [SANS Investigative Forensics Toolkit (SIFT)](https://digital-forensics.sans.org/community/downloads) - Ubuntu-based distro with forensic and incident response tools.
- [REMnux](https://remnux.org/) - Linux toolkit for reverse engineering and analyzing malware.
- [CAINE](https://www.caine-live.net/) - Digital forensics live environment with pre-installed IR tools.
- [Kali Linux](https://www.kali.org/) - Penetration testing and security auditing Linux distribution.

## Tracker Services

- [Ransomware Tracker (abuse.ch)](https://ransomwaretracker.abuse.ch/tracker/) - Lists and tracks known ransomware domains, IPs, and URLs.
- [Feodo Tracker (abuse.ch)](https://feodotracker.abuse.ch/browse/) - Tracks Feodo/Emotet related malicious infrastructure.

## Real-Time Response

- [Mozilla MIG](https://mig.mozilla.org/doc.html) - Mozilla Investigator (MIG) is a platform for investigative remote endpoint querying and intrusion analysis.
