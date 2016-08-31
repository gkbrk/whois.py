#!/usr/bin/env python3
import socket
import sys

def get_tld_server(tld="com"):
    sock = socket.socket()
    sock.connect(("whois.iana.org", 43))
    sock.send("{}\n".format(tld).encode("utf-8"))
    for line in sock.makefile():
        parts = line.split(":", 2)
        if len(parts) > 1:
            header_name = parts[0].strip()
            header_value = parts[1].strip()
            if header_name.lower() == "whois":
                return header_value

def get_whois_data(domain, server=None):
    if not server:
        tld = domain.split(".")[-1]
        server = get_tld_server(tld)

    nextserver = None

    sock = socket.socket()
    sock.connect((server, 43))
    sock.send("{}\n".format(domain).encode("utf-8"))
    for line in sock.makefile():
        parts = line.split(":", 2)
        if len(parts) > 1:
            header_name = parts[0].strip()
            header_value = parts[1].strip()
            if header_name.lower() == "whois server":
                nextserver = header_value
        yield line.replace("\n", "")
    
    if nextserver:
        for line in get_whois_data(domain, nextserver):
            yield line

def main():
    if len(sys.argv) < 2:
        print("Usage: {} domain.com".format(sys.argv[0]))
        exit(1)

    for domain in sys.argv[1:]:
        for line in get_whois_data(domain):
            print(line)

if __name__ == "__main__":
    main()
