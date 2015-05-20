import socket
import sys
import re

def get_tld_server(tld="com"):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect(("whois.iana.org", 43))
    sock.send("{}\n".format(tld).encode("utf-8"))
    for line in sock.makefile():
        tld_match = re.match("^(.*?): {1,}(.*?)$", line)
        if tld_match:
            if tld_match.group(1) == "whois":
                return tld_match.group(2)
        #print(repr(line))

def get_whois_data(domain, server=None):
    if not server:
        tld = domain.split(".")[-1]
        server = get_tld_server(tld)

    nextserver = None

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((server, 43))
    sock.send("{}\n".format(domain).encode("utf-8"))
    for line in sock.makefile():
        parts = re.match("^(.*?): {1,}(.*?)$", line.strip())
        if parts:
            if parts.group(1).lower() == "whois server":
                nextserver = parts.group(2)
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
