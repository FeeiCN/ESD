import socket
import random
import tldextract

import dns.rdatatype
import dns.flags
import dns.query
import dns.resolver
import dns.reversename
import dns.message
from dns.zone import *
from dns.dnssec import algorithm_to_text
from .logger import logger


class DnsSec:
    def __init__(self, domain, ns_server=None, request_timeout=3.0, proto="tcp"):
        self._domain = domain
        self._proto = proto
        if ns_server:
            self._res = dns.resolver.Resolver(configure=False)
            self._res.nameservers = ns_server
            if len(ns_server) > 1:
                self._res.rotate = True
        else:
            self._res = dns.resolver.Resolver(configure=True)
        # Set timing
        self._res.timeout = request_timeout

    def get_a_answer(self, target):
        query = dns.message.make_query(target, dns.rdatatype.NSEC, dns.rdataclass.IN)
        query.flags += dns.flags.CD
        query.use_edns(edns=True, payload=4096)
        query.want_dnssec(True)
        answer = self.query(query)
        return answer

    def query(self, q, port=53, af=None, source=None, source_port=0, one_rr_per_rrset=False):

        if isinstance(self._res.nameservers, list):
            random.shuffle(self._res.nameservers)
            target_server = self._res.nameservers[0]
        else:
            target_server = self._res.nameservers

        if self._proto == "tcp":
            return dns.query.tcp(q, target_server, self._res.timeout, port, af, source, source_port, one_rr_per_rrset)
        else:
            return dns.query.udp(q, target_server, self._res.timeout, port, af, source, source_port, False, one_rr_per_rrset)


    def get_nsec_type(self):

        target = self._domain
        answer = self.get_a_answer(target)
        for a in answer.authority:
            if a.rdtype == 50:
                return "NSEC3"
            elif a.rdtype == 47:
                return "NSEC"

    def dns_sec_check(self):
        try:
            answer = self._res.query(self._domain, 'DNSKEY')
            logger.info("DNSSEC is configured for {0}".format(self._domain))
            nsectype = self.get_nsec_type()
            logger.info("DNSKEYs:")
            for rdata in answer:
                if rdata.flags == 256:
                    key_type = "ZSK"
                if rdata.flags == 257:
                    key_type = "KSK"

                logger.info("{0} {1} {2} {3}".format(nsectype, key_type, algorithm_to_text(
                    rdata.algorithm), dns.rdata._hexify(rdata.key)))
            return True
        except dns.resolver.NXDOMAIN:
            logger.error("Could not resolve domain: {0}".format(self._domain))
            return False

        except dns.resolver.NoNameservers:
            logger.error("All nameservers failed to answer the DNSSEC query for {0}".format(self._domain))
            return False

        except dns.exception.Timeout:
            logger.error("A timeout error occurred please make sure you can reach the target DNS Servers")
            logger.error("directly and requests are not being filtered. Increase the timeout from {0} second".format(self._res.timeout))
            return False
        except dns.resolver.NoAnswer:
            logger.error("DNSSEC is not configured for {0}".format(self._domain))
            return False


    def ds_zone_walk(self):
        """
        Perform DNSSEC Zone Walk using NSEC records found the the error additional
        records section of the message to find the next host to query int he zone.
        """
        logger.info("Performing NSEC Zone Walk for {0}".format(self._domain))

        pending = set([self._domain])
        finished = set()
        extract = tldextract.extract(self._domain)
        root_domain = extract.domain + '.' + extract.suffix
        root_domain_len = len(root_domain) + 1

        try:
            while pending:
                # Get the next pending hostname
                hostname = pending.pop()
                finished.add(hostname)

                target = hostname
                if not target:
                    continue

                # Perform a DNS query for the target and process the response
                response = self.get_a_answer(target)

                for a in response.answer:
                    if a.rdtype != 47:
                        continue

                    # NSEC records give two results:
                    #   1) The previous existing hostname that is signed
                    #   2) The subsequent existing hostname that is signed
                    # Add the latter to our list of pending hostnames
                    for r in a:
                        # Avoid walking outside of the target self._domain. This
                        # happens with certain misconfigured domains.s
                        if r.next.to_text()[-root_domain_len:-1] == root_domain:
                            pending.add(r.next.to_text()[:-1])

                # Ensure nothing pending has already been queried
                pending -= finished

        except (KeyboardInterrupt):
            logger.error("You have pressed Ctrl + C. Saving found records.")

        except (dns.exception.Timeout):
            logger.error(
                "A timeout error occurred while performing the zone walk please make ")
            logger.error(
                "sure you can reach the target DNS Servers directly and requests")
            logger.error("are not being filtered. Increase the timeout to a higher number")

        except (EOFError):
            logger.error("SoA nameserver {} failed to answer the DNSSEC query for {}".format(
                self._res.nameserver, target))

        except (socket.error):
            logger.error("SoA nameserver {} failed to answer the DNSSEC query for {}".format(
                self._res.nameserver, self._domain))

        # Give a summary of the walk
        if len(finished) == 0:
            logger.warning("Zone could not be walked")

        return list(finished)


if __name__ == "__main__":
    domain = sys.argv[1]
    ns_server = ['8.8.8.8']
    proto = 'tcp'
    dnssec = DnsSec(domain, ns_server, 10, proto)
    dnssec.dns_sec_check()
    zone_info = dnssec.ds_zone_walk()
    print(zone_info)
