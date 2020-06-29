# minimr
mini mDNS Responder (framework)

The goal of `minimr` is to provide a generic mDNS query handler and response generator framework.

`minimr` does NOT provide networking or memory management capabilities which ultimately must be implemented by you. Which also means that there is not functionality to register or unregister services.

`minimr` provides rather low-level datastructures that can be used - and can easily be customized. If you only require a fixed and small set of services - which is a likely use case `minimr` was intended for: great!
If you want a complete (and *elaborate*) implementation you're recommended to have a look at AHAVI or Apple's implementations (see below).

See [minimr-cli-demo](#minimr-cli-demo) to see an example implementation of how to use the framework.


## Other implementations

- [AVAHI](https://www.avahi.org/)
- [Apple Bonjour](https://developer.apple.com/bonjour/)
- [zcip](http://zeroconf.sourceforge.net/)
- [lwIP](http://www.nongnu.org/lwip/2_0_x/group__mdns.html): on top of stack
- [mbed's nanostack](https://github.com/ARMmbed/mbed-os/blob/master/features/nanostack/sal-stack-nanostack/nanostack/ns_mdns_api.h): on top of stack??
- [XMOS's lib_xctp](https://github.com/xmos/lib_xtcp/blob/master/lib_xtcp/src/mdns/): for their


## Todos

- ~~[Multicast DNS Character Set](https://tools.ietf.org/html/rfc6762#section-16) and in particular utf8 support~~
- ~~Support name compression for in received queries~~
- Add startup probing (and query) functionality
- Timebased limit of responses of the same RR

## Known Limitations

- Doesn't handle fragmented/truncated/multi-packet messages. (should be ok?)

## Quick Note on DNS-SD (Service Discovery)

Services published through mDNS typically consist of a minimum of three records:

So when a host wants to discover any specific services it queries for PTR records.
A generic PTR record with example RRNAME `_echo._udp.local` (let's make up an UDP based echo service) will point to an actual service in it's RRDATA such as `Here Be Kittens._echo._udp.local`.


Specific services (or servers) are described in SRV records matching the service name, ex `Here Be Kittens._echo._udp.local`, which include a service priority, weight, used port number and a target (ie canonical hostname which must match with an A and/or AAAA record), ex priority 0, weight 0, port 7, target `here-be-kittens.local`. The actual service name - which often will be presented to users - is the first segment of the record's RRNAME, ex `Here Be Kittens`.

As mentioned the target host must match an A and/or AAAA record which merely are IPv4, IPv6 respectively pointers, ex. IPv4 `10.0.0.100`.

Optional service (configuration) options which MUST have the same RRNAME as the SRV record can (or must?) be defined aswell in the typical format `key1=value1 key2=value2 ...` (in fact each key/value pair is preceded withe length of the pair in bytes).

Thus the minimal required record set to make your services discoverable would entail a PTR, SRV, TXT, A and/or AAAA record.

There are additional record types which could be part of a service but this will not be discussed here.

### Publishing a Service: Dependencies and Conflicts

Obviously A and AAAA records depend both on an IPv4, IPv6 respectively and that the given chosen hostname is unique.

Most likely an IP address will be obtained from a DHCP server unless link-local addresses are used. The potential for conflicts does exist, but in a somewhat (dynamically) managed address space, there shouldn't be.

Hostnames (ending in `.local`) can potentially conflict with other hosts on the network - which depends on the host setup (now imagine all those `i-love-kittens.local` hostnames). For standalone devices using a unique hardware ID (such as the mac address) as part of the hostname somewhat guarantees uniqueness but on the other hand might not be so user-friendly.

Service names have the very same problem as hostnames where too many kitten lovers will cause service conflicts - as SRV records point to the A/AAAA (hostname) records, there obviously also is a dependency to valid A/AAAA records.

Because of these potential conflicts mDNS entails a (startup) probing phase where the unique record names (A/AAAA, SRV/TXT) are queried for. The are three possible outcomes of this probing phase:
1. If the host receives an authorative answer for its query, either A/AAAA and/or SRV/TXT, the host will know that it can not use said record names and has to reconfigure.
2. If the host receives a query for the same records there is a race situation where another host is probing for the same record names. There's a strategy to resolve this (refer to the RFC) where one of the two devices will have to reconfigure.
3. The host doesn't receive an answer for its query and can thus assume to be allowed to use the records.

Obviously, if record names are guaranteed to be unique the whole probing phase can be skipped, hurray!

But generally speaking the process of publishing a service should roughly be as follows:
1. obtain an IP address -> update A/AAAA records
2. (optional) probe for records -> reconfigure if taken or conflict lost
3. announce records
4. forever respond to queries
   - if record data changes: announce records
   - when stopping a service: announce records with a TTL of 0 and stop responding


## Utilities

### minimr-reader

```bash
Usage: bin/reader [-q <name>]* [-r <name>]*
Tries to parse messages passed to STDIN and dumps data in a friendlier format to STDOUT
```

Example:
```bash
------------ NEW MESSAGE --------------
hdr
 id 0000 flag 0000 nq 0001 nrr 0000 narr 0000 nexrr 0000
QUERY qtype 12 (PTR) unicast 0 qclass 0 qname (17) ._echo._udp.local
```

### minimr-writer

## Examples

## Implementation notes

Please refer to [RFC6763](https://tools.ietf.org/html/rfc6762) for implementation details which you are recommended to read anyways.

Some noteworthy/essential extracts where appropriate.

### General

IPv4 multicast address: 224.0.0.251
IPv6 (local-link) multicast address: ff02::fb

>   Multicast DNS...
>   * uses multicast *yay!*
>   * uses UDP port 5353 instead of port 53
>   * operates in well-defined parts of the DNS namespace
>   * has no SOA (Start of Authority) records
>   * uses UTF-8, and only UTF-8, to encode resource record names
>   * allows names up to 255 bytes plus a terminating zero byte
>   * allows name compression in rdata for SRV and other record types
>   * allows larger UDP packets
>   * allows more than one question in a query message
>   * defines consistent results for qtype "ANY" and qclass "ANY" queries
>   * uses the Answer Section of a query to list Known Answers
>   * uses the TC bit in a query to indicate additional Known Answers
>   * uses the Authority Section of a query for probe tiebreaking
>   * ignores the Query ID field (except for generating legacy responses)
>   * doesn't require the question to be repeated in the response message
>   * uses unsolicited responses to announce new records
>   * uses NSEC records to signal nonexistence of records
>   * defines a unicast-response bit in the rrclass of query questions
>   * defines a cache-flush bit in the rrclass of response records
>   * uses DNS RR TTL 0 to indicate that a record has been deleted
>   * recommends AAAA records in the additional section when responding
>     to rrtype "A" queries, and vice versa
>   * monitors queries to perform Duplicate Question Suppression
>   * monitors responses to perform Duplicate Answer Suppression...
>   * ... and Ongoing Conflict Detection
>   * ... and Opportunistic Caching

Source: [19.  Summary of Differences between Multicast DNS and Unicast DNS](https://tools.ietf.org/html/rfc6762#section-19)

### Startup / Probing


>[8.1.  Probing](https://tools.ietf.org/html/rfc6762#section-8.1)
>
>   The first startup step is that, for all those resource records that a
>   Multicast DNS responder desires to be unique on the local link, it
>   MUST send a Multicast DNS query asking for those resource records, to
>   see if any of them are already in use.  The primary example of this
>   is a host's address records, which map its unique host name to its
>   unique IPv4 and/or IPv6 addresses.  All probe queries SHOULD be done
>   using the desired resource record name and class (usually class 1,
>   "Internet"), and query type "ANY" (255), to elicit answers for all
>   types of records with that name.  This allows a single question to be
>   used in place of several questions, which is more efficient on the
>   network.  It also allows a host to verify exclusive ownership of a
>   name for all rrtypes, which is desirable in most cases.  It would be
>   confusing, for example, if one host owned the "A" record for
>   "myhost.local.", but a different host owned the "AAAA" record for
>   that name.
>
>   et cetera

Don't forget to read about tie breaking etc.

### Announcements and Updates

You can make use of `minimr_announce()` to construct announcement and update messages:

```c
uint8_t minimr_announce(
    struct minimr_dns_rr **records, uint16_t nrecords,
    uint8_t *outmsg, uint16_t *outmsglen, uint16_t outmsgmaxlen
);
```

> [8.3.  Announcing](https://tools.ietf.org/html/rfc6762#section-8.3)
>
>   The second startup step is that the Multicast DNS responder MUST send
>   an unsolicited Multicast DNS response containing, in the Answer
>   Section, all of its newly registered resource records (both shared
>   records, and unique records that have completed the probing step).
>   If there are too many resource records to fit in a single packet,
>   multiple packets should be used.
>
>   In the case of shared records (e.g., the PTR records used by DNS-
>   Based Service Discovery [RFC6763]), the records are simply placed as
>   is into the Answer Section of the DNS response.
>
>   In the case of records that have been verified to be unique in the
>   previous step, they are placed into the Answer Section of the DNS
>   response with the most significant bit of the rrclass set to one.
>   The most significant bit of the rrclass for a record in the Answer
>   Section of a response message is the Multicast DNS cache-flush bit
>   and is discussed in more detail below in Section 10.2, "Announcements
>   to Flush Outdated Cache Entries".
>
>   The Multicast DNS responder MUST send at least two unsolicited
>   responses, one second apart.  To provide increased robustness against
>   packet loss, a responder MAY send up to eight unsolicited responses,
>   provided that the interval between unsolicited responses increases by
>   at least a factor of two with every response sent.
>
>   A Multicast DNS responder MUST NOT send announcements in the absence
>   of information that its network connectivity may have changed in some
>   relevant way.  In particular, a Multicast DNS responder MUST NOT send
>   regular periodic announcements as a matter of course.
>
>   Whenever a Multicast DNS responder receives any Multicast DNS
>   response (solicited or otherwise) containing a conflicting resource
>   record, the conflict MUST be resolved as described in Section 9,
>   "Conflict Resolution".
>
>[8.4.  Updating](https://tools.ietf.org/html/rfc6762#section-8.4)
>
>   At any time, if the rdata of any of a host's Multicast DNS records
>   changes, the host MUST repeat the Announcing step described above to
>   update neighboring caches.  For example, if any of a host's IP
>   addresses change, it MUST re-announce those address records.  The
>   host does not need to repeat the Probing step because it has already
>   established unique ownership of that name.
>
>   In the case of shared records, a host MUST send a "goodbye"
>   announcement with RR TTL zero (see Section 10.1, "Goodbye Packets")
>   for the old rdata, to cause it to be deleted from peer caches, before
>   announcing the new rdata.  In the case of unique records, a host
>   SHOULD omit the "goodbye" announcement, since the cache-flush bit on
>   the newly announced records will cause old rdata to be flushed from
>   peer caches anyway.
>
>   A host may update the contents of any of its records at any time,
>   though a host SHOULD NOT update records more frequently than ten
>   times per minute.  Frequent rapid updates impose a burden on the
>   network.  If a host has information to disseminate which changes more
>   frequently than ten times per minute, then it may be more appropriate
>   to design a protocol for that specific purpose.

### Service Termination / Goodbye Messages

You can make use of `minimr_terminate()` to construct announcement and update messages:

```c
uint8_t minimr_terminate(
    struct minimr_dns_rr **records, uint16_t nrecords,
    uint8_t *outmsg, uint16_t *outmsglen, uint16_t outmsgmaxlen
);
```

*Note: This is actually just a convenience function that sets all TTLs to 0 and calls `minimr_announce()`*

>[10.1.  Goodbye Packets](https://tools.ietf.org/html/rfc6762#section-10.1)
>
>   In the case where a host knows that certain resource record data is
>   about to become invalid (for example, when the host is undergoing a
>   clean shutdown), the host SHOULD send an unsolicited Multicast DNS
>   response packet, giving the same resource record name, rrtype,
>   rrclass, and rdata, but an RR TTL of zero.  This has the effect of
>   updating the TTL stored in neighboring hosts' cache entries to zero,
>   causing that cache entry to be promptly deleted.
>
>   Queriers receiving a Multicast DNS response with a TTL of zero SHOULD
>   NOT immediately delete the record from the cache, but instead record
>   a TTL of 1 and then delete the record one second later.  In the case
>   of multiple Multicast DNS responders on the network described in
>   Section 6.6 above, if one of the responders shuts down and
>   incorrectly sends goodbye packets for its records, it gives the other
>   cooperating responders one second to send out their own response to
>   "rescue" the records before they expire and are deleted.

### Name Compression

`minimr` does not force you to use [name compression](https://tools.ietf.org/html/rfc6762#section-18.14) and does not automatically compress data provided by you.

If you want to use name compression in responses, please implement this yourself - record callbacks/handlers essentially are provided with complete messages when writing responses, if they can remember which names were used where, this should be a piece of cake ;) (more or less).


## MIT License

Also see `LICENSE` file.

## References

- [RFC6762: Multicast DNS](https://tools.ietf.org/html/rfc6762)
- [IANA Domain Name System (DNS) Parameters](https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml)
