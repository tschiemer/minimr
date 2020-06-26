# minimr
mini mDNS Responder (framework)

The goal of `mimimr` is to provide a generic mDNS query handler and response generator framework.

`mimimr` does not provide networking or memory management capabilities which ultimately must be implemented by you.

See [minimr-cli-demo](#minimr-cli-demo) to see an example implementation of how to use the framework.

## Todos

- [Multicast DNS Character Set](https://tools.ietf.org/html/rfc6762#section-16) and in particular utf8 support
- Support name compression for in received queries
- Add startup probing (and query) functionality

## minimr-cli-demo

Is a simple command line utility to play around and understand what's happening.
It reads from STDIN and STDOUT and assumed to receive full mDNS packets (ie, UDP payloads).


```bash
# start server (NOTE mdns is on multicast address 224.0.0.251 and port 5353)
# because of the debug option we'll also see what is being sent out again (alternatively use wireshark or such)
socat -v -x udp4-recvfrom:6666,ip-add-membership=224.1.0.1:192.168.2.142,fork exec:minimr-cli-demo


# send a packet
cat test-packets/Where-be-Kittens.local-A.bin | socat -u - udp4-datagram:224.1.0.1:6666,range=192.168.2.142/24
```

for more on socat see http://www.dest-unreach.org/socat/doc/socat-multicast.html

## Implementation notes

Please refer to [RFC6763](https://tools.ietf.org/html/rfc6762) for implementation details which you are recommended to read anyways.

Some noteworthy/essential extracts where appropriate.

### General

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

### Unicast responses

`minimr` generally ignores the unicast response requested bit - well, it does not deal with any networking

### Name Compression

`minimr` does not force you to use [name compression](https://tools.ietf.org/html/rfc6762#section-18.14) and does not automatically compress data provided by you.

If you want to use name compression in responses, please implement this yourself.

## MIT License

Also see `LICENSE` file.

## References

- [RFC6762](https://tools.ietf.org/html/rfc6762)
- [IANA Domain Name System (DNS) Parameters](https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml)
