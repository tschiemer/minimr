# minimr
mini mDNS Responder (framework) - platform independent and ARM friendly

*minimr* comes with two parts:
1. a basic mDNS query handler and response generator framework
2. a simple, ready-made mDNS responder for one A, AAAA, SRV, TXT and PTR record (see `minimrsimple.*` and `examples/mbed-simple`)

*minimr* does NOT provide networking, timing or memory management capabilities which ultimately must be implemented by you. Which also means that there is no functionality to register or unregister services.

*minimr* provides rather low-level datastructures and functions that can be used - and can easily be customized. If you only require a fixed and small set of services - which is a likely use case `minimr` was intended for: great!
If you want a complete (and *elaborate*) implementation you're recommended to have a look at AHAVI or Apple's implementations (see below).

The minimrsimple-responder can act as logical core which also shows how the basic framework can be made use of.

For a working example also see `examples/mbed-simple` wherein you will find a demo implementation for an echo-service device.

Key-features:
- Only processes mDNS messages and in particular does NOT use
   - any form of networking (or memory) abstraction
   - dynamic memory allocation
- Provides features usable for both a server and client but no high-level API (except for the simple ready-made responder)
- Low-level but friendly control of (customizable) datastructures


## Other (interesting) implementations

- [AVAHI](https://www.avahi.org/) (Linux)
- [Apple Bonjour](https://developer.apple.com/bonjour/) (macOS, Windows, Linux, embeddable(?)): Service Discovery for Linux using mDNS/DNS-SD -- compatible with Bonjour
- [zcip](http://zeroconf.sourceforge.net/) (Linux)
- [lwIP](http://www.nongnu.org/lwip/2_0_x/group__mdns.html) (*ARM*, macOS, Windows, Linux):
- [mbed's nanostack](https://github.com/ARMmbed/mbed-os/blob/master/features/nanostack/sal-stack-nanostack/nanostack/ns_mdns_api.h) (ARM..?): on top of stack?
- [mjanssons's mDNS/DNS-SD library](https://github.com/mjansson/mdns): a header only cross-platform mDNS and DNS-DS library in C (with a clear concept of sockets)
- [microdns](https://github.com/videolabs/libmicrodns): microdns is an mDNS library, focused on being simple and cross-platform (with a clear concept of sockets (platform callbacks))
- [TinySVCmDNS (fork)](https://github.com/philippe44/TinySVCmDNS) (macOS, Windows, Linux, ARM): tiny MDNS responder implementation for publishing services
- [XMOS's lib_xctp](https://github.com/xmos/lib_xtcp/blob/master/lib_xtcp/src/mdns/): for their XCORE platform
- [mdnsd](https://github.com/kernelconcepts/mdnsd): embeddable Multicast DNS Daemon (with KC enhancements)


## Todos

- [ ] evolve simple responder to a more dynamic version

## Known Limitations

- Doesn't handle fragmented/truncated/multi-packet messages. (should be ok?)
- Tiebreaking (of multiple records) in principle is possible but requires architectural complexity which contradicts the simplicity aimed for. Thus it is a feature which is not provided but can be implemented by you.

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

TODO (?)

## Implementation Notes (Framework)

Please refer to [RFC6763](https://tools.ietf.org/html/rfc6762) for implementation details which you are recommended to read anyways.

You are also recommended to have a look at `minimrsimple.*` which shows how to work with the types and functions available.

### General

- IPv4 multicast address: 224.0.0.251
- IPv6 (local-link) multicast address: ff02::fb

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

### Core

Records essentially consist of a derivation of `struct minimr_rr`, which looks roughly as follows:

```c

/**
 * desired function type
 * @see minimr_rr_fun
 */
typedef enum  {
    minimr_rr_fun_query_respond_to,
    minimr_rr_fun_query_get_rr,
    minimr_rr_fun_query_get_authority_rrs,
    minimr_rr_fun_query_get_extra_rrs,
    minimr_rr_fun_get_rr,
    minimr_rr_fun_announce_get_rr,
    minimr_rr_fun_announce_get_extra_rrs,
    minimr_rr_fun_lexcmp
} minimr_rr_fun;

typedef int32_t (*minimr_rr_fun_handler)(minimr_rr_fun type, struct minimr_rr *rr, ...);

struct minimr_rr {
    uint16_t type;
    uint16_t cache_class;
    uint32_t ttl;

    MINIMR_TIMESTAMP_FIELD
    MINIMR_RR_CUSTOM_FIELD

    minimr_rr_fun_handler handler;

    uint16_t name_length;

    uint8_t name[__namelen__];
}
```

Any actual record types are defined using precompiler macros `MINIMR_RR_TYPE_BEGIN(__namelen__)` and `MINIMR_RR_TYPE_END()`. Extensions and customizations are possible either using the given `MINIMR_RR_CUSTOM_FIELD` define or by actually defining a type, like so:

```c
typedef
MINIMR_RR_TYPE_BEGIN(MY_MAX_NAMELEN)
  uint16_t priority;
  uint8_t fancy_field;
  // etc
MINIMR_RR_TYPE_END()
my_custom_rr_t;
```

By setting a series of max-size defines (also see `examples/mbed-simple/minimropt.h`) the default types `minimr_rr_a`, `minimr_rr_aaaa`, `minimr_rr_srv`, `minimr_rr_txt` and `minimr_srv` will be defined.

Any generation of messages with records requires the listed handler-function (see `minimrsimple.c` for a generic example).

RRNAME/CNAMEs have a specific segmented "normalized" (and internally used!) format - to easily normalize and denormalize names from/to NUL-terminated strings you can use the following functions:

```c

/**
 * Turns a NUL-terminated string into N segments preceded by a segment * length marker and sets <length> to string length (incl. NUL)
 */
void minimr_field_normalize(uint8_t * field, uint16_t * length, uint8_t marker);

/**
 * Shorthand to normalize an uncompressed NAME
 */
#define minimr_name_normalize(field, length)            minimr_field_normalize(field, length, '.')

/**
 * Shorthand to normalize TXT RDATA
 * length - 1 because length is not NUL-terminated but specifies RDLENGTH
 */
#define minimr_txt_normalize(field, length, marker)     minimr_field_normalize(field, length, marker); \
                                                            if (length != NULL) (*(length))--;

/**
 * Reverse function of minimr_field_normalize()
 * (field must be
 */
void minimr_field_denormalize(uint8_t * field, uint16_t length, uint8_t marker);

#define minimr_name_denormalize(field, length)          minimr_field_denormalize(field, length, '.')

#define minimr_txt_denormalize(field, length, marker)   minimr_field_denormalize(field, length, marker)

```

#### Message Parser

If you want to search arriving mDNS messages for specific records, you can use the parser for this:

```c
/**
 * Tries to parse given mDNS message calling the (optional) handlers for each encountered query or RR
 * Can be used to construct a fully featured mDNS responder
 * @var unimulticast    Was message sent over unicast (0)
 * @see minimr_query_handler
 * @see minimr_rr_handler
 */
int32_t minimr_parse_msg(
        uint8_t *msg, uint16_t msglen,
        minimr_msgtype msgtype,
        minimr_query_handler qhandler, struct minimr_filter * qfilters, uint16_t nqfilters,
        minimr_rr_handler rrhandler, struct minimr_filter * rrfilters, uint16_t nrrfilters,
        void * user_data
);
```

#### Message Generator

To generate arbitrary messages you can use the following function, although note, that there are a series of convenience functions for particular message types (ie probe queries, announcements; see below):

```c
/**
 * Generates an arbitrary mDNS message according to arguments.
 *
 * IMPORTANT NOTE: names are expected to be normalized
 *
 * @param queries       can be NULL iff nqueries == 0
 * @param answer_rrs    can be NULL iff nanswer_rrs == 0
 * @param auth_rrs      can be NULL iff nauth_rrs == 0
 * @param extra_rrs     can be NULL iff nextra_rrs == 0
 * @see struct minimr_query
 * @see struct minimr_rr
 * @see
 */
int32_t  minimr_make_msg(
        uint16_t tid, uint8_t flag1, uint8_t flag2,
        struct minimr_query * queries, uint16_t nqueries,
        struct minimr_rr ** answer_rrs, uint16_t nanswer_rrs,
        struct minimr_rr ** auth_rrs, uint16_t nauth_rrs,
        struct minimr_rr ** extra_rrs, uint16_t nextra_rrs,
        uint8_t *outmsg, uint16_t *outmsglen, uint16_t outmsgmaxlen,
        void * user_data
);
```

### Convenience Functions

#### Probing

```c
/**
 * Comfort function to generate a probe-query for 1-2 specific (normalized) qnames ANY type and IN class
 *
 * @param name1     required NORMALIZED name to query
 * @param name2     optional NORMALIZED name to query; NULL if not used
 */
int32_t minimr_probequery_msg(
        uint8_t * name1,
        uint8_t * name2,
        struct minimr_rr ** proposed_rrs, uint16_t nproposed_rrs,
        uint8_t *outmsg, uint16_t *outmsglen, uint16_t outmsgmaxlen,
        uint8_t request_unicast,
        void * user_data
);
```

#### Announcements and Updates

You can make use of `minimr_announce()` to construct announcement and update messages:

```c
uint8_t minimr_announce_msg(
        struct minimr_rr **records, uint16_t nrecords,
        uint8_t *outmsg, uint16_t *outmsglen, uint16_t outmsgmaxlen,
        void * user_data
);
```


#### Service Termination / Goodbye Messages

You can make use of `minimr_terminate()` to construct announcement and update messages:

```c
uint8_t minimr_terminate(
    struct minimr_dns_rr **records, uint16_t nrecords,
    uint8_t *outmsg, uint16_t *outmsglen, uint16_t outmsgmaxlen
);
```

*IMPORTANT NOTE: This is actually just a convenience function that sets all TTLs to 0 and calls `minimr_announce()` (remember to set the TTL again to a valid value when republished)*


### Other

#### Name Compression

*minimr* does not force you to use [name compression](https://tools.ietf.org/html/rfc6762#section-18.14) and does not automatically compress data provided by you, but can handle compressed names of incoming messages - and if so desired extract compressed names; also see:

```c
/**
 * Copies possibly compressed name to given destination and returns length of NUL-terminated string
 */
int32_t minimr_name_uncompress(uint8_t * uncompressed_name, uint16_t maxlen, uint16_t namepos, uint8_t * msg, uint8_t msglen);
```

If you want to use name compression in responses, please implement this yourself - record callbacks/handlers essentially are provided with complete messages when writing responses, if they can remember which names were used where, this should be a piece of cake ;) (more or less).



## MIT License

Also see `LICENSE` file.

## References

- [RFC6762: Multicast DNS](https://tools.ietf.org/html/rfc6762)
- [IANA Domain Name System (DNS) Parameters](https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml)
