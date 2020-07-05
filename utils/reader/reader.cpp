//
// Created by Philip Tschiemer on 28.06.20.
//

#include <vector>
#include "minimr.h"

#include "getopt.h"

void print_help(char * argv[])
{
    printf("Usage: %s [-t <q|r>] [-q [<qtype> [<qclass> ]]<qname>]* [-r [<rrtype> [<rrclass> ]]<rrname>]*\n", argv[0]);
    printf("Tries to parse messages passed to STDIN and dumps data in a friendlier format to STDOUT\n");
    printf("\t -t <q|r> \t Parse only q(ueries) or r(esponses)\n");
    printf("\t -q [<qtype> [<qclass> ]]<qname>\n\t\t Add query filter for specific types, classes and foremost names. If type and or class are not given, ANY is assumed.\n");
    printf("\t -r [<rrtype> [<rrclass> ]]<rrname>\n\t\t Add response filter for specific types, classes and foremost names. If type and or class are not given, ANY is assumed.\n");
    printf("\n");
    printf("=== IMPORTANT NOTE ===\n");
    printf("qnames and rrnames these must be formatted as follows: .segment1.segment2. etc .tld\n");
    printf("\n");
    printf("Examples:\n");
    printf("%s -t q\n", argv[0]);
    printf("%s -q .Here-be-Kittens.local\n", argv[0]);
    printf("%s -q A .Here-be-Kittens.local\n", argv[0]);
    printf("%s -r PTR IN _echo._udp.local\n", argv[0]);
    printf("\n");
    printf("Copyfright 2020 filou.se, MIT License\n");
    printf("~~ LONG LIVE KITTENS ~~\n");
}

uint16_t receive_udp_packet(uint8_t * payload, uint16_t maxlen)
{

    MINIMR_ASSERT(payload != NULL);
    MINIMR_ASSERT(maxlen > 0);

    // from_addr is not really used

    size_t r = fread(payload, sizeof(uint8_t), maxlen, stdin);

    return r;
}

void add_filter(char * str, std::vector<struct minimr_filter> &filters){

    struct minimr_filter filter;// = (struct minimr_filter *)malloc(sizeof(struct minimr_filter));

    char tmptype[256];
    char tmpclass[256];
    char * pname;
    int n;

    if (2 == sscanf(str, "%[0-9A-Z] %[0-9A-Z] %n.", tmptype, tmpclass, &n)){

        filter.type = minimr_dns_type_fromstr((uint8_t*)tmptype);

        if (filter.type == 0){
            filter.type = std::atoi(tmptype);

            if (filter.type == 0){
                filter.type = MINIMR_DNS_TYPE_ANY;
            }
        }

        filter.fclass = minimr_dns_class_fromstr((uint8_t*)tmpclass);

        if (filter.fclass == 0){
            filter.fclass = std::atoi(tmpclass);

            if (filter.fclass == 0){
                filter.fclass = MINIMR_DNS_CLASS_IN;
            }
        }

        pname = &str[n];

    } else if (1 == sscanf(str, "%[0-9A-Z] %n", tmptype, &n)){

        filter.type = minimr_dns_type_fromstr((uint8_t*)tmptype);

        if (filter.type == 0){
            filter.type = std::atoi(tmptype);

            if (filter.type == 0){
                filter.type = MINIMR_DNS_TYPE_ANY;
            }
        }

        filter.fclass = MINIMR_DNS_CLASS_IN;

        pname = &str[n];

    } else {

        filter.type = MINIMR_DNS_TYPE_ANY;
        filter.fclass = MINIMR_DNS_CLASS_IN;

        pname = str;
    }

    filter.name = (uint8_t*)pname;

//        printf("query type = %s (%d), class = %s (%d), name = %s\n", minimr_dns_type_tostr(filter.type), filter.type, minimr_dns_class_tostr(filter.fclass), filter.fclass, filter.name);

    minimr_name_normalize((uint8_t*)pname, NULL);

    filters.push_back(filter);
    
    
}

void print_hdr(struct minimr_dns_hdr * hdr){
    printf("hdr\n tid %04x flag %02x%02x nq %04x nrr %04x narr %04x nexrr %04x\n", hdr->transaction_id, hdr->flags[0], hdr->flags[1], hdr->nqueries, hdr->nanswers, hdr->nauthrr, hdr->nextrarr);
}

uint8_t print_query(struct minimr_dns_hdr * hdr, struct minimr_dns_query_stat * qstat, uint8_t * msg, uint16_t msglen, void * user_data)
{
    uint8_t unicast = (qstat->unicast_class & MINIMR_DNS_QUNICAST);
    uint8_t glass = (qstat->unicast_class & ~MINIMR_DNS_QCLASS);
    uint8_t name[256] = "";
    int32_t namelen = minimr_name_uncompress(name, sizeof(name), qstat->name_offset, msg, msglen);

    MINIMR_ASSERT(namelen >= 0);

    minimr_name_denormalize(name, namelen);

    printf("QUERY qtype %d (%s) unicast %d qclass %d qname (%d) %s\n", qstat->type, minimr_dns_type_tostr(qstat->type), unicast, glass, namelen, name);


    return MINIMR_CONTINUE;
}

uint8_t print_rr(struct minimr_dns_hdr * hdr, minimr_rr_section section, struct minimr_dns_rr_stat * rstat, uint8_t * msg, uint16_t msglen, void * user_data)
{

    uint8_t * sectionstr;

    switch (section){
        case minimr_rr_section_answer:
            sectionstr = (uint8_t*)"ANSWER ";
            break;
        case minimr_rr_section_authority:
            sectionstr = (uint8_t*)"AUTH ";
            break;
        case minimr_rr_section_extra:
            sectionstr = (uint8_t*)"EXTRA ";
            break;
    }

    uint8_t cacheflush = (rstat->cache_class & MINIMR_DNS_CACHEFLUSH) ? 1 : 0;
    uint8_t rclass = (rstat->cache_class & MINIMR_DNS_RRCLASS);

    uint8_t name[256] = "";
    int32_t namelen = minimr_name_uncompress(name, sizeof(name), rstat->name_offset, msg, msglen);

    MINIMR_ASSERT(namelen >= 0);

    minimr_name_denormalize(name, namelen);

    printf("%sRR rrtype %d (%s) cacheflush %d rrclass %d rrname (%d) %s rrdata (%d) ", sectionstr, rstat->type, minimr_dns_type_tostr(rstat->type), cacheflush, rclass, namelen, name, rstat->dlength);



    if (rstat->type == MINIMR_DNS_TYPE_A) {
        printf("%d.%d.%d.%d", msg[rstat->data_offset + 0], msg[rstat->data_offset + 1], msg[rstat->data_offset + 2],
               msg[rstat->data_offset + 3]);
    }
    else if (rstat->type == MINIMR_DNS_TYPE_AAAA) {
        printf("%x:%x:%x:%x:%x:%x:%x:%x",
               (uint16_t) ((msg[rstat->data_offset + 0] << 8) | msg[rstat->data_offset + 1]),
               (uint16_t) ((msg[rstat->data_offset + 2] << 8) | msg[rstat->data_offset + 3]),
               (uint16_t) ((msg[rstat->data_offset + 4] << 8) | msg[rstat->data_offset + 5]),
               (uint16_t) ((msg[rstat->data_offset + 6] << 8) | msg[rstat->data_offset + 7]),
               (uint16_t) ((msg[rstat->data_offset + 8] << 8) | msg[rstat->data_offset + 9]),
               (uint16_t) ((msg[rstat->data_offset + 10] << 8) | msg[rstat->data_offset + 11]),
               (uint16_t) ((msg[rstat->data_offset + 12] << 8) | msg[rstat->data_offset + 13]),
               (uint16_t) ((msg[rstat->data_offset + 14] << 8) | msg[rstat->data_offset + 15]));
    }
    else if (rstat->type == MINIMR_DNS_TYPE_PTR) {
        namelen = minimr_name_uncompress(name, sizeof(name), rstat->data_offset, msg, msglen);
        MINIMR_ASSERT(namelen >= 0);
        minimr_name_denormalize(name, namelen);
        printf("domain: %s", name);
    }
    else if (rstat->type == MINIMR_DNS_TYPE_SRV) {
        uint16_t priority =  (uint16_t) ((msg[rstat->data_offset + 0] << 8) | msg[rstat->data_offset + 1]);
        uint16_t weight = (uint16_t) ((msg[rstat->data_offset + 2] << 8) | msg[rstat->data_offset + 3]);
        uint16_t port = (uint16_t) ((msg[rstat->data_offset + 4] << 8) | msg[rstat->data_offset + 5]);

        namelen = minimr_name_uncompress(name, sizeof(name), rstat->data_offset+6, msg, msglen);
        MINIMR_ASSERT(namelen >= 0);
        minimr_name_denormalize(name, namelen);

        printf("priority %hu weight %hu port %hu target: %s", priority, weight, port, name);
    }
    else {
        for(uint16_t i = 0; i < rstat->dlength; i++){
            printf("%02x", msg[rstat->data_offset + i]);
        }
    }

    printf("\n");

    return MINIMR_CONTINUE;
}

int main(int argc, char * argv[]){


    int opt;

    minimr_msgtype msgtype = minimr_msgtype_any;

    std::vector<struct minimr_filter> qfilters;
    std::vector<struct minimr_filter> rrfilters;

    while ((opt = getopt(argc, argv, "hq:r:t:")) != -1) {
        switch (opt) {
            case 'h':
            case '?':
                print_help(argv);
                return EXIT_SUCCESS;

            case 'q':
                add_filter(optarg, qfilters);
                break;

            case 'r':
                add_filter(optarg, rrfilters);
                break;

            case 't':
                if (optarg[0] == 'q'){
                    msgtype = minimr_msgtype_query;
                } else if (optarg[0] == 'r'){
                    msgtype = minimr_msgtype_response;
                } else {
                    fprintf(stderr, "ERROR invalid option for msgtype (-t <q|r>): %s\n", optarg);
                    return EXIT_FAILURE;
                }
                break;

            default:
                fprintf(stderr, "ERROR unrecognized option\n");
                print_help(argv);
                return EXIT_FAILURE;

        }
    }

    uint8_t udp_payload[2048];
    uint16_t len;


    while(!feof(stdin)){

        len = receive_udp_packet(udp_payload, sizeof(udp_payload));

        if (len <= MINIMR_DNS_HDR_SIZE){
            continue;
        }
        printf("------------ NEW MESSAGE --------------\n");

        struct minimr_dns_hdr hdr;

        minimr_dns_hdr_read(&hdr, udp_payload);

        print_hdr(&hdr);

//        int res = minimr_parse_msg(udp_payload, len,  print_query, &qfilters[0], qfilters.size(), print_rr, &rrfilters[0], rrfilters.size(), NULL);
        int res = minimr_parse_msg(udp_payload, len,  msgtype, print_query, &qfilters[0], qfilters.size(), print_rr, &rrfilters[0], rrfilters.size(), NULL);

        if (res != MINIMR_OK){
            printf("ERROR %d\n", res);
        }
    }

    return EXIT_SUCCESS;
}