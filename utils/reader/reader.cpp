//
// Created by Philip Tschiemer on 28.06.20.
//

#include <vector>
#include "minimr.h"

#include "getopt.h"

void print_help(char * argv[])
{
    printf("Usage: %s [-q <name>]* [-r <name>]*\n", argv[0]);
    printf("Tries to parse messages passed to STDIN and dumps data in a friendlier format to STDOUT\n");
}

uint16_t receive_udp_packet(uint8_t * payload, uint16_t maxlen)
{

    MINIMR_ASSERT(payload != NULL);
    MINIMR_ASSERT(maxlen > 0);

    // from_addr is not really used

    size_t r = fread(payload, sizeof(uint8_t), maxlen, stdin);

    return r;
}

void print_hdr(struct minimr_dns_hdr * hdr){
    printf("hdr\n id %04x flag %02x%02x nq %04x nrr %04x narr %04x nexrr %04x\n", hdr->transaction_id, hdr->flags[0], hdr->flags[1], hdr->nqueries, hdr->nanswers, hdr->nauthrr, hdr->nextrarr);
}

uint8_t print_query(struct minimr_dns_hdr * hdr, struct minimr_dns_query_stat * qstat, uint8_t * msg, uint16_t msglen, uint8_t ifilter, void * user_data)
{
    uint8_t unicast = (qstat->unicast_class & MINIMR_DNS_QUNICAST);
    uint8_t glass = (qstat->unicast_class & ~MINIMR_DNS_QCLASS);

    uint8_t name[256] = "";
    int32_t namelen = minimr_dns_uncompress_name(name, sizeof(name), qstat->name_offset, msg, msglen);

    MINIMR_ASSERT(namelen >= 0);

    minimr_dns_denormalize_field(name, namelen, '.');

    printf("QUERY qtype %d (%s) unicast %d qclass %d qname (%d) %s\n", qstat->type, minimr_dns_type_str(qstat->type), unicast, glass, namelen, name);



    return MINIMR_CONTINUE;
}

uint8_t print_rr(struct minimr_dns_hdr * hdr, minimr_dns_rr_section section, struct minimr_dns_rr_stat * rstat, uint8_t * msg, uint16_t msglen, uint8_t ifilter, void * user_data)
{

    uint8_t * sectionstr;

    switch (section){
        case minimr_dns_rr_section_answer:
            sectionstr = (uint8_t*)"";
            break;
        case minimr_dns_rr_section_authority:
            sectionstr = (uint8_t*)"AUTH";
            break;
        case minimr_dns_rr_section_extra:
            sectionstr = (uint8_t*)"EXTRA";
            break;
    }

    uint8_t cacheflush = (rstat->cache_class & MINIMR_DNS_CACHEFLUSH) ? 1 : 0;
    uint8_t glass = (rstat->cache_class & MINIMR_DNS_RRCLASS);

    uint8_t name[256] = "";
    int32_t namelen = minimr_dns_uncompress_name(name, sizeof(name), rstat->name_offset, msg, msglen);

    MINIMR_ASSERT(namelen >= 0);

    minimr_dns_denormalize_field(name, namelen, '.');

    printf("%sRR rrtype %d (%s) cacheflush %d rrclass %d rrname (%d) %s rrdata (%d) ", sectionstr, rstat->type, minimr_dns_type_str(rstat->type), cacheflush, glass, namelen, name, rstat->dlength);

    for(uint16_t i = 0; i < rstat->dlength; i++){
        printf("%02x", msg[rstat->data_offset + i]);
    }

    printf("\n");

    return MINIMR_CONTINUE;
}

int main(int argc, char * argv[]){


    int opt;

    std::vector<uint8_t *> qfilters;
    std::vector<uint8_t *> rrfilters;

    while ((opt = getopt(argc, argv, "hq:r:")) != -1) {
        switch (opt) {
            case 'h':
            case '?':
                print_help(argv);
                return EXIT_SUCCESS;

            case 'q':
                minimr_dns_normalize_name((uint8_t*)optarg, NULL);
                qfilters.push_back((uint8_t*)optarg);
                break;

            case 'r':
                minimr_dns_normalize_name((uint8_t*)optarg, NULL);
                rrfilters.push_back((uint8_t*)optarg);
                break;

            default:
                printf("ERROR unrecognized option\n");
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

        int res = minimr_parse_msg(udp_payload, len,  print_query, &qfilters[0], qfilters.size(), print_rr, &rrfilters[0], rrfilters.size(), NULL);

        if (res != MINIMR_OK){
            printf("ERROR %d\n", res);
        }
    }

    return EXIT_SUCCESS;
}