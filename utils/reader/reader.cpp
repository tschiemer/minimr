//
// Created by Philip Tschiemer on 28.06.20.
//

#include <vector>
#include "minimr.h"

#include "getopt.h"

void print_help(char * argv[])
{
    printf("Usage: %s [-q <name>]* [-r <name>]*\n", argv[0]);
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
    uint8_t glass = (qstat->unicast_class & ~MINIMR_DNS_QUNICAST);

    uint8_t name[256] = "";
    int32_t namelen = minimr_dns_uncompress_name(name, sizeof(name), qstat->name_offset, msg, msglen);

    MINIMR_ASSERT(namelen >= 0);

    minimr_dns_denormalize_field(name, namelen, '.');

    printf("QUERY qtype %d unicast %d qclass %d qname (%d) %s\n", qstat->type, unicast, glass, namelen, name);



    return MINIMR_CONTINUE;
}

uint8_t print_rr(struct minimr_dns_hdr * hdr, minimr_dns_rr_section section, struct minimr_dns_rr_stat * rstat, uint8_t * msg, uint16_t msglen, uint8_t ifilter, void * user_data)
{
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