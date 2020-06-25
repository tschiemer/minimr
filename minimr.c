//
// Created by Philip Tschiemer on 25.06.20.
//

#include "minimr.h"

void minimr_dns_ntoh_hdr(struct minimr_dns_hdr *hdr, uint8_t *bytes) {
    hdr->transaction_id = (bytes[0] << 8) | bytes[1];
    hdr->flags[0] = bytes[2];
    hdr->flags[1] = bytes[3];
    hdr->nquestions = (bytes[4] << 8) | bytes[5]; // nquestions
    hdr->nanswers = (bytes[6] << 8) | bytes[7]; // nanswers
    hdr->nauthrr = (bytes[8] << 8) | bytes[9]; // nauthrr
    hdr->nextrarr = (bytes[10] << 8) | bytes[11]; // nextrarr
}

void minimr_dns_hton_hdr(uint8_t *bytes, struct minimr_dns_hdr *hdr) {
    bytes[0] = (hdr->transaction_id >> 8) & 0xff;
    bytes[1] = hdr->transaction_id & 0xff;
    bytes[2] = hdr->flags[0];
    bytes[3] = hdr->flags[1];
    bytes[4] = (hdr->nquestions >> 8) & 0xff;
    bytes[5] = hdr->nquestions & 0xff;
    bytes[6] = (hdr->nanswers >> 8) & 0xff;
    bytes[7] = hdr->nanswers & 0xff;
    bytes[8] = (hdr->nauthrr >> 8) & 0xff;
    bytes[9] = hdr->nauthrr & 0xff;
    bytes[10] = (hdr->nextrarr >> 8) & 0xff;
    bytes[11] = hdr->nextrarr & 0xff;
}

void minimr_dns_normalize_name(struct minimr_dns_rr * rr)
{
    ASSERT( rr != NULL );

    for(uint16_t i = 0; i < rr->name_length; i++){
        if (rr->name[i] == '.'){
            rr->name[i] = '\0';
        }
    }
}

void minimr_dns_normalize_txt(uint8_t * txt)
{
    ASSERT(txt != NULL);

    // this is not 100% safe, but it should only break if you configure something wrong

    for(uint16_t i = 0; txt[i] != '\0'; i++){

        // each txt part MUST begin with MINIMR_DNS_TXT_MARKER1/2
        ASSERT(txt[i] == MINIMR_DNS_TXT_MARKER1);
        ASSERT(txt[i+1] == MINIMR_DNS_TXT_MARKER2);

        // start with offset
        uint16_t l = 2;

        for(; txt[i+l] != '\0' && txt[i+l] != MINIMR_DNS_TXT_MARKER1 && txt[i+l+1] != MINIMR_DNS_TXT_MARKER2; l++){
            // just looking for end of part
        }

        // subtract original offset
        l -= 2;

        ASSERT(l > 0);

        // replace text markers with part size
        txt[i] = (l >> 8) & 0xff;
        txt[i+1] = l & 0xff;

        i += l;
    }
}

uint8_t minimr_dns_extract_query_stat(struct minimr_dns_query_stat * stat, uint8_t * msg, uint16_t * pos, uint16_t msglen)
{
    uint16_t p = *pos;

    // minlen = QNAME(3)[= <len> <name> NUL] QTYPE(2) UNICAST/QCLASS(2)
    if (p + 7 >= msglen){
        return MINIMR_NOT_OK;
    }

    for(; p < msglen && msg[p] != '\0'; p++){
        // just looking for the end of qname
        // note: it's not checked wether the qname is correctly formatted

        // fail if the name of a question is compressed.
        if ( (msg[p] & MINIMR_DNS_COMPRESSED_NAME) == MINIMR_DNS_COMPRESSED_NAME){
            return MINIMR_DNS_HDR2_RCODE_SERVAIL;
        }
    }

    // simple sanity check
    // did not go beyond msg
    // read at least 3 bytes?
    // remaining minlen = QTYPE(2) UNICAST/QCLASS(2)
    if (p >= msglen || p - *pos < 3 || p + 4 > msglen){
        return MINIMR_NOT_OK;
    }

    stat->name_offset = *pos;
    stat->name_length = p - *pos;

    stat->type = msg[p] << 8;
    stat->type |= msg[p++];

    stat->unicast_class = msg[p++] << 8;
    stat->unicast_class |= msg[p++];

    *pos = p;

    return MINIMR_OK;
}

uint8_t minimr_dns_extract_rr_stat(struct minimr_dns_rr_stat * stat, uint8_t * msg, uint16_t *pos, uint16_t msglen)
{
    uint16_t p = *pos;

    // minlen = QNAME(2) RRTYPE(2) CACHE/RRCLASS(2) TTL(4) RDLENGTH(2) + RDLENGTH
    if (p + 12 >= msglen){
        return MINIMR_NOT_OK;
    }


    if ( (msg[p] & MINIMR_DNS_COMPRESSED_NAME) == MINIMR_DNS_COMPRESSED_NAME){
        stat->name_offset = (MINIMR_DNS_COMPRESSED_NAME_OFFSET & msg[p++]) << 8;
        stat->name_offset |=  msg[p++];

        uint16_t name_pos = stat->name_offset;

        for(; name_pos < msglen && msg[name_pos] != '\0'; name_pos++){
            // just looking for the end of rrname
            // note: it's not checked wether the rrname is correctly formatted

            // do not allow recursive compression
            if ( (msg[name_pos] & MINIMR_DNS_COMPRESSED_NAME) == MINIMR_DNS_COMPRESSED_NAME){
                return MINIMR_DNS_HDR2_RCODE_SERVAIL;
            }
        }


        // simple sanity check
        // did not go beyond msg
        // read at least 3 bytes?
        if (name_pos >= msglen || name_pos - stat->name_offset < 3){
            return MINIMR_NOT_OK;
        }

        stat->name_length = name_pos - stat->name_offset;

    } else {
        stat->name_offset = p;

        for(; p < msglen && msg[p] != '\0'; p++){
            // just looking for the end of rrname
            // note: it's not checked wether the rrname is correctly formatted

            // do not allow partial name compression
            // fail if the name of a question is compressed.
            if ( (msg[p] & MINIMR_DNS_COMPRESSED_NAME) == MINIMR_DNS_COMPRESSED_NAME){
                return MINIMR_DNS_HDR2_RCODE_SERVAIL;
            }
        }

        // simple sanity check
        // did not go beyond msg
        // read at least 3 bytes?
        if (p >= msglen || p - *pos < 3 ){
            return MINIMR_NOT_OK;
        }

        stat->name_length = p - *pos;

        p++;
    }

    // minlen = RRTYPE(2) CACHE/RRCLASS(2) TTL(4) RDLENGTH(2) + RDLENGTH
    if (p + 10 >= msglen){
        return MINIMR_NOT_OK;
    }


    stat->type = msg[p++] << 8;
    stat->type |= msg[p++];

    stat->cache_class = msg[p++] << 8;
    stat->cache_class |= msg[p++];

    stat->ttl = msg[p++] << 24;
    stat->ttl |= msg[p++] << 16;
    stat->ttl |= msg[p++] << 8;
    stat->ttl |= msg[p++];

    stat->dlength = msg[p++] << 8;
    stat->dlength |= msg[p++];

    if (p + stat->dlength >= msglen){
        return MINIMR_NOT_OK;
    }

    stat->data_offset = p;

    *pos = p + stat->dlength;

    return MINIMR_OK;
}


uint8_t minimr_handle_msg(
        uint8_t * msg, uint16_t msglen,
        struct minimr_dns_query_stat qstats[], uint16_t nqstats,
        struct minimr_dns_rr ** records, uint16_t nrecords,
        uint8_t *outmsg, uint16_t * outmsglen, uint16_t outmsgmaxlen
)
{
    ASSERT(msg != NULL);
    ASSERT(qstats != NULL);
    ASSERT(nqstats > 0);
    ASSERT(records != NULL);
    ASSERT(nrecords > 0);
    ASSERT(outmsg != NULL);
    ASSERT(outmsglen != NULL);
    ASSERT(outmsgmaxlen > MINIMR_DNS_HDR_SIZE);


    // ignore messages that are not long enough to even have a complete header
    if (msglen < MINIMR_DNS_HDR_SIZE){
        return MINIMR_IGNORE;
    }

    struct minimr_dns_hdr hdr;

    // read header info
    minimr_dns_ntoh_hdr(&hdr, msg);


    // not a (standard) query? ignore
    // or no questions? nothing to do!
    if ( (hdr.flags[0] & MINIMR_DNS_HDR1_QR) != MINIMR_DNS_HDR1_QR_QUERY ||
         (hdr.flags[0] & MINIMR_DNS_HDR1_OPCODE) != MINIMR_DNS_HDR1_OPCODE_QUERY ||
         hdr.nquestions == 0){

        return MINIMR_IGNORE;
    }


    uint16_t pos = MINIMR_DNS_HDR_SIZE;
    uint16_t nq = 0;

    // note all relevant questions for us
    // stored in stats as 0 - nq
    for(uint16_t iq = 0; iq < hdr.nquestions && nq < nqstats && pos < msglen; iq++){

        uint8_t res = minimr_dns_extract_query_stat(&qstats[nq], msg, &pos, msglen);

        // in case of a server fail, pass this along
        if (res == MINIMR_DNS_HDR2_RCODE_SERVAIL) {
            return MINIMR_DNS_HDR2_RCODE_SERVAIL;
        }

        if (res != MINIMR_OK){
            // we could respond that it was a faulty query..
            return MINIMR_DNS_HDR2_RCODE_FORMERR;
        }

        for(uint16_t ir = 0; ir < nrecords; ir++){

            if (qstats[nq].type != records[ir]->type) continue;

            // unless ANY class was asked for check if classes match
            if ((qstats[nq].unicast_class & MINIMR_DNS_QCLASS) != MINIMR_DNS_CLASS_ANY &&
                    (qstats[nq].unicast_class & MINIMR_DNS_QCLASS) != (records[ir]->cache_class & MINIMR_DNS_RRCLASS) ) continue;

            // if name lengths don't match, there's no point checking names
            if (qstats[nq].name_length != records[ir]->name_length) continue;

            // pretty much a reverse memcmp of the name
            uint8_t found = 0;
            for(int32_t i = qstats[nq].name_length - 1; found == 0 && i > 0; i--){
                uint8_t * qname = &msg[qstats[nq].name_offset];
                if (qname[i] != records[ir]->name[i]){
                    found = 1;
                }
            }

            if (found == 0) continue;


            // so it's a match and we might consider responding
            // but let's remember this question and the matching record and let's go to the next question

            qstats[nq].relevant = 1;
            qstats[nq].ir = ir;

            nq++;

            break;
        }

    }

    // msg seems to be faulty, stop processing
    if (pos >= msglen){
        return MINIMR_DNS_HDR2_RCODE_FORMERR;
    }

    // no questions we need to answer
    if (nq == 0){
        return MINIMR_IGNORE;
    }

    // note how many questions we actually have to answer
    // (can change after checking the known answers)
    uint16_t remaining_nq = nq;

    // now check all known answers
    if (hdr.nanswers > 0){

        for(uint16_t ia = 0; ia < hdr.nanswers && nq < nqstats && pos < msglen; ia++){

            struct minimr_dns_rr_stat rstat;

            uint8_t res = minimr_dns_extract_rr_stat(&rstat, msg, &pos, msglen);

            // in case of a server fail, pass this along
            if (res == MINIMR_DNS_HDR2_RCODE_SERVAIL) {
                return MINIMR_DNS_HDR2_RCODE_SERVAIL;
            }

            if (res != MINIMR_OK){
                // we could respond that it was a faulty query..
                return MINIMR_DNS_HDR2_RCODE_FORMERR;
            }

            // check if the known answer relates to any of the relevant questions

            for(uint16_t iq = 0; iq < nq; iq++){

                // same type?
                if (rstat.type != qstats[iq].type) continue;

                // same class?
                if ((rstat.cache_class & MINIMR_DNS_RRCLASS) != (qstats[iq].unicast_class & MINIMR_DNS_QCLASS) ) continue;


                // only check name if name offsets do not match
                if (rstat.name_offset != qstats[iq].name_offset){

                    // if name lengths don't match, there's no point checking names
                    if (rstat.name_length != qstats[iq].name_length) continue;

                    uint8_t found = 0;

                    // pretty much a reverse memcmp of the name
                    for(int32_t i = rstat.name_length - 1; found == 0 && i > 0; i--){
                        uint8_t * rname = &msg[rstat.name_offset];
                        uint8_t * qname = &msg[qstats[iq].name_offset];
                        if (qname[i] != qname[i]){
                            found = 1;
                        }
                    }

                    if (found == 0) continue;
                }

                // so it's a match and we have to check wether it's up to date
                struct minimr_dns_rr * rr = records[qstats[iq].ir];
                if (rr->fun(minimr_dns_rr_fun_type_is_uptodate, rr, &rstat, msg) == MINIMR_UPTODATE){
                    qstats[iq].relevant = 0;
                    remaining_nq--;
                }

                break;
            }

        }

        // msg seems to be faulty, stop processing
        if (pos >= msglen){
            return MINIMR_DNS_HDR2_RCODE_FORMERR;
        }
    }

    // oh, all our records are known already! time for a coffee
    if (remaining_nq == 0){
        return MINIMR_IGNORE;
    }


    // sanity check config
    if (outmsgmaxlen <= MINIMR_DNS_HDR_SIZE){
        return MINIMR_DNS_HDR2_RCODE_SERVAIL;
    }


    uint16_t outlen = MINIMR_DNS_HDR_SIZE;

    uint16_t nanswers = 0;

    // add all normal answers RRs
    for(uint16_t iq = 0; iq < nq; iq++){

        // don't check questions that have become irrelevant
        if (qstats[iq].relevant == 0){
            continue;
        }

        struct minimr_dns_rr * rr = records[qstats[iq].ir];

        uint16_t nrr = 0;

        uint8_t res = rr->fun(minimr_dns_rr_fun_type_get_answer_rrs, rr, outmsg, &outlen, outmsgmaxlen, &nrr);

        if (res != MINIMR_OK){
            return MINIMR_DNS_HDR2_RCODE_SERVAIL;
        }

        nanswers += nrr;
    }

    // add all authority RRs
    uint16_t nauthrr = 0;
    for(uint16_t iq = 0; iq < nq; iq++){

        // don't check questions that have become irrelevant
        if (qstats[iq].relevant == 0){
            continue;
        }

        struct minimr_dns_rr * rr = records[qstats[iq].ir];

        uint16_t nrr = 0;

        uint8_t res = rr->fun(minimr_dns_rr_fun_type_get_authority_rrs, rr, outmsg, &outlen, outmsgmaxlen, &nrr);

        if (res != MINIMR_OK){
            return MINIMR_DNS_HDR2_RCODE_SERVAIL;
        }

        nauthrr += nrr;
    }

    // add all additional RRs
    uint16_t nextrarr = 0;
    for(uint16_t iq = 0; iq < nq; iq++){

        // don't check questions that have become irrelevant
        if (qstats[iq].relevant == 0){
            continue;
        }

        struct minimr_dns_rr * rr = records[qstats[iq].ir];

        uint16_t nrr = 0;

        uint8_t res = rr->fun(minimr_dns_rr_fun_type_get_authority_rrs, rr, outmsg, &outlen, outmsgmaxlen, &nrr);

        if (res != MINIMR_OK){
            return MINIMR_DNS_HDR2_RCODE_SERVAIL;
        }

        nextrarr += nrr;
    }

    // prepare outheader and out sanity check
    struct minimr_dns_hdr outhdr;

//    // memset outheader
//    for(int i = 0; i < sizeof(outhdr); i++){
//        *(uint8_t*)&outhdr = 0;
//    }

    // finalize header
    outhdr.transaction_id = hdr.transaction_id; // likely to be 0x0000 ....

    outhdr.flags[0] = MINIMR_DNS_HDR1_QR_REPLY | MINIMR_DNS_HDR1_AA;
    outhdr.flags[1] = MINIMR_DNS_HDR2_RCODE_NOERROR;

    outhdr.nquestions = 0;
    outhdr.nanswers = nanswers;
    outhdr.nauthrr = nauthrr;
    outhdr.nextrarr = nextrarr;

    // add header
    minimr_dns_hton_hdr(outmsg, &outhdr);

    return MINIMR_DNS_HDR2_RCODE_NOERROR;
}