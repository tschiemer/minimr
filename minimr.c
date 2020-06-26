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

    MINIMR_DEBUGF("hdr\n id %04x flag %02x%02x nq %04x nrr %04x narr %04x nexrr %04x\n", hdr->transaction_id, hdr->flags[0], hdr->flags[1], hdr->nquestions, hdr->nanswers, hdr->nauthrr, hdr->nextrarr);
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

    MINIMR_DEBUGF("hdr\n id %04x flag %02x%02x nq %04x nrr %04x narr %04x nexrr %04x\n", hdr->transaction_id, hdr->flags[0], hdr->flags[1], hdr->nquestions, hdr->nanswers, hdr->nauthrr, hdr->nextrarr);
}

void minimr_dns_normalize_field(uint8_t * field, uint16_t * length, uint8_t marker)
{
    MINIMR_ASSERT(field != NULL);
    MINIMR_ASSERT(length != NULL);

    uint16_t i = 0;

    while(field[i] != '\0'){

        MINIMR_ASSERT(field[i] == marker);

        uint16_t l = 1;

        for(; field[i+l] != '\0' && field[i+l] != marker; l++){
            // just looking for boundary
        }

        MINIMR_ASSERT(l > 0);

        field[i] = l - 1;

        i += l;
    }

    if (length != NULL){
        *length = i + 1;
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

    // move past NUL
    p ++;

    stat->name_offset = *pos;
    stat->name_length = p - *pos;


    stat->type = msg[p++] << 8;
    stat->type |= msg[p++];

    stat->unicast_class = msg[p++] << 8;
    stat->unicast_class |= msg[p++];

    *pos = p;

    MINIMR_DEBUGF("qstat\n type %d unicast %d class %d name_offset %d name_len %d\n", stat->type, stat->unicast_class & MINIMR_DNS_UNICAST, stat->unicast_class & MINIMR_DNS_QCLASS, stat->name_offset, stat->name_length);

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
    MINIMR_ASSERT(msg != NULL);
    MINIMR_ASSERT(qstats != NULL);
    MINIMR_ASSERT(nqstats > 0);
    MINIMR_ASSERT(records != NULL);
    MINIMR_ASSERT(nrecords > 0);
    MINIMR_ASSERT(outmsg != NULL);
    MINIMR_ASSERT(outmsglen != NULL);
    MINIMR_ASSERT(outmsgmaxlen > MINIMR_DNS_HDR_SIZE);

    MINIMR_DEBUGF("\nnew msg %p (len %d)\n", msg, msglen);

    MINIMR_DEBUGF("msglen check\n");

    // ignore messages that are not long enough to even have a complete header
    if (msglen < MINIMR_DNS_HDR_SIZE){
        return MINIMR_IGNORE;
    }

    struct minimr_dns_hdr hdr;

    // read header info
    minimr_dns_ntoh_hdr(&hdr, msg);

    MINIMR_DEBUGF("is standard query?\n");

    // not a (standard) query? ignore
    // or no questions? nothing to do!
    if ( (hdr.flags[0] & MINIMR_DNS_HDR1_QR) != MINIMR_DNS_HDR1_QR_QUERY ||
         (hdr.flags[0] & MINIMR_DNS_HDR1_OPCODE) != MINIMR_DNS_HDR1_OPCODE_QUERY ||
         hdr.nquestions == 0){

        return MINIMR_IGNORE;
    }


    uint16_t pos = MINIMR_DNS_HDR_SIZE;
    uint16_t nq = 0;

    MINIMR_DEBUGF("checking %d questions\n", hdr.nquestions);

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

        MINIMR_DEBUGF("comparing question %d with %d records\n", iq,nrecords);

        for(uint16_t ir = 0; ir < nrecords; ir++){

            // don't check if record not given
            if (records[ir] == NULL){
                continue;
            }

//            MINIMR_DEBUGF("check types %d == %d\n", qstats[nq].type, records[ir]->type);

            if (qstats[nq].type != records[ir]->type) continue;

//            MINIMR_DEBUGF("check class %d ANY or == %d\n", (qstats[nq].unicast_class & MINIMR_DNS_QCLASS), (records[ir]->cache_class & MINIMR_DNS_RRCLASS));

            // unless ANY class was asked for check if classes match
            if ((qstats[nq].unicast_class & MINIMR_DNS_QCLASS) != MINIMR_DNS_CLASS_ANY &&
                    (qstats[nq].unicast_class & MINIMR_DNS_QCLASS) != (records[ir]->cache_class & MINIMR_DNS_RRCLASS) ) continue;

//            MINIMR_DEBUGF("check len %d == %d\n", qstats[nq].name_length, records[ir]->name_length);

            // if name lengths don't match, there's no point checking names
            if (qstats[nq].name_length != records[ir]->name_length) continue;

//            MINIMR_DEBUGF("check name\n");

            // pretty much a reverse memcmp of the name
            uint8_t mismatch = 0;
            for(int32_t i = qstats[nq].name_length - 1; mismatch == 0 && i > 0; i--){
                uint8_t * qname = &msg[qstats[nq].name_offset];
                if (qname[i] != records[ir]->name[i]){
                    mismatch = 1;
                }

//                MINIMR_DEBUGF("%02x %02x\n", qname[i], records[ir]->name[i]);
            }

            if (mismatch) continue;


            // so it's a match and we might consider responding
            // but let's remember this question and the matching record and let's go to the next question

            qstats[nq].relevant = 1;
            qstats[nq].ir = ir;

            nq++;

            MINIMR_DEBUGF("question %d matches record %d\n", iq, ir);

            break;
        }

    }

    MINIMR_DEBUGF("got %d relevant questions\n", nq);

    // no questions we need to answer
    if (nq == 0){
        return MINIMR_IGNORE;
    }

    MINIMR_DEBUGF("checking known answers\n");

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

    MINIMR_DEBUGF("remaining questions %d\n", remaining_nq);

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

    MINIMR_DEBUGF("outlen %d\n", outlen);

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

    MINIMR_DEBUGF("added %d answer rr\n", nanswers);

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

    MINIMR_DEBUGF("added %d authority rr\n", nauthrr);

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

    MINIMR_DEBUGF("added %d extra rr\n", nextrarr);

    // prepare outheader and out sanity check
    struct minimr_dns_hdr outhdr;


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

    *outmsglen = outlen;

    return MINIMR_DNS_HDR2_RCODE_NOERROR;
}


uint8_t minimr_announce(
    struct minimr_dns_rr **records, uint16_t nrecords,
    uint8_t *outmsg, uint16_t *outmsglen, uint16_t outmsgmaxlen
)
{

    // sanity check config
    if (outmsgmaxlen <= MINIMR_DNS_HDR_SIZE){
        return MINIMR_DNS_HDR2_RCODE_SERVAIL;
    }


    uint16_t outlen = MINIMR_DNS_HDR_SIZE;

    uint16_t nanswers = 0;

    // add all normal answers RRs
    for(uint16_t i = 0; i < nrecords; i++){

        if (records[i] != NULL){
            continue;
        }

        uint16_t nrr = 0;

        uint8_t res = records[i]->fun(minimr_dns_rr_fun_type_get_answer_rrs, records[i], outmsg, &outlen, outmsgmaxlen, &nrr);

        if (res != MINIMR_OK){
            return MINIMR_DNS_HDR2_RCODE_SERVAIL;
        }

        nanswers += nrr;
    }

    MINIMR_DEBUGF("added %d answer rr\n", nanswers);

    // add all authority RRs
    uint16_t nauthrr = 0;
    for(uint16_t i = 0; i < nrecords; i++){

        if (records[i] != NULL){
            continue;
        }

        uint16_t nrr = 0;

        uint8_t res = records[i]->fun(minimr_dns_rr_fun_type_get_authority_rrs, records[i], outmsg, &outlen, outmsgmaxlen, &nrr);

        if (res != MINIMR_OK){
            return MINIMR_DNS_HDR2_RCODE_SERVAIL;
        }

        nauthrr += nrr;
    }

    MINIMR_DEBUGF("added %d authority rr\n", nauthrr);

    // add all additional RRs
    uint16_t nextrarr = 0;
    for(uint16_t i = 0; i < nrecords; i++){

        if (records[i] != NULL){
            continue;
        }

        uint16_t nrr = 0;

        uint8_t res = records[i]->fun(minimr_dns_rr_fun_type_get_authority_rrs, records[i], outmsg, &outlen, outmsgmaxlen, &nrr);

        if (res != MINIMR_OK){
            return MINIMR_DNS_HDR2_RCODE_SERVAIL;
        }

        nextrarr += nrr;
    }


    MINIMR_DEBUGF("added %d extra rr\n", nextrarr);

    // prepare outheader and out sanity check
    struct minimr_dns_hdr outhdr;

    // finalize header
    outhdr.transaction_id = 0;

    outhdr.flags[0] = MINIMR_DNS_HDR1_QR_REPLY | MINIMR_DNS_HDR1_AA;
    outhdr.flags[1] = MINIMR_DNS_HDR2_RCODE_NOERROR;

    outhdr.nquestions = 0;
    outhdr.nanswers = nanswers;
    outhdr.nauthrr = nauthrr;
    outhdr.nextrarr = nextrarr;

    // add header
    minimr_dns_hton_hdr(outmsg, &outhdr);

    *outmsglen = outlen;

    return MINIMR_DNS_HDR2_RCODE_NOERROR;
}


uint8_t minimr_terminate(
    struct minimr_dns_rr **records, uint16_t nrecords,
    uint8_t *outmsg, uint16_t *outmsglen, uint16_t outmsgmaxlen
)
{
    for(uint16_t i = 0; i < nrecords; i++){
        if (records[i] == NULL){
            continue;
        }
        records[i]->ttl = 0;
    }
    return minimr_announce(records, nrecords, outmsg, outmsglen, outmsgmaxlen);
}