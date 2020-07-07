//
// Created by Philip Tschiemer on 25.06.20.
//

#include "minimr.h"


const uint8_t * minimr_dns_type_tostr(uint16_t type)
{
    switch (type) {
        case MINIMR_DNS_TYPE_ANY:       return (uint8_t*)"ANY";
        case MINIMR_DNS_TYPE_A:         return (uint8_t*)"A";
        case MINIMR_DNS_TYPE_AAAA:      return (uint8_t*)"AAAA";
        case MINIMR_DNS_TYPE_SRV:       return (uint8_t*)"SRV";
        case MINIMR_DNS_TYPE_TXT:       return (uint8_t*)"TXT";
        case MINIMR_DNS_TYPE_PTR:       return (uint8_t*)"PTR";

    }
    return (uint8_t*)"?";
}

const uint8_t * minimr_dns_class_tostr(uint16_t glass)
{
    switch (glass) {
        case MINIMR_DNS_CLASS_ANY:       return (uint8_t*)"ANY";
        case MINIMR_DNS_CLASS_IN:         return (uint8_t*)"IN";

    }
    return (uint8_t*)"?";
}

#define _seq1_(lhs, rhs) ( lhs[0] == rhs[0] )
#define _seq2_(lhs, rhs) ( lhs[0] == rhs[0] && lhs[1] == rhs[1] )
#define _seq3_(lhs, rhs) ( lhs[0] == rhs[0] && lhs[1] == rhs[1] && lhs[2] == rhs[2] )
#define _seq4_(lhs, rhs) ( lhs[0] == rhs[0] && lhs[1] == rhs[1] && lhs[2] == rhs[2] && lhs[3] == rhs[4])

uint16_t minimr_dns_type_fromstr(uint8_t * typestr)
{
    // in decreasing order of length

    if (_seq4_(typestr, "AAAA"))    return MINIMR_DNS_TYPE_AAAA;

    if (_seq3_(typestr, "ANY"))     return MINIMR_DNS_TYPE_ANY;
    if (_seq3_(typestr, "SRV"))     return MINIMR_DNS_TYPE_SRV;
    if (_seq3_(typestr, "TXT"))     return MINIMR_DNS_TYPE_TXT;
    if (_seq3_(typestr, "PTR"))     return MINIMR_DNS_TYPE_PTR;

    if (_seq1_(typestr, "A"))       return MINIMR_DNS_TYPE_A;

    MINIMR_DEBUGF("type not recognized! %s\n", typestr);

    return 0;
}


uint16_t minimr_dns_class_fromstr(uint8_t * classstr)
{
    // in decreasing order of length
    if (_seq3_(classstr, "ANY"))     return MINIMR_DNS_CLASS_ANY;
    if (_seq2_(classstr, "IN"))       return MINIMR_DNS_CLASS_IN;

    MINIMR_DEBUGF("class not recognized! %s\n", classstr);

    return 0;
}

#undef _seq1_
#undef _seq2_
#undef _seq3_
#undef _seq4_



void minimr_dns_hdr_read(struct minimr_dns_hdr *hdr, uint8_t *src) {

    MINIMR_DNS_HDR_READ(src, hdr->transaction_id, hdr->flags[0], hdr->flags[1], hdr->nqueries, hdr->nanswers, hdr->nauthrr, hdr->nextrarr)

    MINIMR_DEBUGF("hdr\n id %04x flag %02x%02x nq %04x nrr %04x narr %04x nexrr %04x\n", hdr->transaction_id, hdr->flags[0], hdr->flags[1], hdr->nqueries, hdr->nanswers, hdr->nauthrr, hdr->nextrarr);
}

void minimr_dns_hdr_write(uint8_t *dst, struct minimr_dns_hdr *hdr) {

    MINIMR_DNS_HDR_WRITE(dst, hdr->transaction_id, hdr->flags[0], hdr->flags[1], hdr->nqueries, hdr->nanswers, hdr->nauthrr, hdr->nextrarr)

    MINIMR_DEBUGF("hdr\n id %04x flag %02x%02x nq %04x nrr %04x narr %04x nexrr %04x\n", hdr->transaction_id, hdr->flags[0], hdr->flags[1], hdr->nqueries, hdr->nanswers, hdr->nauthrr, hdr->nextrarr);
}

uint8_t minimr_extract_query_stat(struct minimr_query_stat * stat, uint8_t * msg, uint16_t * pos, uint16_t msglen)
{
    uint16_t p = *pos;

    // minlen = QNAME(2)[= <pointer>] QTYPE(2) UNICAST/QCLASS(2)
    if (p + 5 >= msglen){
//        MINIMR_DEBUGF("0 p %d msglen %d\n", p, msglen);
        return MINIMR_NOT_OK;
    }

    for(; p < msglen && msg[p] != '\0'; p++){
        // just looking for the end of rrname
        // note: it's not checked wether the rrname is correctly formatted

        if ( (msg[p] & MINIMR_DNS_COMPRESSED_NAME) == MINIMR_DNS_COMPRESSED_NAME){
            p ++;
//            MINIMR_DEBUGF("is jump\n");
            break;
        }

//        MINIMR_DEBUGF("p + %d\n", msg[p]);

        p += msg[p];
    }

    // simple sanity check
    // did not go beyond msg
    // read at least 1 bytes?
    if (p >= msglen || p == *pos ){
//        MINIMR_DEBUGF("1 *pos %d p %d msglen %d\n", *pos, p, msglen);
        return MINIMR_NOT_OK;
    }

//    stat->name_length = p - *pos;

    // move past last name byte (either NUL or second byte of pointer offset
    p++;

    stat->name_offset = *pos;

    stat->type = msg[p++] << 8;
    stat->type |= msg[p++];

    stat->unicast_class = msg[p++] << 8;
    stat->unicast_class |= msg[p++];

    *pos = p;

    // MINIMR_DEBUGF("qstat\n type %d unicast %d class %d name_offset %d\n", stat->type, (stat->unicast_class & MINIMR_DNS_QUNICAST) == MINIMR_DNS_QUNICAST, stat->unicast_class & MINIMR_DNS_QCLASS, stat->name_offset);

    return MINIMR_OK;
}

uint8_t minimr_extract_rr_stat(struct minimr_rr_stat * stat, uint8_t * msg, uint16_t *pos, uint16_t msglen)
{
    uint16_t p = *pos;

    // minlen = QNAME(2) RRTYPE(2) CACHE/RRCLASS(2) TTL(4) RDLENGTH(2) + RDLENGTH
    if (p + 11 >= msglen){
        return MINIMR_NOT_OK;
    }

    stat->name_offset = p;

    for(; p < msglen && msg[p] != '\0'; p++){
        // just looking for the end of rrname
        // note: it's not checked wether the rrname is correctly formatted

        if ( (msg[p] & MINIMR_DNS_COMPRESSED_NAME) == MINIMR_DNS_COMPRESSED_NAME){
            p ++;
//            MINIMR_DEBUGF("is jump\n");
            break;
        }

//        MINIMR_DEBUGF("p + %d\n", msg[p]);

        p += msg[p];
    }

    // simple sanity check
    // did not go beyond msg
    // read at least 1 bytes?
    if (p >= msglen || p == *pos ){
        return MINIMR_NOT_OK;
    }

    // minlen = RRTYPE(2) CACHE/RRCLASS(2) TTL(4) RDLENGTH(2) + RDLENGTH
    if (p + 10 >= msglen){
        return MINIMR_NOT_OK;
    }

    // move past last name byte (either NUL or second byte of pointer offset
    p++;

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

    if (p + stat->dlength > msglen){
        return MINIMR_NOT_OK;
    }

    stat->data_offset = p;

    *pos = p + stat->dlength;

    return MINIMR_OK;
}

int8_t minimr_dns_rr_lexcmp(uint16_t lhsclass, uint16_t lhstype, uint8_t * lhsrdata, uint16_t lhsrdatalen,
                            uint16_t rhsclass, uint16_t rhstype, uint8_t * rhsrdata, uint16_t rhsrdatalen)
{
    if ( (lhsclass & MINIMR_DNS_QCLASS) < (rhsclass & MINIMR_DNS_QCLASS)) return -1;
    if ( (lhsclass & MINIMR_DNS_QCLASS) > (rhsclass & MINIMR_DNS_QCLASS)) return 1;

    if ( lhstype < rhstype) return -1;
    if ( lhstype > rhstype ) return 1;

    uint16_t len = lhsrdatalen < rhsrdatalen ? lhsrdatalen : rhsrdatalen;

    uint16_t i = 0;
    for (; i < len; i++){
        if (lhsrdata[i] < rhsrdata[i]) return -1;
        if (lhsrdata[i] > rhsrdata[i]) return 1;
    }

    //
    if (lhsrdatalen < rhsrdatalen) return -1;
    if (lhsrdatalen > rhsrdatalen) return 1;

    return 0;
}

void minimr_field_normalize(uint8_t * field, uint16_t * length, uint8_t marker)
{
    MINIMR_ASSERT(field != NULL);

    // if first byte does not match marker, we assume the field has already been normalized
    // note: this could the source of an error where the field to be normalized in fact was just wrongly formatted..
    if (field[0] != marker){
        MINIMR_DEBUGF("WARNING first byte of field to be normalized is not marker '%c' - assumed to be normalized alread\n", marker);
        return;
    }

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

void minimr_field_denormalize(uint8_t * field, uint16_t length, uint8_t marker)
{
    MINIMR_ASSERT(field != NULL);
    uint8_t seglen;
    for(uint16_t pos = 0; pos < length; pos += seglen + 1){
        seglen = field[pos];
        field[pos] = marker;
    }
}

//uint8_t minimr_dns_name_len(uint16_t namepos, uint8_t * msg, uint16_t msglen, uint8_t * namelen, uint8_t * bytelen)
//{
//    return MINIMR_OK;
//}


int32_t minimr_name_cmp(uint8_t * uncompressed_name, uint16_t namepos, uint8_t * msg, uint16_t msglen)
{
    MINIMR_ASSERT(uncompressed_name != NULL);
    MINIMR_ASSERT(msg != NULL);
    MINIMR_ASSERT(msglen > 0);
    MINIMR_ASSERT(namepos < msglen);

    uint16_t len = 0;

    uint8_t njumps = 0;

    while (uncompressed_name[len] != '\0' && namepos < msglen && msg[namepos] != '\0'){

        // is name compressed? jump
        if ((msg[namepos] & MINIMR_DNS_COMPRESSED_NAME) == MINIMR_DNS_COMPRESSED_NAME){

            uint16_t offset;

            // is pointer to pointer?????
            do {

                // is offset address in msg?
                if (namepos+1 >= msglen){
                    return -1;
                }

                offset = ((msg[namepos] & MINIMR_DNS_COMPRESSED_NAME_OFFSET) << 8) | msg[namepos+1];

                njumps++;

//                MINIMR_DEBUGF("jumping (%d) to %d\n", njumps, offset);

                // evil (or faulty) messages can loop
                if (njumps > MINIMR_COMPRESSION_MAX_JUMPS){
                    return -1;
                }

                // actually make jump
                namepos = offset;

            } while ((msg[namepos] & MINIMR_DNS_COMPRESSED_NAME) == MINIMR_DNS_COMPRESSED_NAME);


            // repeat
            continue;
        }

        uint8_t seglen = uncompressed_name[len];


//        MINIMR_DEBUGF("2 namepos %d seglen %d\n", namepos, seglen);

        for(uint8_t i = 0; i <= seglen && namepos < msglen; i++){
            uint8_t lhs = uncompressed_name[len++];
            uint8_t rhs = msg[namepos++];

            #define LOWERCASE(c) ( ('A' <= (c) && (c) <= 'Z') ? ((c) - 'A' + 'a' ) : (c) )
            lhs = LOWERCASE(lhs);
            rhs = LOWERCASE(rhs);
            #undef LOWERCASE

            if (lhs < rhs) return -1;
            if (lhs > rhs) return 1;
        }
    }

    if (namepos >= msglen){
        return 1;
    }

    // if both are equal, both are NUL
    if (uncompressed_name[len] == msg[namepos]) return 0;

    if (uncompressed_name[len] == '\0') return -1;

    return 1;
}

int32_t minimr_name_uncompress(uint8_t * uncompressed_name, uint16_t maxlen, uint16_t namepos, uint8_t * msg, uint8_t msglen)
{
    MINIMR_ASSERT(uncompressed_name != NULL);
    MINIMR_ASSERT(maxlen > 0);
    MINIMR_ASSERT(msg != NULL);
    MINIMR_ASSERT(msglen > 0);
    MINIMR_ASSERT(namepos < msglen);

    uint16_t len = 0;

    uint8_t njumps = 0;

    while (len < maxlen && namepos < msglen && msg[namepos] != '\0'){

        // is name compressed? jump
        if ((msg[namepos] & MINIMR_DNS_COMPRESSED_NAME) == MINIMR_DNS_COMPRESSED_NAME){

            uint16_t offset;

            // is pointer to pointer?????
            do {

//                MINIMR_DEBUGF("is jump\n");

                // is offset address in msg?
                if (namepos+1 >= msglen){
                    return -1;
                }

                offset = ((msg[namepos] & MINIMR_DNS_COMPRESSED_NAME_OFFSET) << 8) | msg[namepos+1];

                njumps++;

//                MINIMR_DEBUGF("jumping (%d) to %d\n", njumps, offset);

                // evil (or faulty) messages can loop
                if (njumps > MINIMR_COMPRESSION_MAX_JUMPS){
                    return -1;
                }

                // actually make jump
                namepos = offset;

            } while ((msg[namepos] & MINIMR_DNS_COMPRESSED_NAME) == MINIMR_DNS_COMPRESSED_NAME);


            // repeat
            continue;
        }

        uint8_t seglen = msg[namepos];

        if (namepos + seglen >= msglen){
            return -1;
        }

        // seglen
        uncompressed_name[len++] = msg[namepos++];

        for (uint8_t i = 0; i < seglen; i++){
            uncompressed_name[len++] = msg[namepos++];
        }
    }

    if (len >= maxlen || namepos >= msglen){
        return -1;
    }

    uncompressed_name[len] = '\0';

    return len;
}


int32_t  minimr_parse_msg(
        uint8_t *msg, uint16_t msglen,
        minimr_msgtype msgtype,
        minimr_query_handler qhandler, struct minimr_filter * qfilters, uint16_t nqfilters,
        minimr_rr_handler rrhandler, struct minimr_filter * rrfilters, uint16_t nrrfilters,
        void * user_data
)
{
    MINIMR_ASSERT(msg != NULL);
    MINIMR_ASSERT(nqfilters == 0 || qfilters != NULL);
    MINIMR_ASSERT(nrrfilters == 0 || rrfilters != NULL);
    MINIMR_ASSERT(qhandler != NULL && rrhandler != NULL); // doesn't make any sense not to use any handler at all.

//    MINIMR_DEBUGF("\nnew msg %p (len %d)\n", msg, msglen);
//
//    MINIMR_DEBUGF("msglen check\n");

    // ignore messages that are not long enough to even have a complete header
    if (msglen < MINIMR_DNS_HDR_SIZE){
        return MINIMR_OK;
    }

    struct minimr_dns_hdr hdr;

    // read header info
    minimr_dns_hdr_read(&hdr, msg);

    // if asked for specific type but other at hand, abort
    if ((msgtype == minimr_msgtype_query && (hdr.flags[0] & MINIMR_DNS_HDR1_QR) == MINIMR_DNS_HDR1_QR_REPLY )
        || (msgtype == minimr_msgtype_response && (hdr.flags[0] & MINIMR_DNS_HDR1_QR) == MINIMR_DNS_HDR1_QR_REPLY )){
        return MINIMR_OK;
    }

    uint16_t pos = MINIMR_DNS_HDR_SIZE;

    for(uint16_t iq = 0; iq < hdr.nqueries && pos < msglen; iq++){

        struct minimr_query_stat qstat;

        uint8_t res = minimr_extract_query_stat(&qstat, msg, &pos, msglen);

        // in case of a server fail, pass this along
        if (res == MINIMR_DNS_HDR2_RCODE_SERVAIL) {
            return MINIMR_DNS_HDR2_RCODE_SERVAIL;
        }

        if (res != MINIMR_OK){
            // we could respond that it was a faulty query..
            return MINIMR_DNS_HDR2_RCODE_FORMERR;
        }

        if (qhandler == NULL){
            continue;
        }


        uint8_t cont = MINIMR_CONTINUE;

        if (nqfilters == 0){
            cont = qhandler(&hdr, &qstat, msg, msglen, user_data);
        } else {

            for (uint16_t i = 0; i < nqfilters; i++){

                MINIMR_ASSERT(qfilters[i].name != NULL);

                // type match?
                if (qfilters[i].type != MINIMR_DNS_TYPE_ANY && qstat.type != MINIMR_DNS_TYPE_ANY && qfilters[i].type != qstat.type){
                    continue;
                }

                // class match?
                if (qfilters[i].fclass != MINIMR_DNS_CLASS_ANY && (qstat.unicast_class & MINIMR_DNS_QCLASS) != MINIMR_DNS_CLASS_ANY && qfilters[i].fclass != (qstat.unicast_class & MINIMR_DNS_QCLASS) ){
                    continue;
                }

                if (minimr_name_cmp(qfilters[i].name, qstat.name_offset, msg, msglen) == 0){

                    qstat.match_i = i;

                    // pass to user rr handler
                    cont = qhandler(&hdr, &qstat, msg, msglen, user_data);
                }
            }
        }

        if (cont != MINIMR_CONTINUE){
            return MINIMR_OK;
        }
    }


    // msg seems to be faulty, stop processing
    if (pos > msglen){
        return MINIMR_DNS_HDR2_RCODE_FORMERR;
    }

    if (pos == msglen){
        return MINIMR_OK;
    }

    // if we're not interested in records, skip further processing
    if (rrhandler == NULL){
        return MINIMR_OK;
    }

    MINIMR_DEBUGF("checking %d rr, %d authrr, %d extrarr\n", hdr.nanswers, hdr.nauthrr, hdr.nextrarr);

    uint16_t nrr = hdr.nanswers + hdr.nauthrr + hdr.nextrarr;
    minimr_rr_section section = minimr_rr_section_answer;
    uint16_t section_until = hdr.nanswers;

    for(uint16_t ir = 0; ir < nrr && pos < msglen; ir++){

        struct minimr_rr_stat rstat;

        uint8_t res = minimr_extract_rr_stat(&rstat, msg, &pos, msglen);

        // in case of a server fail, pass this along
        if (res == MINIMR_DNS_HDR2_RCODE_SERVAIL) {
            return MINIMR_DNS_HDR2_RCODE_SERVAIL;
        }

        if (res != MINIMR_OK){
            // we could respond that it was a faulty query..
            return MINIMR_DNS_HDR2_RCODE_FORMERR;
        }

        if (section == minimr_rr_section_answer && ir >= section_until){
            section = minimr_rr_section_authority;
            section_until += hdr.nauthrr;
        }
        if (section == minimr_rr_section_authority && ir >= section_until){
            section = minimr_rr_section_extra;
        }

        uint8_t cont = MINIMR_CONTINUE;

        // if any filter records were given, just look for these
        if (nrrfilters == 0) {
            cont = rrhandler(&hdr, section, &rstat, msg, msglen, user_data);
        } else {
            for (uint16_t i = 0; i < nrrfilters; i++){

                MINIMR_ASSERT(rrfilters[i].name != NULL);

                // type match?
                if (rrfilters[i].type != MINIMR_DNS_TYPE_ANY && rrfilters[i].type != rstat.type){
                    continue;
                }
                // class match?
                if (rrfilters[i].fclass != MINIMR_DNS_CLASS_ANY && rrfilters[i].fclass != (rstat.cache_class & MINIMR_DNS_RRCLASS) ){
                    continue;
                }

                if (minimr_name_cmp(rrfilters[i].name, rstat.name_offset, msg, msglen) == 0){

                    rstat.match_i = i;

                    // pass to user rr handler
                    cont = rrhandler(&hdr, section, &rstat, msg, msglen, user_data);
                }
            }
        }

        if (cont != MINIMR_CONTINUE){
            return MINIMR_OK;
        }
    }


    return MINIMR_OK;
}

int32_t  minimr_make_msg(
        uint16_t tid, uint8_t flag1, uint8_t flag2,
        struct minimr_query * queries, uint16_t nqueries,
        struct minimr_rr ** answerrr, uint16_t nanswers,
        struct minimr_rr ** authrr, uint16_t nauthrr,
        struct minimr_rr ** extrarr, uint16_t nextrarr,
        uint8_t *outmsg, uint16_t *outmsglen, uint16_t outmsgmaxlen,
        void * user_data
)
{
    MINIMR_ASSERT(nqueries == 0 || queries != NULL);
    MINIMR_ASSERT(nanswers == 0 || answerrr != NULL);
    MINIMR_ASSERT(nauthrr == 0 || authrr != NULL);
    MINIMR_ASSERT(nextrarr == 0 || extrarr != NULL);
    MINIMR_ASSERT(outmsg != NULL);
    MINIMR_ASSERT(outmsglen != NULL);


    // sanity check config
    if (outmsgmaxlen <= MINIMR_DNS_HDR_SIZE){
        return MINIMR_DNS_HDR2_RCODE_SERVAIL;
    }


    uint16_t outlen = MINIMR_DNS_HDR_SIZE;

    for (uint16_t i = 0; i < nqueries; i++){

        MINIMR_ASSERT(queries[i].name != NULL);

        for(uint16_t j = 0; queries[i].name[j] != '\0'; j++){
            if (outlen > outmsgmaxlen){
                return MINIMR_DNS_HDR2_RCODE_SERVAIL;
            }
            outmsg[outlen++] = queries[i].name[j];

            // MINIMR_DEBUGF("%02x ", queries[i].name[j]);
        }
        // MINIMR_DEBUGF("\n");

        if (outlen + 5 > outmsgmaxlen){
            return MINIMR_DNS_HDR2_RCODE_SERVAIL;
        }

        // name termination
        outmsg[outlen++] = '\0';

        MINIMR_DNS_Q_WRITE_TYPE( outmsg, outlen, queries[i].type);
        MINIMR_DNS_Q_WRITE_CLASS( outmsg, outlen, queries[i].unicast_class );
    }

    MINIMR_DEBUGF("added %d queries\n", nqueries);

    uint16_t final_nanswers = 0; // needed because there might be NULL entries

    // add all normal answers RRs
    for(uint16_t i = 0; i < nanswers; i++){

        if (answerrr[i] == NULL){
            continue;
        }

        uint16_t nrr = 0;

        //minimr_rr_fun_handler( minimr_rr_fun_get_rr, struct minimr_rr * rr,  uint8_t * outmsg, uint16_t * outlen, uint16_t outmsgmaxlen, uint16_t * nrr, void * user_data)
        uint8_t res = answerrr[i]->MINIMR_RR_FUN_GET_RR(answerrr[i], outmsg, &outlen, outmsgmaxlen, &nrr, user_data);

        if (res != MINIMR_OK){
            return MINIMR_DNS_HDR2_RCODE_SERVAIL;
        }

        final_nanswers += nrr;
    }

    MINIMR_DEBUGF("added %d known answer rr\n", nanswers);

    uint16_t final_nauthrr = 0;

    // add all normal answers RRs
    for(uint16_t i = 0; i < nauthrr; i++){

        if (authrr[i] == NULL){
            continue;
        }

        uint16_t nrr = 0;

        uint8_t res = authrr[i]->MINIMR_RR_FUN_GET_RR(authrr[i], outmsg, &outlen, outmsgmaxlen, &nrr, user_data);

        if (res != MINIMR_OK){
            return MINIMR_DNS_HDR2_RCODE_SERVAIL;
        }

        final_nauthrr += nrr;
    }

    MINIMR_DEBUGF("added %d extra rr\n", nauthrr);

    uint16_t final_nextrarr = 0;

    // add all normal answers RRs
    for(uint16_t i = 0; i < nextrarr; i++){

        if (extrarr[i] == NULL){
            continue;
        }

        uint16_t nrr = 0;

        uint8_t res = extrarr[i]->MINIMR_RR_FUN_GET_RR(extrarr[i], outmsg, &outlen, outmsgmaxlen, &nrr, user_data);

        if (res != MINIMR_OK){
            return MINIMR_DNS_HDR2_RCODE_SERVAIL;
        }

        final_nextrarr += nrr;
    }

    MINIMR_DEBUGF("added %d extra rr\n", nextrarr);

    // prepare outheader and out sanity check
    struct minimr_dns_hdr outhdr;

    // finalize header
    outhdr.transaction_id = tid;

    // set QR flag depending on queries given
    flag1 = (flag1 & ~MINIMR_DNS_HDR1_QR) | (nqueries ? MINIMR_DNS_HDR1_QR_QUERY : MINIMR_DNS_HDR1_QR_REPLY);

    // note: the AA flag is not set by default (because maybe, maybe you don't want to send an authorative answer ;)

    outhdr.flags[0] = flag1;
    outhdr.flags[1] = flag2;

    outhdr.nqueries = nqueries;
    outhdr.nanswers = final_nanswers;
    outhdr.nauthrr = final_nauthrr;
    outhdr.nextrarr = final_nextrarr;

    // add header
    minimr_dns_hdr_write(outmsg, &outhdr);

    *outmsglen = outlen;

    return MINIMR_OK;
}

int32_t minimr_probequery_msg(
        uint8_t * name1,
        uint8_t * name2,
        struct minimr_rr ** proposed_rrs, uint16_t nproposed_rrs,
        uint8_t *outmsg, uint16_t *outmsglen, uint16_t outmsgmaxlen,
        uint8_t request_unicast,
        void * user_data
)
{
    MINIMR_ASSERT(name1 != NULL);
    MINIMR_ASSERT(proposed_rrs != NULL);
    MINIMR_ASSERT(nproposed_rrs > 0);

    struct minimr_query queries[2];

    queries[0].unicast_class = MINIMR_DNS_CLASS_IN | (request_unicast ? MINIMR_DNS_QUNICAST : 0);
    queries[0].type = MINIMR_DNS_TYPE_ANY;
    queries[0].name = name1;

    uint16_t nqueries = 1;

    if (name2 != NULL){
        queries[1].unicast_class = MINIMR_DNS_CLASS_IN | (request_unicast ? MINIMR_DNS_QUNICAST : 0);
        queries[1].type = MINIMR_DNS_TYPE_ANY;
        queries[1].name = name2;
        nqueries++;
    }

    return minimr_make_msg(
            0, 0, 0, // no special header
            queries, nqueries,
            NULL, 0, // no answer rrs
            proposed_rrs, nproposed_rrs, // proposed records in auth section
            NULL, 0, // no extra rrs
            outmsg, outmsglen, outmsgmaxlen,
            user_data
    );
}


int32_t minimr_query_msg(
        uint8_t * name1,
        uint8_t * name2,
        struct minimr_rr ** knownanswer_rrs, uint16_t nknownanswer_rrs,
        uint8_t *outmsg, uint16_t *outmsglen, uint16_t outmsgmaxlen,
        uint8_t request_unicast,
        void * user_data
)
{
    MINIMR_ASSERT(name1 != NULL);
    MINIMR_ASSERT(nknownanswer_rrs == 0 | knownanswer_rrs != NULL);

    struct minimr_query queries[2];

    queries[0].type = MINIMR_DNS_TYPE_ANY;
    queries[0].unicast_class = MINIMR_DNS_CLASS_IN | (request_unicast ? MINIMR_DNS_QUNICAST : 0);
    queries[0].name = name1;

    uint16_t nqueries = 1;

    if (name2 != NULL){
        queries[1].type = MINIMR_DNS_TYPE_ANY;
        queries[1].unicast_class = MINIMR_DNS_CLASS_IN | (request_unicast ? MINIMR_DNS_QUNICAST : 0);
        queries[1].name = name2;
    }

    return minimr_make_msg(
            0, 0, 0, // no special header
            queries, nqueries,
            knownanswer_rrs, nknownanswer_rrs,
            NULL, 0, // no auth rrs
            NULL, 0, // no extra rrs
            outmsg, outmsglen, outmsgmaxlen,
            user_data
    );
}

int32_t minimr_announce_msg(
    struct minimr_rr **records, uint16_t nrecords,
    uint8_t *outmsg, uint16_t *outmsglen, uint16_t outmsgmaxlen,
    void * user_data
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

        if (records[i] == NULL){
            continue;
        }

        uint16_t nrr = 0;

        //minimr_rr_fun_handler( minimr_rr_fun_announce_get_*, struct minimr_rr * rr, uint8_t * outmsg, uint16_t * outlen, uint16_t outmsgmaxlen, uint16_t * nrr, void * user_data)
        uint8_t res = records[i]->MINIMR_RR_FUN_ANNOUNCE_GET_RR( records[i], outmsg, &outlen, outmsgmaxlen, &nrr, user_data);

        if (res != MINIMR_OK){
            return MINIMR_DNS_HDR2_RCODE_SERVAIL;
        }

        nanswers += nrr;
    }

    MINIMR_DEBUGF("added %d answer rr\n", nanswers);

    // add all additional RRs
    uint16_t nextrarr = 0;
    for(uint16_t i = 0; i < nrecords; i++){

        // don't check questions that have become irrelevant
        if (records[i] == NULL){
            continue;
        }

        uint16_t nrr = 0;

        //minimr_rr_fun_handler( minimr_rr_fun_announce_get_*, struct minimr_rr * rr, uint8_t * outmsg, uint16_t * outlen, uint16_t outmsgmaxlen, uint16_t * nrr, void * user_data)
        uint8_t res = records[i]->MINIMR_RR_FUN_ANNOUNCE_GET_EXTRA_RRS( records[i], outmsg, &outlen, outmsgmaxlen, &nrr, user_data);

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

    outhdr.nqueries = 0;
    outhdr.nanswers = nanswers;
    outhdr.nauthrr = 0;
    outhdr.nextrarr = nextrarr;

    // add header
    minimr_dns_hdr_write(outmsg, &outhdr);

    *outmsglen = outlen;

    return MINIMR_DNS_HDR2_RCODE_NOERROR;
}


int32_t minimr_terminate_msg(
    struct minimr_rr **records, uint16_t nrecords,
    uint8_t *outmsg, uint16_t *outmsglen, uint16_t outmsgmaxlen,
    void * user_data
)
{
    for(uint16_t i = 0; i < nrecords; i++){
        if (records[i] == NULL){
            continue;
        }
        records[i]->ttl = 0;
    }
    return minimr_announce_msg(records, nrecords, outmsg, outmsglen, outmsgmaxlen, user_data);
}





int32_t minimr_query_response_msg(
        uint8_t * msg, uint16_t msglen,
        struct minimr_query_stat qstats[], uint16_t nqstats,
        struct minimr_rr ** records, uint16_t nrecords,
        uint8_t *outmsg, uint16_t * outmsglen, uint16_t outmsgmaxlen,
        uint8_t *unicast_requested,
        void * user_data
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

    // MINIMR_DEBUGF("\nnew msg %p (len %d)\n", msg, msglen);

    // MINIMR_DEBUGF("msglen check\n");

    // ignore messages that are not long enough to even have a complete header
    if (msglen < MINIMR_DNS_HDR_SIZE){
        return MINIMR_IGNORE;
    }

    struct minimr_dns_hdr hdr;

    // read header info
    minimr_dns_hdr_read(&hdr, msg);

    // MINIMR_DEBUGF("is standard query?\n");

    // not a (standard) query? ignore
    // or no questions? nothing to do!
    if ( (hdr.flags[0] & MINIMR_DNS_HDR1_QR) != MINIMR_DNS_HDR1_QR_QUERY ||
         (hdr.flags[0] & MINIMR_DNS_HDR1_OPCODE) != MINIMR_DNS_HDR1_OPCODE_QUERY ||
         hdr.nqueries == 0){

        return MINIMR_IGNORE;
    }


    uint16_t pos = MINIMR_DNS_HDR_SIZE;
    uint16_t nq = 0;

    // MINIMR_DEBUGF("checking %d questions\n", hdr.nqueries);

    // note all relevant questions for us
    // stored in stats as 0 - nq
    for(uint16_t iq = 0; iq < hdr.nqueries && nq < nqstats && pos < msglen; iq++){

        uint8_t res = minimr_extract_query_stat(&qstats[nq], msg, &pos, msglen);

        // in case of a server fail, pass this along
        if (res == MINIMR_DNS_HDR2_RCODE_SERVAIL) {
            return MINIMR_DNS_HDR2_RCODE_SERVAIL;
        }

        if (res != MINIMR_OK){
            // we could respond that it was a faulty query..
            return MINIMR_DNS_HDR2_RCODE_FORMERR;
        }

        // MINIMR_DEBUGF("comparing question %d with %d records\n", iq,nrecords);

        for(uint16_t ir = 0; ir < nrecords; ir++){

            // don't check if record not given
            if (records[ir] == NULL){
                continue;
            }

//            MINIMR_DEBUGF("check types %d == %d\n", qstats[nq].type, records[ir]->type);

            if (qstats[nq].type != MINIMR_DNS_TYPE_ANY && qstats[nq].type != records[ir]->type) continue;

//            MINIMR_DEBUGF("check class %d ANY or == %d\n", (qstats[nq].unicast_class & MINIMR_DNS_QCLASS), (records[ir]->cache_class & MINIMR_DNS_RRCLASS));

            // unless ANY class was asked for check if classes match
            if ((qstats[nq].unicast_class & MINIMR_DNS_QCLASS) != MINIMR_DNS_CLASS_ANY &&
                (qstats[nq].unicast_class & MINIMR_DNS_QCLASS) != (records[ir]->cache_class & MINIMR_DNS_RRCLASS) ) continue;


            // if name lengths don't match, there's no point checking names
           res = minimr_name_cmp(records[ir]->name, qstats[nq].name_offset, msg, msglen);

            if (res != 0) continue;

            // so it's a match and we might consider responding
            // but let's remember this question and the matching record and let's go to the next question

            qstats[nq].relevant = 1;
            qstats[nq].match_i = ir;

            nq++;

            // MINIMR_DEBUGF("question %d matches record %d\n", iq, ir);

            break;
        }

    }

    // MINIMR_DEBUGF("got %d relevant questions\n", nq);

    // no questions we need to answer
    if (nq == 0){
        return MINIMR_IGNORE;
    }

    // init to false;
    uint8_t unicast_req = 0;

    // MINIMR_DEBUGF("checking known answers\n");

    // note how many questions we actually have to answer
    // (can change after checking the known answers)
    uint16_t remaining_nq = nq;

    // now check all known answers
    if (hdr.nanswers > 0){

        for(uint16_t ia = 0; ia < hdr.nanswers && nq < nqstats && pos < msglen; ia++){

            struct minimr_rr_stat rstat;

            uint8_t res = minimr_extract_rr_stat(&rstat, msg, &pos, msglen);

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
                    res = minimr_name_cmp(records[qstats[iq].match_i]->name, qstats[iq].name_offset, msg, msglen);

                    if (res != 0) continue;
                }

                // so it's a match and we have to check wether it's up to date
                struct minimr_rr * rr = records[qstats[iq].match_i];

                //minimr_rr_fun_handler(minimr_rr_fun_query_respond_to, struct minimr_rr * rr, void * user_data)
                if (rr->MINIMR_RR_FUN_QUERY_RESPOND_TO(rr, user_data) == MINIMR_DO_NOT_RESPOND){
                    qstats[iq].relevant = 0;
                    remaining_nq--;
                } else if ((qstats[iq].unicast_class & MINIMR_DNS_QUNICAST) == MINIMR_DNS_QUNICAST) {
                    unicast_req = 1;
                }

                break;
            }

        }

        // msg seems to be faulty, stop processing
        if (pos >= msglen){
            return MINIMR_DNS_HDR2_RCODE_FORMERR;
        }
    }

    // MINIMR_DEBUGF("remaining questions %d\n", remaining_nq);

    // oh, all our records are known already! time for a coffee
    if (remaining_nq == 0){
        return MINIMR_IGNORE;
    }


    // sanity check config
    if (outmsgmaxlen <= MINIMR_DNS_HDR_SIZE){
        return MINIMR_DNS_HDR2_RCODE_SERVAIL;
    }

    // MINIMR_DEBUGF("unicast requested %d\n", unicast_req);
    if (unicast_requested != NULL){
        *unicast_requested = unicast_req;
    }


    uint16_t outlen = MINIMR_DNS_HDR_SIZE;

    uint16_t nanswers = 0;

    // MINIMR_DEBUGF("outlen %d\n", outlen);

    // add all normal answers RRs
    for(uint16_t iq = 0; iq < nq; iq++){

        // don't check questions that have become irrelevant
        if (qstats[iq].relevant == 0){
            continue;
        }

        struct minimr_rr * rr = records[qstats[iq].match_i];

        uint16_t nrr = 0;

        //minimr_rr_fun_handler( minimquery_get_*, struct minimr_rr * rr, struct minimr_query_stat * qstat, uint8_t * outmsg, uint16_t * outlen, uint16_t outmsgmaxlen, uint16_t * nrr, void * user_data)
        uint8_t res = rr->MINIMR_RR_FUN_QUERY_GET_RR(rr, &qstats[iq], outmsg, &outlen, outmsgmaxlen, &nrr, user_data);

        if (res != MINIMR_OK){
            return MINIMR_DNS_HDR2_RCODE_SERVAIL;
        }

        nanswers += nrr;
    }

    // MINIMR_DEBUGF("added %d answer rr\n", nanswers);

    // add all authority RRs
    uint16_t nauthrr = 0;
    for(uint16_t iq = 0; iq < nq; iq++){

        // don't check questions that have become irrelevant
        if (qstats[iq].relevant == 0){
            continue;
        }

        struct minimr_rr * rr = records[qstats[iq].match_i];

        uint16_t nrr = 0;

        //minimr_rr_fun_handler( minimquery_get_*, struct minimr_rr * rr, struct minimr_query_stat * qstat, uint8_t * outmsg, uint16_t * outlen, uint16_t outmsgmaxlen, uint16_t * nrr, void * user_data)
        uint8_t res = rr->MINIMR_RR_FUN_QUERY_GET_AUTHRR(rr, &qstats[iq], outmsg, &outlen, outmsgmaxlen, &nrr, user_data);

        if (res != MINIMR_OK){
            return MINIMR_DNS_HDR2_RCODE_SERVAIL;
        }

        nauthrr += nrr;
    }

    // MINIMR_DEBUGF("added %d authority rr\n", nauthrr);

    // add all additional RRs
    uint16_t nextrarr = 0;
    for(uint16_t iq = 0; iq < nq; iq++){

        // don't check questions that have become irrelevant
        if (qstats[iq].relevant == 0){
            continue;
        }

        struct minimr_rr * rr = records[qstats[iq].match_i];

        uint16_t nrr = 0;

        //minimr_rr_fun_handler( minimquery_get_*, struct minimr_rr * rr, struct minimr_query_stat * qstat, uint8_t * outmsg, uint16_t * outlen, uint16_t outmsgmaxlen, uint16_t * nrr, void * user_data)
        uint8_t res = rr->MINIMR_RR_FUN_QUERY_GET_EXTRARR(rr, &qstats[iq], outmsg, &outlen, outmsgmaxlen, &nrr, user_data);

        if (res != MINIMR_OK){
            return MINIMR_DNS_HDR2_RCODE_SERVAIL;
        }

        nextrarr += nrr;
    }

    // MINIMR_DEBUGF("added %d extra rr\n", nextrarr);

    // prepare outheader and out sanity check
    struct minimr_dns_hdr outhdr;


    // finalize header
    outhdr.transaction_id = hdr.transaction_id; // is generally ignored (ie 0x0000) but included for legacy support..

    outhdr.flags[0] = MINIMR_DNS_HDR1_QR_REPLY | MINIMR_DNS_HDR1_AA;
    outhdr.flags[1] = MINIMR_DNS_HDR2_RCODE_NOERROR;

    outhdr.nqueries = 0;
    outhdr.nanswers = nanswers;
    outhdr.nauthrr = nauthrr;
    outhdr.nextrarr = nextrarr;

    // add header
    minimr_dns_hdr_write(outmsg, &outhdr);

    *outmsglen = outlen;

    return MINIMR_OK;
}


#if MINIMR_RR_COUNT > 0  && MINIMR_SIMPLE_INTERFACE_ENABLED == 0

int32_t minimr_default_query_response_msg(
    uint8_t *msg, uint16_t msglen,
    struct minimr_rr **records, uint16_t nrecords,
    uint8_t *outmsg, uint16_t *outmsglen, uint16_t outmsgmaxlen,
    uint8_t *unicast_requested,
    void * user_data
)
{
    struct minimr_query_stat qstats[MINIMR_RR_COUNT];

    return minimr_query_response_msg(
        msg, msglen,
        qstats, MINIMR_RR_COUNT,
        records, nrecords,
        outmsg, outmsglen, outmsgmaxlen,
        unicast_requested,
        user_data
    );
}

#endif
