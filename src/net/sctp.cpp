/*            _       _
 *  _ __ ___ (_)_ __ | | __
 * | '_ ` _ \| | '_ \| |/ /
 * | | | | | | | | | |   <
 * |_| |_| |_|_|_| |_|_|\_\
 *
 * SPDX-License-Identifier: MIT
 *
 */

#include <arpa/inet.h>
#include <chunk.h>
#include <errno.h>
#include <sctp.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <iostream>

int sctp::get_client(int serverSock, sockaddr_in *sci) {
    int socket = -1;
    if (sci != nullptr) {
        // zero mem
        memset((void *)sci, 0, sizeof(sockaddr_in));
        // sizes
        int size_sci = sizeof(sockaddr_in);
        // accept socket
        socket = accept(serverSock, (sockaddr *)sci, (socklen_t *)&size_sci);

    } else {
        socket = accept(serverSock, nullptr, nullptr);
    }

    if (socket > 0) {
        /* set socket options */
        struct sctp_event_subscribe events;
        memset((void *)&events, 0, sizeof(events));
        events.sctp_data_io_event = 1;
        events.sctp_association_event = 1;
        events.sctp_shutdown_event = 1;
        setsockopt(socket, SOL_SCTP, SCTP_EVENTS, (const void *)&events,
                   sizeof(events));
    }

    return socket;
}
int sctp::shutdown_sctp_server(int socket) {
    int res = shutdown(socket, SHUT_RDWR);
    res += close(socket);
    return res;
}

int sctp::init_sctp_server(unsigned long local_addr_1,
                           unsigned long local_addr_2, 
                           int local_port,
                           uint32_t _hb_interval, 
                           uint16_t _path_max_retrans,
                           uint32_t _max_init_retrans, 
                           uint32_t _rto_initial,
                           uint32_t _rto_max, 
                           uint32_t _rto_min,
                           uint32_t _max_burst, 
                           uint32_t _sack_timeout,
                           uint32_t _sack_freq, 
                           uint32_t _valid_cookie_life) {
    int ret, serverSock;
    struct sockaddr_in servaddr[2];
    struct sctp_event_subscribe events;
    struct sctp_paddrparams addr_params;
    struct sctp_rtoinfo rto_info;
    struct sctp_sack_info sack_params;
    struct sctp_assocparams assoc_params;
    struct sctp_assoc_value assoc_value;
    struct sctp_initmsg initmsg;
    // no delay
    int int_bool = 1;

    /* Create an SCTP TCP-Style Socket */
    serverSock = socket(AF_INET, SOCK_STREAM, IPPROTO_SCTP);

    /* Specify primary peer endpoint to which we'll connect */
    memset(servaddr, 0, sizeof(servaddr));
    servaddr[0].sin_family = AF_INET;
    servaddr[0].sin_port = htons(local_port);
    // automatic bind
    if (local_addr_1 == 0)
        servaddr[0].sin_addr.s_addr = htonl(INADDR_ANY);
    else {
        // specific bind
        servaddr[0].sin_addr.s_addr = local_addr_1;

        // secondary bind
        if (local_addr_2 != 0) {
            servaddr[1].sin_family = AF_INET;
            servaddr[1].sin_port = servaddr[0].sin_port;
            servaddr[1].sin_addr.s_addr = local_addr_2;
        }
    }

    // bind primary
    ret = bind(serverSock, (sockaddr *)&servaddr[0], sizeof(sockaddr_in));
    if (ret < 0) goto error_out;

    // bind secondary
    if (local_addr_2 != 0) {
        ret = sctp_bindx(serverSock, (sockaddr *)&servaddr[1], 1,
                         SCTP_BINDX_ADD_ADDR);
        if (ret < 0) goto error_out;
    }

    /* Specify that a maximum of 16 streams will be available per socket */
    memset(&initmsg, 0, sizeof(initmsg));
    initmsg.sinit_num_ostreams = 16;
    initmsg.sinit_max_instreams = 16;
    initmsg.sinit_max_attempts = _max_init_retrans;
    ret = setsockopt(serverSock, IPPROTO_SCTP, SCTP_INITMSG, &initmsg,
                     sizeof(initmsg));
    if (ret < 0) goto error_out;

    // no delay
    setsockopt(serverSock, IPPROTO_SCTP, SCTP_NODELAY, &int_bool,
               sizeof(int_bool));

    /* Enable receipt of SCTP Snd/Rcv Data via sctp_recvmsg */
    memset(&events, 0, sizeof(events));
    events.sctp_data_io_event = 1;
    ret = setsockopt(serverSock, SOL_SCTP, SCTP_EVENTS, (const void *)&events,
                     sizeof(events));
    if (ret < 0) goto error_out;

    // addr params
    memset(&addr_params, 0, sizeof(addr_params));
    addr_params.spp_hbinterval = _hb_interval;
    addr_params.spp_flags =
        SPP_HB_ENABLE | SPP_PMTUD_ENABLE | SPP_SACKDELAY_ENABLE;
    addr_params.spp_pathmaxrxt = _path_max_retrans;
    ret = setsockopt(serverSock, IPPROTO_SCTP, SCTP_PEER_ADDR_PARAMS,
                     &addr_params, sizeof(addr_params));
    if (ret < 0) goto error_out;

    // rto info
    memset(&rto_info, 0, sizeof(rto_info));
    rto_info.srto_initial = _rto_initial;
    rto_info.srto_max = _rto_max;
    rto_info.srto_min = _rto_min;
    ret = setsockopt(serverSock, IPPROTO_SCTP, SCTP_RTOINFO, &rto_info,
                     sizeof(rto_info));
    if (ret < 0) goto error_out;

    // sack params
    memset(&sack_params, 0, sizeof(sack_params));
    sack_params.sack_delay = _sack_timeout;
    sack_params.sack_freq = _sack_freq;
    ret = setsockopt(serverSock, IPPROTO_SCTP, SCTP_DELAYED_ACK, &sack_params,
                     sizeof(sack_params));
    if (ret < 0) goto error_out;

    // max burst
    memset(&assoc_value, 0, sizeof(assoc_value));
    assoc_value.assoc_value = _max_burst;
    ret = setsockopt(serverSock, IPPROTO_SCTP, SCTP_MAX_BURST, &assoc_value,
                     sizeof(assoc_value));
    if (ret < 0) goto error_out;

    // assoc info
    memset(&assoc_params, 0, sizeof(assoc_params));
    assoc_params.sasoc_cookie_life = _valid_cookie_life;
    ret = setsockopt(serverSock, IPPROTO_SCTP, SCTP_ASSOCINFO, &assoc_params,
                     sizeof(assoc_params));
    if (ret < 0) goto error_out;

    // listen
    listen(serverSock, 5);
    // return socket
    return serverSock;

error_out:
    shutdown(serverSock, SHUT_RDWR);
    close(serverSock);
    return -1;
}

int sctp::init_sctp_client_bind(uint32_t remote_addr_1, 
                                uint32_t remote_addr_2, 
                                uint32_t local_addr_1,
                                uint32_t local_addr_2, 
                                uint16_t local_port, 
                                uint16_t remote_port,
                                int stream_count, 
                                uint32_t _hb_interval, 
                                uint16_t _path_max_retrans,
                                uint32_t _max_init_retrans, 
                                uint32_t _rto_initial, 
                                uint32_t _rto_max,
                                uint32_t _rto_min, 
                                uint32_t _max_burst, 
                                uint32_t _sack_timeout,
                                uint32_t _sack_freq, 
                                uint32_t _valid_cookie_life) {
    int ret, connSock, endpc;
    struct sockaddr_in servaddrs[2];
    struct sockaddr_in local_bind;
    struct sockaddr_in local_bind_2;
    struct sctp_event_subscribe events;
    struct sctp_initmsg initmsg;
    struct sctp_paddrparams addr_params;
    struct sctp_rtoinfo rto_info;
    struct sctp_sack_info sack_params;
    struct sctp_assocparams assoc_params;
    struct sctp_assoc_value assoc_value;

    /* Create an SCTP TCP-Style Socket */
    connSock = socket(AF_INET, SOCK_STREAM, IPPROTO_SCTP);
    if (connSock < 0) {
        return -1;
    }
    int yes = 1;
    int int_bool = 1;
    // set socket option
    setsockopt(connSock, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int));
#ifdef SO_REUSEPORT
    setsockopt(connSock, SOL_SOCKET, SO_REUSEPORT, &yes, sizeof(int));
#endif
    // main bind
    if (local_addr_1 != 0) {
        // local bind
        memset((void *)&local_bind, 0, sizeof(local_bind));
        local_bind.sin_family = AF_INET;
        local_bind.sin_addr.s_addr = local_addr_1;
        local_bind.sin_port = htons(local_port);
        ret = bind(connSock, (sockaddr *)&local_bind, sizeof(sockaddr_in));
        if (ret < 0) goto error_out;

        // extra bind
        if (local_addr_2 != 0) {
            memset(&local_bind_2, 0, sizeof(local_bind_2));
            local_bind_2.sin_family = AF_INET;
            local_bind_2.sin_addr.s_addr = local_addr_2;
            local_bind_2.sin_port = htons(local_port);
            ret = sctp_bindx(connSock, (sockaddr *)&local_bind_2, 1,
                             SCTP_BINDX_ADD_ADDR);
            if (ret < 0) goto error_out;
        }
    }

    /* Specify that a maximum of 5 streams will be available per socket */
    memset(&initmsg, 0, sizeof(initmsg));
    initmsg.sinit_num_ostreams = stream_count;
    initmsg.sinit_max_instreams = stream_count;
    initmsg.sinit_max_attempts = _max_init_retrans;
    ret = setsockopt(connSock, IPPROTO_SCTP, SCTP_INITMSG, &initmsg,
                     sizeof(initmsg));
    if (ret < 0) goto error_out;

    // no delay
    setsockopt(connSock, IPPROTO_SCTP, SCTP_NODELAY, &int_bool,
               sizeof(int_bool));

    // addr params
    memset(&addr_params, 0, sizeof(addr_params));
    addr_params.spp_hbinterval = _hb_interval;
    addr_params.spp_flags =
        SPP_HB_ENABLE | SPP_PMTUD_ENABLE | SPP_SACKDELAY_ENABLE;
    addr_params.spp_pathmaxrxt = _path_max_retrans;
    ret = setsockopt(connSock, IPPROTO_SCTP, SCTP_PEER_ADDR_PARAMS,
                     &addr_params, sizeof(addr_params));
    if (ret < 0) goto error_out;

    // rto info
    memset(&rto_info, 0, sizeof(rto_info));
    rto_info.srto_initial = _rto_initial;
    rto_info.srto_max = _rto_max;
    rto_info.srto_min = _rto_min;
    ret = setsockopt(connSock, IPPROTO_SCTP, SCTP_RTOINFO, &rto_info,
                     sizeof(rto_info));
    if (ret < 0) goto error_out;

    // sack params
    memset(&sack_params, 0, sizeof(sack_params));
    sack_params.sack_delay = _sack_timeout;
    sack_params.sack_freq = _sack_freq;
    ret = setsockopt(connSock, IPPROTO_SCTP, SCTP_DELAYED_ACK, &sack_params,
                     sizeof(sack_params));
    if (ret < 0) goto error_out;

    // max burst
    memset(&assoc_value, 0, sizeof(assoc_value));
    assoc_value.assoc_value = _max_burst;
    ret = setsockopt(connSock, IPPROTO_SCTP, SCTP_MAX_BURST, &assoc_value,
                     sizeof(assoc_value));
    if (ret < 0) goto error_out;

    // assoc info
    memset(&assoc_params, 0, sizeof(assoc_params));
    assoc_params.sasoc_cookie_life = _valid_cookie_life;
    ret = setsockopt(connSock, IPPROTO_SCTP, SCTP_ASSOCINFO, &assoc_params,
                     sizeof(assoc_params));
    if (ret < 0) goto error_out;

    /* Specify primary peer endpoint to which we'll connect */
    memset(servaddrs, 0, sizeof(servaddrs));
    servaddrs[0].sin_family = AF_INET;
    servaddrs[0].sin_port = htons(remote_port);
    servaddrs[0].sin_addr.s_addr = remote_addr_1;

    // secondary peer address
    if (remote_addr_2 != 0) {
        servaddrs[1].sin_family = AF_INET;
        servaddrs[1].sin_port = servaddrs[0].sin_port;
        servaddrs[1].sin_addr.s_addr = remote_addr_2;
        // two end points
        endpc = 2;

        // one endpoint
    } else
        endpc = 1;

    /* Connect to the server */
    ret = sctp_connectx(connSock, (sockaddr *)servaddrs, endpc, nullptr);

    if (ret == 0) {
        /* Enable receipt of SCTP Snd/Rcv Data via sctp_recvmsg */
        memset((void *)&events, 0, sizeof(events));
        events.sctp_data_io_event = 1;
        events.sctp_association_event = 1;
        events.sctp_shutdown_event = 1;
        ret = setsockopt(connSock, SOL_SCTP, SCTP_EVENTS, (const void *)&events,
                         sizeof(events));
        if (ret < 0) goto error_out;
        return connSock;

    } else goto error_out;

error_out:
    shutdown(connSock, SHUT_RDWR);
    close(connSock);
    return -1;
}
int sctp::init_sctp_client(unsigned long addr, int remote_port,
                           int stream_count) {
    int in, ret, connSock;
    int int_bool = 1;
    struct sockaddr_in servaddr;
    struct sctp_status status;
    struct sctp_event_subscribe events;
    struct sctp_initmsg initmsg;

    /* Create an SCTP TCP-Style Socket */
    connSock = socket(AF_INET, SOCK_STREAM, IPPROTO_SCTP);
    if (connSock < 0) {
        return -1;
    }
    /* Specify that a maximum of 5 streams will be available per socket */
    memset(&initmsg, 0, sizeof(initmsg));

    initmsg.sinit_num_ostreams = stream_count;
    initmsg.sinit_max_instreams = stream_count;
    initmsg.sinit_max_attempts = 0;
    ret = setsockopt(connSock, IPPROTO_SCTP, SCTP_INITMSG, &initmsg,
                     sizeof(initmsg));
    if (ret < 0) goto error_out;

    // no delay
    setsockopt(connSock, IPPROTO_SCTP, SCTP_NODELAY, &int_bool,
               sizeof(int_bool));

    /* Specify the peer endpoint to which we'll connect */
    memset((void *)&servaddr, 0, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(remote_port);
    servaddr.sin_addr.s_addr = addr;

    /* Connect to the server */
    ret = connect(connSock, (struct sockaddr *)&servaddr, sizeof(servaddr));
    if (ret == 0) {
        /* Enable receipt of SCTP Snd/Rcv Data via sctp_recvmsg */
        memset((void *)&events, 0, sizeof(events));
        events.sctp_data_io_event = 1;
        events.sctp_association_event = 1;
        events.sctp_shutdown_event = 1;
        ret = setsockopt(connSock, SOL_SCTP, SCTP_EVENTS, (const void *)&events,
                         sizeof(events));
        if (ret < 0) goto error_out;

        /* Read and emit the status of the Socket (optional step) */
        in = sizeof(status);
        ret = getsockopt(connSock, SOL_SCTP, SCTP_STATUS, (void *)&status,
                         (socklen_t *)&in);
        if (ret < 0) goto error_out;
        return connSock;

    } else goto error_out;

error_out:
    shutdown(connSock, SHUT_RDWR);
    close(connSock);
    return -1;
}

/*
 * RETURN 0 if sucessfully sent a message
 * RETURN 1 if unsucesfull!
 */
int sctp::send_sctp(int connSock, const void *msg, size_t msg_len,
                    uint32_t ppid, uint16_t stream_id) {
    sctp_sndrcvinfo sinfo;
    memset(&sinfo, 0, sizeof(sinfo));
    sinfo.sinfo_ppid = htobe32(ppid);
    sinfo.sinfo_stream = stream_id;
    int res;
    res = sctp_send(connSock, msg, msg_len, &sinfo, MSG_NOSIGNAL);
    if (res > 0)
        return EXIT_SUCCESS;
    else
        return EXIT_FAILURE;
}

/*
 * RETURN Number of bytes received.
 */
int sctp::rcv_sctp(int connSock, const void *msg_buffer,
                   unsigned int msg_buffer_size, int *flags,
                   sctp_sndrcvinfo *sndrcvinfo) {
    return sctp_recvmsg(connSock, (void *)msg_buffer, msg_buffer_size,
                        (struct sockaddr *)nullptr, nullptr, sndrcvinfo, flags);
}

/*
 * SCTP Client SHUTDOWN
 */
int sctp::shutdown_sctp_client(int connSock) {
    int res = shutdown(connSock, SHUT_RDWR);
    res += close(connSock);
    return res;
}

sctp::SCTPPacket::SCTPPacket()
    : source_port(0),
      destination_port(0),
      verification_tag_length(0),
      verification_tag(nullptr),
      checksum_length(0),
      checksum(nullptr) {
    // reserve mem for 10 initial chunks
    chunks.reserve(10);
}

sctp::Chunk *sctp::SCTPPacket::get_chunk(ChunkType chunk_type) {
    for (unsigned int i = 0; i < chunks.size(); i++)
        if (chunks[i]->type == chunk_type) return chunks[i];
    return nullptr;
}

sctp::Data *sctp::SCTPPacket::get_chunk(PayloadProtocolType payload_type) {
    Data *data = nullptr;
    for (unsigned int i = 0; i < chunks.size(); i++) {
        if (chunks[i]->type == DATA) {
            data = (Data *)chunks[i];
            if (data->payload_protocol_type == payload_type) return data;
        }
    }
    return nullptr;
}

void sctp::decode(unsigned char *data, int data_length, SCTPPacket *sctpp,
                  ChunkPool *chunk_pool) {
    if ((data != nullptr) && (data_length > 0) && (sctpp != nullptr)) {
        sctpp->chunks.clear();
        int byte_pos = 0;
        ChunkType ct;
        Chunk *chunk;
        sctpp->source_port =
            (((data[byte_pos] << 8) & 0xff) + (data[byte_pos + 1] & 0xFF)) &
            0xFFFF;
        byte_pos += 2;
        sctpp->destination_port =
            (((data[byte_pos] << 8) & 0xff) + (data[byte_pos + 1] & 0xFF)) &
            0xFFFF;
        byte_pos += 2;
        // verification tag
        sctpp->verification_tag_length = 4;
        sctpp->verification_tag = &data[byte_pos];
        byte_pos += 4;
        // checksum
        sctpp->checksum_length = 4;
        sctpp->checksum = &data[byte_pos];
        byte_pos += 4;

        // chunk loop
        while (byte_pos < data_length) {
            ct = (ChunkType)(data[byte_pos] & 0xFF);
            // validate chunk
            if (!chunk_pool->chunk_valid(ct)) return;
            // get chunk
            chunk = chunk_pool->request_chunk(ct);
            // unknown chunk error
            if (chunk == nullptr) return;
            chunk->byte_pos = 0;
            // decode chunk
            chunk->decode(&data[byte_pos], data_length - byte_pos);
            // sanity
            if (chunk->length <= 0) return;
            sctpp->chunks.push_back(chunk);
            byte_pos += chunk->length;
            // chunk has to be a multiple of 4, if not, zero padding is added
            int m = chunk->length % 4;
            byte_pos += ((m > 0) ? 4 - m : 0);
        }
    }
}

sctp::SCTPPacket *sctp::decode(unsigned char *data, int data_length) {
    if ((data != nullptr) && (data_length > 0)) {
        SCTPPacket *sctpp = new SCTPPacket();
        int byte_pos = 0;
        ChunkType ct;
        Chunk *chunk;
        sctpp->source_port =
            (((data[byte_pos] << 8) & 0xff) + (data[byte_pos + 1] & 0xFF)) &
            0xFFFF;
        byte_pos += 2;
        sctpp->destination_port =
            (((data[byte_pos] << 8) & 0xff) + (data[byte_pos + 1] & 0xFF)) &
            0xFFFF;
        byte_pos += 2;
        // verification tag
        sctpp->verification_tag_length = 4;
        sctpp->verification_tag = &data[byte_pos];
        byte_pos += 4;
        // checksum
        sctpp->checksum_length = 4;
        sctpp->checksum = &data[byte_pos];
        byte_pos += 4;

        // chunk loop
        while (byte_pos < data_length) {
            ct = (ChunkType)(data[byte_pos] & 0xFF);
            switch (ct) {
                case DATA:
                    chunk = new Data();
                    break;
                default:
                    chunk = new Chunk();
                    break;
            }
            // decode chunk
            chunk->decode(&data[byte_pos], data_length - byte_pos);
            sctpp->chunks.push_back(chunk);
            byte_pos += chunk->length;
            // chunk has to be a multiple of 4, if not, zero padding is added
            int m = chunk->length % 4;
            byte_pos += ((m > 0) ? 4 - m : 0);
        }

        return sctpp;
    }
    return nullptr;
}

