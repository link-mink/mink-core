/*            _       _
 *  _ __ ___ (_)_ __ | | __
 * | '_ ` _ \| | '_ \| |/ /
 * | | | | | | | | | |   <
 * |_| |_| |_|_|_| |_|_|\_\
 *
 * SPDX-License-Identifier: MIT
 *
 */

#ifndef SCTP_H_
#define SCTP_H_

#include <chunk.h>
#include <netinet/in.h>
#include <netinet/sctp.h>
#include <vector>

using namespace std;

namespace sctp {
    // dissection
    class SCTPPacket {
    public:
        SCTPPacket();
        int source_port;
        int destination_port;
        int verification_tag_length;
        unsigned char* verification_tag;
        int checksum_length;
        unsigned char* checksum;
        vector<Chunk*> chunks;
        Chunk* get_chunk(ChunkType chunk_type);
        Data* get_chunk(PayloadProtocolType payload_type);
    };
    // main decode method
    SCTPPacket* decode(unsigned char* data, int data_length);
    void decode(unsigned char* data, 
                int data_length, 
                SCTPPacket* sctpp,
                ChunkPool* chunk_pool);

    // socket handling
    int init_sctp_server(unsigned long local_addr_1, 
                         unsigned long local_addr_2,
                         int local_port, 
                         uint32_t _hb_interval = 30000,
                         uint16_t _path_max_retrans = 5,
                         uint32_t _max_init_retrans = 8,
                         uint32_t _rto_initial = 3000, 
                         uint32_t _rto_max = 60000,
                         uint32_t _rto_min = 1000, 
                         uint32_t _max_burst = 4,
                         uint32_t _sack_timeout = 200, 
                         uint32_t _sack_freq = 2,
                         uint32_t _valid_cookie_life = 60000

    );

    int shutdown_sctp_server(int socket);
    int get_client(int serverSock, sockaddr_in* sci);
    int init_sctp_client(unsigned long addr, int remote_port, int stream_count);
    int init_sctp_client_bind(uint32_t remote_addr_1, 
                              uint32_t remote_addr_2,
                              uint32_t local_addr_1, 
                              uint32_t local_addr_2,
                              uint16_t local_port, 
                              uint16_t remote_port,
                              int stream_count, 
                              uint32_t _hb_interval = 30000,
                              uint16_t _path_max_retrans = 5,
                              uint32_t _max_init_retrans = 8,
                              uint32_t _rto_initial = 3000,
                              uint32_t _rto_max = 60000, 
                              uint32_t _rto_min = 1000,
                              uint32_t _max_burst = 4, 
                              uint32_t _sack_timeout = 200,
                              uint32_t _sack_freq = 2,
                              uint32_t _valid_cookie_life = 60000

    );

    int send_sctp(int connSock, 
                  const void* msg, 
                  size_t msg_len, 
                  uint32_t ppid,
                  uint16_t stream_id);
    int rcv_sctp(int connSock, 
                 const void* msg_buffer, 
                 unsigned int msg_buffer_size,
                 int* flags, 
                 sctp_sndrcvinfo* sndrcvinfo);
    int shutdown_sctp_client(int connSock);

}  // namespace sctp

#endif /* SCTP_H_ */
