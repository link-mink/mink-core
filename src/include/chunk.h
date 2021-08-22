/*            _       _
 *  _ __ ___ (_)_ __ | | __
 * | '_ ` _ \| | '_ \| |/ /
 * | | | | | | | | | |   <
 * |_| |_| |_|_|_| |_|_|\_\
 *
 * SPDX-License-Identifier: MIT
 *
 */

#ifndef CHUNK_H_
#define CHUNK_H_
#include <map>
namespace sctp {
    // http://www.iana.org/assignments/sctp-parameters/sctp-parameters.xml#sctp-parameters-25
    enum PayloadProtocolType {
        IUA = 0x01,
        M2UA = 0x02,
        M3UA = 0x03,
        SUA = 0x04,
        M2PA = 0x05,
        V5UA = 0x06,
        H_248 = 0x07,
        BICC_Q_2150_3 = 0x08,
        TALI = 0x09,
        DUA = 10,
        ASAP = 11,
        ENRP = 12,
        H_323 = 13,
        Q_IPC_Q_2150_3 = 14,
        SIMCO = 15,
        DDP_SEGMENT_CHUNK = 16,
        DDP_STREAM_SESSION_CONTROL = 17,
        S1AP = 18,
        RUA = 19,
        HNBAP = 20,
        FORCES_HP = 21,
        FORCES_MP = 22,
        FORCES_LP = 23,
        SBC_AP = 24,
        NBAP = 25,
        X2AP = 27,
        IRCP = 28,
        LCS_AP = 29,
        MPICH2 = 30,
        SABP = 31,
        FGP = 32,
        PPP = 33,
        CALCAPP = 34,
        SSP = 35,
        NPMP_CONTROL = 36,
        NPMP_DATA = 37,
        ECHO = 38,
        DISCARD = 39,
        DAYTIME = 40,
        CHARGEN = 41,
        _3GPP_RNA = 42,
        _3GPP_M2AP = 43,
        _3GPP_M3AP = 44,
        SSH_SCTP = 45,
        DIAMETER_SCTP_DATA = 46,
        DIAMETER_DTLS_SCTP_DATA = 47,
        R14P = 48,
        GDT = 49

    };

    enum ChunkType {
        _UNKNOWN_CHUNK_ = -1,
        DATA = 0x00,
        INIT = 0x01,
        INIT_ACL = 0x02,
        SACK = 0x03,
        HEARTBEAT = 0x04,
        HEARTBEAT_ACK = 0x05,
        ABORT = 0x06,
        SHUTDOWN = 0x07,
        SHUTDOWN_ACK = 0x08,
        ERROR = 0x09,
        COOKIE_ECHO = 0x0a,
        COOKIE_ACK = 0x0b,
        ECNE = 0x0c,
        CWR = 0x0d,
        SHUTDOWN_COMPLETE = 0x0e
    };

    // base chunk
    class Chunk {
       public:
        Chunk();
        virtual ~Chunk();
        ChunkType type;
        unsigned char flags;
        int length;
        int byte_pos;

        int getLength(unsigned char* data, int data_length);
        virtual void decode(unsigned char* data, int data_length);
    };
    // data chunk
    class Data : public Chunk {
       public:
        Data();
        ~Data();
        unsigned char* tsn;
        int tsn_length;
        int stream_identifier;
        int sequence_number;
        PayloadProtocolType payload_protocol_type;
        int user_data_length;
        unsigned char* user_data;
        bool U_bit;
        bool B_bit;
        bool E_bit;
        void decode(unsigned char* data, int data_length);
    };

    // chunk memory pool
    class ChunkPoolItem {
       private:
        Chunk** pool;
        Chunk* next_free_item;
        int total_count;
        int free_count;
        Chunk* create_chunk(ChunkType _chunk_type);

       public:
        ChunkPoolItem();
        ~ChunkPoolItem();
        ChunkType type;
        Chunk* request_item();
        int get_free_count();
        void init_pool();
        void set_pool_size(int _total_count);
    };

    class ChunkPool {
       private:
        std::map<ChunkType, ChunkPoolItem*> CHUNK_POOL;
        int chunk_count;
        void init_chunk(ChunkType _chunk_type);

       public:
        ChunkPool();
        ~ChunkPool();
        void set_pool_size(int _chunk_count);
        void init_pool();
        Chunk* request_chunk(ChunkType chunk_type);
        bool chunk_valid(int id);
    };

}  // namespace sctp

#endif /* CHUNK_H_ */
