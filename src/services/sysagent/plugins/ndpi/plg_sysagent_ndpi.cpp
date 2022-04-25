/*            _       _
 *  _ __ ___ (_)_ __ | | __
 * | '_ ` _ \| | '_ \| |/ /
 * | | | | | | | | | |   <
 * |_| |_| |_|_|_| |_|_|\_\
 *
 * SPDX-License-Identifier: MIT
 *
 */

#include <algorithm>
#include <mink_plugin.h>
#include <gdt_utils.h>
#include <mink_pkg_config.h>
#include <string>
#ifdef ENABLE_GRPC
#include <gdt.pb.h>
#else
#include <gdt.pb.enums_only.h>
#endif
#include <sysagent.h>
#include <json_rpc.h>
#include <pcap/pcap.h>
#include <ndpi/ndpi_main.h>
#include <regex>
#include <thread>
#include <chrono>

/***********/
/* Aliases */
/***********/
using Jrpc = json_rpc::JsonRpc;
using Pargs = mink_utils::Plugin_args;

/***********/
/* Forward */
/***********/
class Pcap_d;

/**********************/
/* ndpi flow tracking */
/**********************/
typedef struct ndpi_flow_info {
    u_int32_t flow_id;
    u_int32_t hashval;
    u_int32_t src_ip;
    u_int32_t dst_ip;
    u_int16_t src_port;
    u_int16_t dst_port;
    u_int8_t detection_completed;
    u_int8_t protocol;
    u_int8_t bidirectional;
    u_int16_t vlan_id;
    ndpi_flow_struct *ndpi_flow;
    char src_name[48];
    char dst_name[48];
    u_int8_t ip_version;
    u_int64_t src2dst_bytes;
    u_int64_t dst2src_bytes;
    u_int64_t src2dst_goodput_bytes;
    u_int64_t dst2src_goodput_bytes;
    u_int32_t src2dst_packets;
    u_int32_t dst2src_packets;
    ndpi_protocol detected_protocol;
    ndpi_bin payload_len_bin;

} ndpi_flow_info_t;

/*************************/
/* ndpi flow preferences */
/*************************/
typedef struct ndpi_workflow_prefs {
  u_int8_t decode_tunnels;
  u_int8_t quiet_mode;
  u_int8_t ignore_vlanid;
  u_int32_t num_roots;
  u_int32_t max_ndpi_flows;
} ndpi_workflow_prefs_t;


/*****************/
/* ndpi workflow */
/*****************/
typedef struct ndpi_workflow {
    ndpi_workflow_prefs prefs;
    pcap_t *pcap_handle;
    Pcap_d *pcap_d;
    void **ndpi_flows_root;
    ndpi_detection_module_struct *ndpi_struct;
    u_int32_t num_allocated_flows;
} ndpi_workflow_t;

/*******************/
/* PCAP descriptor */
/*******************/
class Pcap_d {
public:
    Pcap_d() = delete;
    ~Pcap_d() = default;
    Pcap_d(const Pcap_d &o) {
        if_n_ = o.if_n_;
        pcap_h_ = o.pcap_h_;
        workflow_ = o.workflow_;
        stats_ = o.stats_;
    }
    Pcap_d(const std::string &if_n) : if_n_(if_n) {
        // reserved
    }

    const std::string &get_if() const {
        return if_n_;
    }

    const pcap_t *get_pcap_h() const {
        return pcap_h_;
    }

    void set_pcap_h(pcap_t *pcap_h) {
        pcap_h_ = pcap_h;
    }

    ndpi_workflow_t &get_workflow() {
        return workflow_;
    }

    void update_stats(const std::string &id, const uint64_t s) {
        std::unique_lock<std::mutex> lock(mtx_);
        stats_[id] += s;
    }
    void inc_stats(const std::string &id) {
        std::unique_lock<std::mutex> lock(mtx_);
        ++stats_[id];
    }

    void get_stats(std::map<std::string, uint64_t> &out) {
        std::unique_lock<std::mutex> lock(mtx_);
        out = stats_;
    }

private:
    std::string if_n_;
    pcap_t *pcap_h_;
    ndpi_workflow_t workflow_;
    std::map<std::string, uint64_t> stats_;
    std::mutex mtx_;
};

/****************/
/* PCAP manager */
/****************/
class Pcap_mngr {
public:
    Pcap_mngr() = default;
    ~Pcap_mngr() = default;
    Pcap_mngr(const Pcap_mngr &o) = delete;
    Pcap_mngr &operator=(const Pcap_mngr &o) = delete;

    Pcap_d &add_pcap(const std::string &if_n) {
        // interface should not be present
        if (pcap_lst_.find(if_n) != pcap_lst_.cend()) {
            throw std::invalid_argument("interface already exists");
        }
        return pcap_lst_.emplace(std::make_pair(if_n, Pcap_d(if_n))).first->second;
    }

    void del_pcap(const std::string &if_n) {
        auto it = pcap_lst_.find(if_n);
        if (it != pcap_lst_.end()) {
            pcap_lst_.erase(it);
        }

    }

    Pcap_d &get_pcap(const std::string &if_n) {
        auto it = pcap_lst_.find(if_n);
        if (it == pcap_lst_.end())
            throw std::invalid_argument("pcap descriptor is missing");
        else
            return it->second;

    }

private:
    std::map<std::string, Pcap_d> pcap_lst_;

};

/***************/
/* Global vars */
/***************/
Pcap_mngr pcap_mngr;
uint32_t current_ndpi_memory;
uint32_t max_ndpi_memory;

/*************/
/* Plugin ID */
/*************/
static const char *PLG_ID = "plg_sysagent_ndpi.so";

/**********************************************/
/* list of command implemented by this plugin */
/**********************************************/
extern "C" constexpr int COMMANDS[] = {
    gdt_grpc::CMD_NDPI_GET_STATS,
    // end of list marker
    -1
};

/******************/
/* Get PLG config */
/******************/
json *plg_get_config(){
    // cfg pointer
    PluginsConfig *pcfg = nullptr;
    // get daemon pointer
    auto dd = static_cast<SysagentdDescriptor *>(mink::CURRENT_DAEMON);
    // get config
    try {
        pcfg = static_cast<PluginsConfig *>(dd->dparams.get_pval<void *>(4));

    } catch (std::exception &e) {
        throw std::invalid_argument("configuration file missing");
    }

    // find config for this plugin
    const auto &it = pcfg->cfg.find(PLG_ID);
    if(it == pcfg->cfg.cend()){
        throw std::invalid_argument("configuration missing");
    }

    return &*it;
}

// ndpi_malloc wrapper function
static void *ndpi_malloc_wrapper(size_t size) {
    current_ndpi_memory += size;

    if (current_ndpi_memory > max_ndpi_memory)
        max_ndpi_memory = current_ndpi_memory;

    return (malloc(size));
}

// free wrapper function
static void free_wrapper(void *freeable) {
    free(freeable);
}

// suported Data Link Type
int ndpi_is_datalink_supported(int dlt) {
    switch (dlt) {
        // IEEE 802.3 Ethernet - 1
        case DLT_EN10MB:
            return 1;
        default:
            return 0;
    }
}

// compare node 32bit
static inline int cmp_n32(uint32_t a, uint32_t b) {
    return a == b ? 0 : ntohl(a) < ntohl(b) ? -1 : 1;
}

// compare node 16bit
static inline int cmp_n16(uint16_t a, uint16_t b) {
    return a == b ? 0 : ntohs(a) < ntohs(b) ? -1 : 1;
}

// compare two nodes in workflow
static int ndpi_workflow_node_cmp(const void *a, const void *b) {
    const struct ndpi_flow_info *fa = (const struct ndpi_flow_info *)a;
    const struct ndpi_flow_info *fb = (const struct ndpi_flow_info *)b;

    if (fa->hashval < fb->hashval)
        return (-1);
    else if (fa->hashval > fb->hashval)
        return (1);

    // Flows have the same hash
    if (fa->vlan_id < fb->vlan_id)
        return (-1);
    else {
        if (fa->vlan_id > fb->vlan_id)
            return (1);
    }
    if (fa->protocol < fb->protocol)
        return (-1);
    else {
        if (fa->protocol > fb->protocol)
            return (1);
    }

    int r;
    r = cmp_n32(fa->src_ip, fb->src_ip);
    if (r)
        return r;
    r = cmp_n16(fa->src_port, fb->src_port);
    if (r)
        return r;
    r = cmp_n32(fa->dst_ip, fb->dst_ip);
    if (r)
        return r;
    r = cmp_n16(fa->dst_port, fb->dst_port);

    return (r);
}


static ndpi_flow_info *get_ndpi_flow_info(ndpi_workflow *workflow,
                                          const u_int8_t version,
                                          const ndpi_iphdr *iph,
                                          const ndpi_ipv6hdr *iph6,
                                          u_int16_t ip_offset,
                                          u_int16_t ipsize,
                                          u_int16_t l4_packet_len,
                                          u_int16_t l4_offset,
                                          ndpi_tcphdr **tcph,
                                          ndpi_udphdr **udph,
                                          u_int16_t *sport,
                                          u_int16_t *dport,
                                          u_int8_t *proto,
                                          u_int8_t **payload,
                                          u_int16_t *payload_len,
                                          u_int8_t *src_to_dst_direction) {

    u_int32_t idx, hashval;
    ndpi_flow_info flow;
    void *ret;
    const u_int8_t *l3, *l4;
    u_int32_t l4_data_len = 0XFEEDFACE;

    if (version == IPVERSION) {
        if (ipsize < 20)
            return nullptr;

        if ((iph->ihl * 4) > ipsize || ipsize < ntohs(iph->tot_len))
            return nullptr;

        l3 = (const u_int8_t *)iph;
    } else {
        if (l4_offset > ipsize)
            return nullptr;

        l3 = (const u_int8_t *)iph6;
    }

    // ip hszie check
    if (ipsize < l4_offset + l4_packet_len)
        return nullptr;

    *proto = iph->protocol;

    l4 = &((const u_int8_t *)l3)[l4_offset];

    if (*proto == IPPROTO_TCP && l4_packet_len >= sizeof(ndpi_tcphdr)) {
        u_int tcp_len;

        // TCP
        *tcph = (ndpi_tcphdr *)l4;
        *sport = ntohs((*tcph)->source), *dport = ntohs((*tcph)->dest);
        tcp_len = ndpi_min(4 * (*tcph)->doff, l4_packet_len);
        *payload = (u_int8_t *)&l4[tcp_len];
        *payload_len = ndpi_max(0, l4_packet_len - 4 * (*tcph)->doff);
        l4_data_len = l4_packet_len - sizeof(ndpi_tcphdr);

    } else if (*proto == IPPROTO_UDP && l4_packet_len >= sizeof(ndpi_udphdr)) {
        // UDP
        *udph = (ndpi_udphdr *)l4;
        *sport = ntohs((*udph)->source), *dport = ntohs((*udph)->dest);
        *payload = (u_int8_t *)&l4[sizeof(ndpi_udphdr)];
        *payload_len = (l4_packet_len > sizeof(ndpi_udphdr))
                           ? l4_packet_len - sizeof(ndpi_udphdr)
                           : 0;
        l4_data_len = l4_packet_len - sizeof(ndpi_udphdr);

    } else if (*proto == IPPROTO_ICMP) {
        *payload = (u_int8_t *)&l4[sizeof(ndpi_icmphdr)];
        *payload_len = (l4_packet_len > sizeof(ndpi_icmphdr))
                           ? l4_packet_len - sizeof(ndpi_icmphdr)
                           : 0;
        l4_data_len = l4_packet_len - sizeof(ndpi_icmphdr);
        *sport = *dport = 0;

    } else if (*proto == IPPROTO_ICMPV6) {
        *payload = (u_int8_t *)&l4[sizeof(ndpi_icmp6hdr)];
        *payload_len = (l4_packet_len > sizeof(ndpi_icmp6hdr))
                           ? l4_packet_len - sizeof(ndpi_icmp6hdr)
                           : 0;
        l4_data_len = l4_packet_len - sizeof(ndpi_icmp6hdr);
        *sport = *dport = 0;

    } else {
        // non tcp/udp protocols
        *sport = *dport = 0;
        l4_data_len = 0;
    }

    flow.protocol = iph->protocol;
    flow.vlan_id = 0;
    flow.src_ip = iph->saddr, flow.dst_ip = iph->daddr;
    flow.src_port = htons(*sport), flow.dst_port = htons(*dport);
    flow.hashval = hashval = flow.protocol +
                             ntohl(flow.src_ip) +
                             ntohl(flow.dst_ip) +
                             ntohs(flow.src_port) +
                             ntohs(flow.dst_port);

    idx = hashval % workflow->prefs.num_roots;
    ret = ndpi_tfind(&flow,
                     &workflow->ndpi_flows_root[idx],
                     ndpi_workflow_node_cmp);

    // to avoid two nodes in one binary tree for a flow
    int is_changed = 0;
    if (ret == NULL) {
        u_int32_t orig_src_ip = flow.src_ip;
        u_int16_t orig_src_port = flow.src_port;
        u_int32_t orig_dst_ip = flow.dst_ip;
        u_int16_t orig_dst_port = flow.dst_port;

        flow.src_ip = orig_dst_ip;
        flow.src_port = orig_dst_port;
        flow.dst_ip = orig_src_ip;
        flow.dst_port = orig_src_port;

        is_changed = 1;

        ret = ndpi_tfind(&flow,
                         &workflow->ndpi_flows_root[idx],
                         ndpi_workflow_node_cmp);

        if (ret == nullptr) {
            ndpi_flow_info_t *newflow =
                (ndpi_flow_info_t *)ndpi_malloc(sizeof(struct ndpi_flow_info));

            if (newflow == nullptr) {
                return (nullptr);
            } else
                workflow->num_allocated_flows++;

            memset(newflow, 0, sizeof(ndpi_flow_info_t));
            newflow->flow_id = 0;
            newflow->hashval = hashval;
            newflow->protocol = iph->protocol;
            newflow->src_ip = iph->saddr;
            newflow->dst_ip = iph->daddr;
            newflow->src_port = htons(*sport),
            newflow->dst_port = htons(*dport);
            newflow->ip_version = version;

            if (version == IPVERSION) {
                inet_ntop(AF_INET,
                          &newflow->src_ip,
                          newflow->src_name,
                          sizeof(newflow->src_name));
                inet_ntop(AF_INET,
                          &newflow->dst_ip,
                          newflow->dst_name,
                          sizeof(newflow->dst_name));
            } else {
                inet_ntop(AF_INET6,
                          &iph6->ip6_src,
                          newflow->src_name,
                          sizeof(newflow->src_name));
                inet_ntop(AF_INET6,
                          &iph6->ip6_dst,
                          newflow->dst_name,
                          sizeof(newflow->dst_name));
                // For consistency across platforms replace :0: with ::
                ndpi_patchIPv6Address(newflow->src_name);
                ndpi_patchIPv6Address(newflow->dst_name);
            }
            if ((newflow->ndpi_flow = (ndpi_flow_struct *)ndpi_flow_malloc(
                     SIZEOF_FLOW_STRUCT)) == nullptr) {
                ndpi_free_bin(&newflow->payload_len_bin);
                ndpi_free(newflow);
                return (nullptr);
            } else
                memset(newflow->ndpi_flow, 0, SIZEOF_FLOW_STRUCT);

            ndpi_tsearch(newflow,
                         &workflow->ndpi_flows_root[idx],
                         ndpi_workflow_node_cmp);

            return newflow;
        }
    } else {
        ndpi_flow_info_t *rflow = *(ndpi_flow_info_t **)ret;

        if (is_changed) {
            *src_to_dst_direction = 0;
            rflow->bidirectional |= 1;
        } else {
            *src_to_dst_direction = 1;
        }

        return (rflow);
    }

    return nullptr;
}

static ndpi_flow_info *get_ndpi_flow_info6(ndpi_workflow * workflow,
                                           const ndpi_ipv6hdr *iph6,
                                           u_int16_t ip_offset,
                                           u_int16_t ipsize,
                                           ndpi_tcphdr **tcph,
                                           ndpi_udphdr **udph,
                                           u_int16_t *sport,
                                           u_int16_t *dport,
                                           u_int8_t *proto,
                                           u_int8_t **payload,
                                           u_int16_t *payload_len,
                                           u_int8_t *src_to_dst_direction) {
  struct ndpi_iphdr iph;

  if (ipsize < 40)
      return (nullptr);
  memset(&iph, 0, sizeof(iph));
  iph.version = IPVERSION;
  iph.saddr = iph6->ip6_src.u6_addr.u6_addr32[2] +
              iph6->ip6_src.u6_addr.u6_addr32[3];
  iph.daddr = iph6->ip6_dst.u6_addr.u6_addr32[2] +
              iph6->ip6_dst.u6_addr.u6_addr32[3];
  u_int8_t l4proto = iph6->ip6_hdr.ip6_un1_nxt;
  u_int16_t ip_len = ntohs(iph6->ip6_hdr.ip6_un1_plen);
  const u_int8_t *l4ptr = (((const u_int8_t *)iph6) +
                          sizeof(struct ndpi_ipv6hdr));
  if (ipsize < sizeof(struct ndpi_ipv6hdr) + ip_len)
      return (nullptr);

  if (ndpi_handle_ipv6_extension_headers(ipsize - sizeof(struct ndpi_ipv6hdr),
                                         &l4ptr,
                                         &ip_len,
                                         &l4proto) != 0) {
      return (nullptr);
  }
  iph.protocol = l4proto;

  return (get_ndpi_flow_info(workflow,
                             6,
                             &iph,
                             iph6,
                             ip_offset,
                             ipsize,
                             ip_len,
                             l4ptr - (const u_int8_t *)iph6,
                             tcph,
                             udph,
                             sport,
                             dport,
                             proto,
                             payload,
                             payload_len,
                             src_to_dst_direction));
}

static ndpi_proto packet_proc(ndpi_workflow * workflow,
                              const ndpi_iphdr *iph,
                              const ndpi_ipv6hdr *iph6,
                              u_int16_t ip_offset,
                              u_int16_t ipsize,
                              u_int16_t rawsize,
                              const pcap_pkthdr *header,
                              const u_char *packet) {

    ndpi_flow_info *flow = nullptr;
    ndpi_flow_struct *ndpi_flow = nullptr;
    u_int8_t proto;
    ndpi_tcphdr *tcph = nullptr;
    ndpi_udphdr *udph = nullptr;
    u_int16_t sport, dport, payload_len = 0;
    u_int8_t *payload;
    u_int8_t src_to_dst_direction = 1;
    u_int8_t begin_or_end_tcp = 0;
    ndpi_proto nproto = NDPI_PROTOCOL_NULL;

    if (iph)
        flow = get_ndpi_flow_info(workflow,
                                  IPVERSION,
                                  iph,
                                  nullptr,
                                  ip_offset,
                                  ipsize,
                                  ntohs(iph->tot_len) - (iph->ihl * 4),
                                  iph->ihl * 4,
                                  &tcph,
                                  &udph,
                                  &sport,
                                  &dport,
                                  &proto,
                                  &payload,
                                  &payload_len,
                                  &src_to_dst_direction);
    else
        flow = get_ndpi_flow_info6(workflow,
                                   iph6,
                                   ip_offset,
                                   ipsize,
                                   &tcph,
                                   &udph,
                                   &sport,
                                   &dport,
                                   &proto,
                                   &payload,
                                   &payload_len,
                                   &src_to_dst_direction);

    if (flow != nullptr) {
        pkt_timeval tdiff;

        ndpi_flow = flow->ndpi_flow;

    } else {
        return (nproto);
    }

    if (!flow->detection_completed) {
        u_int enough_packets =
            (((proto == IPPROTO_UDP) &&
              ((flow->src2dst_packets + flow->dst2src_packets) > 24)) ||
             ((proto == IPPROTO_TCP) &&
              ((flow->src2dst_packets + flow->dst2src_packets) > 80)))
                ? 1
                : 0;

        flow->detected_protocol = ndpi_detection_process_packet(workflow->ndpi_struct,
                                                                ndpi_flow,
                                                                iph ? (uint8_t *)iph : (uint8_t *)iph6,
                                                                ipsize,
                                                                0);
        if (enough_packets ||
            (flow->detected_protocol.app_protocol != NDPI_PROTOCOL_UNKNOWN)) {

            if ((!enough_packets) && ndpi_extra_dissection_possible(workflow->ndpi_struct,
                                                                    ndpi_flow))
                ; // Wait for certificate fingerprint
            else {
                // New protocol detected or give up
                flow->detection_completed = 1;

                if (flow->detected_protocol.app_protocol == NDPI_PROTOCOL_UNKNOWN) {
                    u_int8_t proto_guessed;

                    flow->detected_protocol = ndpi_detection_giveup(workflow->ndpi_struct,
                                                                    flow->ndpi_flow,
                                                                    true,
                                                                    &proto_guessed);
                }

            }
        }
    }

    return (flow->detected_protocol);
}

static ndpi_proto ndpi_workflow_process_packet(ndpi_workflow * workflow,
                                               pcap_t *pcap_h,
                                               const pcap_pkthdr *header,
                                               const u_char *packet) {

    // unknown protocol
    ndpi_proto nproto = NDPI_PROTOCOL_NULL;

    // headers
    ndpi_ethhdr *ethernet;
    ndpi_llc_header_snap *llc;
    ndpi_iphdr *iph;
    ndpi_ipv6hdr *iph6;

    // offsets/lengths
    u_int32_t eth_offset = 0;
    u_int16_t ip_offset = 0;
    int check = 0;
    int pyld_eth_len = 0;
    u_int16_t type = 0;
    u_int8_t proto = 0;
    u_int16_t frag_off = 0;
    u_int16_t ip_len = 0;

    // get/check datalink layer
    int dlt = pcap_datalink(pcap_h);
    // 20 for min iph and 8 for min UDP
    if (header->caplen < eth_offset + 28)
        return (nproto);

    // process DLT
    switch (dlt) {
        // IEEE 802.3 Ethernet - 1
        case DLT_EN10MB:
            ethernet = (ndpi_ethhdr *)&packet[eth_offset];
            ip_offset = sizeof(ndpi_ethhdr) + eth_offset;
            check = ntohs(ethernet->h_proto);

            if (check <= 1500)
                pyld_eth_len = check;

            else if (check >= 1536)
                type = check;

            if (pyld_eth_len != 0) {
                llc = (struct ndpi_llc_header_snap *)(&packet[ip_offset]);
                // check for LLC layer with SNAP extension
                if (llc->dsap == 0xAA || llc->ssap == 0xAA) {
                    type = llc->snap.proto_ID;
                    ip_offset += +8;
                }
                // No SNAP extension - Spanning Tree pkt must be discarted
                else if (llc->dsap == 0x42 || llc->ssap == 0x42) {
                    return (nproto);
                }
            }
            break;
    }

    // process ether type
    switch(type){
        case ETH_P_VLAN:
        case ETH_P_MPLS_UNI:
        case ETH_P_MPLS_MULTI:
        case ETH_P_PPPoE:
            return (nproto);
            break;

        default:
            break;
    }

    // IP check
    if (header->caplen < ip_offset + sizeof(ndpi_iphdr))
        return (nproto);

    iph = (ndpi_iphdr *)&packet[ip_offset];

    // just work on Ethernet packets that contain IP
    if (type == ETH_P_IP && header->caplen >= ip_offset) {
        frag_off = ntohs(iph->frag_off);
        proto = iph->protocol;

    }

    // IPv4
    if (iph->version == IPVERSION) {
        ip_len = ((u_int16_t)iph->ihl * 4);
        iph6 = NULL;

        if (iph->protocol == IPPROTO_IPV6) {
            return (nproto);
        }

        if ((frag_off & 0x1FFF) != 0) {
            return (nproto);
        }

    // IPv6
    } else if (iph->version == 6) {
        if (header->caplen < ip_offset + sizeof(ndpi_ipv6hdr))
            return (nproto);

        iph6 = (ndpi_ipv6hdr *)&packet[ip_offset];
        proto = iph6->ip6_hdr.ip6_un1_nxt;
        ip_len = ntohs(iph6->ip6_hdr.ip6_un1_plen);

        if (header->caplen < (ip_offset + sizeof(ndpi_ipv6hdr) +
                              ntohs(iph6->ip6_hdr.ip6_un1_plen)))
            return (nproto);

        const u_int8_t *l4ptr = (((const u_int8_t *)iph6) +
                                sizeof(ndpi_ipv6hdr));
        u_int16_t ipsize = header->caplen - ip_offset;

        if (ndpi_handle_ipv6_extension_headers(ipsize - sizeof(ndpi_ipv6hdr),
                                               &l4ptr,
                                               &ip_len,
                                               &proto) != 0) {
            return (nproto);
        }

        if (proto == IPPROTO_IPV6 || proto == IPPROTO_IPIP) {
            return (nproto);
        }

        iph = NULL;
    } else {

        return (nproto);
    }


    // process the packet
    return (packet_proc(workflow,
                        iph,
                        iph6,
                        ip_offset,
                        header->caplen - ip_offset,
                        header->caplen,
                        header,
                        packet));

}


static void ndpi_process_packet(u_char *args,
                                const pcap_pkthdr *header,
                                const u_char *packet) {

    ndpi_workflow_t *workflow = (ndpi_workflow_t *)args;
    pcap_t *pcap_h = workflow->pcap_handle;

    ndpi_proto p = ndpi_workflow_process_packet(workflow,
                                                pcap_h,
                                                header,
                                                packet);
/*
    if (p.app_protocol != NDPI_PROTOCOL_UNKNOWN)
        std::cout << "app: "
                  << ndpi_get_proto_name(workflow->ndpi_struct, p.app_protocol)
                  << " ";
    if (p.master_protocol != NDPI_PROTOCOL_UNKNOWN)
        std::cout << "master: "
                  << ndpi_get_proto_name(workflow->ndpi_struct,
                                         p.master_protocol)
                  << " ";

    if (p.app_protocol != NDPI_PROTOCOL_UNKNOWN ||
        p.master_protocol != NDPI_PROTOCOL_UNKNOWN)
        std::cout << std::endl;
*/
    // inc stats
    if (p.app_protocol != NDPI_PROTOCOL_UNKNOWN) {
        auto pn = ndpi_get_proto_name(workflow->ndpi_struct, p.app_protocol);
        workflow->pcap_d->inc_stats(pn);

    } else if (p.master_protocol != NDPI_PROTOCOL_UNKNOWN) {
        auto pn = ndpi_get_proto_name(workflow->ndpi_struct, p.master_protocol);
        workflow->pcap_d->inc_stats(pn);
    }
}

/*************************/
/* packet capture thread */
/*************************/
static void thread_proc_packet(Pcap_d *pcap_d){
    int sl = 1536;
    int promisc = 1;
    char pcap_err_b[PCAP_ERRBUF_SIZE];
    pcap_t *pcap_h = nullptr;
    ndpi_detection_module_struct *m = nullptr;

    // setuo
    try {
        // pcap handle
        pcap_h = pcap_open_live(pcap_d->get_if().c_str(),
                                sl,
                                promisc,
                                500,
                                pcap_err_b);
        if (!pcap_h) {
            throw std::invalid_argument("cannot start packet capture");
        }
        // set pcap handle
        pcap_d->set_pcap_h(pcap_h);

        // datalink type check
        int dlt = pcap_datalink(pcap_h);
        if (!ndpi_is_datalink_supported(dlt)) {
            throw std::invalid_argument("unsupported datalink type");
        }

        // ndpi detection module
        NDPI_PROTOCOL_BITMASK all;
        set_ndpi_malloc(ndpi_malloc_wrapper);
        set_ndpi_free(free_wrapper);
        set_ndpi_flow_malloc(nullptr);
        set_ndpi_flow_free(nullptr);
        m = ndpi_init_detection_module(ndpi_no_prefs);
        if (!m) {
            throw std::invalid_argument("cannot create ndpi detection module");
        }

        // set ndpi bitmask
        NDPI_BITMASK_SET_ALL(all);
        ndpi_set_protocol_detection_bitmask2(m, &all);
        ndpi_finalize_initialization(m);

    } catch (std::exception &e) {
        mink::CURRENT_DAEMON->log(mink::LLT_ERROR,
                                  "plg_ndpi: [%s]",
                                  e.what());
        // cleanup
        if (pcap_h) pcap_close(pcap_h);
        if (m) ndpi_exit_detection_module(m);
        return;
    }

    // init workflow struct
    ndpi_workflow_t *workflow = (ndpi_workflow_t *)ndpi_calloc(1, sizeof(ndpi_workflow_t));
    workflow->ndpi_flows_root = (void **)ndpi_calloc(512, sizeof(void *));
    workflow->ndpi_struct = m;
    workflow->prefs.num_roots = 512;
    workflow->pcap_handle = pcap_h;
    workflow->pcap_d = pcap_d;

    // process packets
    int r = pcap_loop(pcap_h, -1, &ndpi_process_packet, (u_char *)workflow);
    if (r == -1) {
        ndpi_exit_detection_module(m);
        ndpi_free(workflow->ndpi_flows_root);
        ndpi_free(workflow);
        pcap_close(pcap_h);
        throw std::invalid_argument("error while capturing packets");
    }

    // cleanup
    ndpi_exit_detection_module(m);
    ndpi_free(workflow->ndpi_flows_root);
    ndpi_free(workflow);
    pcap_close(pcap_h);
}

/********************************/
/* Process static configuration */
/********************************/
static int process_cfg(mink_utils::PluginManager *pm) {
    json *pcfg = nullptr;
    // get config
    try {
        pcfg = plg_get_config();

    } catch (std::exception &e) {
            mink::CURRENT_DAEMON->log(mink::LLT_ERROR, "plg_ndpi: [%s]",
                                      e.what());
            return -1;
    }

    // process
    try {
        // get interfaces
        auto j_if_lst = pcfg->at("interfaces");
        // loop interfaces
        for(auto it_if = j_if_lst.begin(); it_if != j_if_lst.end(); ++ it_if) {
            // sanity check
            if(!it_if->is_string()){
                throw std::invalid_argument("interface != string");
            }
            // add interface
            Pcap_d &pcap_d = pcap_mngr.add_pcap(*it_if);
            // init process match thread
            std::thread th(&thread_proc_packet, &pcap_d);
            th.detach();
        }

    } catch(std::exception &e) {
        mink::CURRENT_DAEMON->log(mink::LLT_ERROR,
                                  "plg_ndpi: [%s]", e.what());
        return -3;
    }

    return 0;
}

/****************/
/* init handler */
/****************/
extern "C" int init(mink_utils::PluginManager *pm, mink_utils::PluginDescriptor *pd){
    // process cfg
    if (process_cfg(pm)) {
        mink::CURRENT_DAEMON->log(mink::LLT_ERROR,
                                  "plg_ndpi: [cannot process plugin configuration]");
        return 1;
    }

    return 0;
}

/*********************/
/* terminate handler */
/*********************/
extern "C" int terminate(mink_utils::PluginManager *pm, mink_utils::PluginDescriptor *pd){
    return 0;
}

/**********************/
/* CMD_NDPI_GET_STATS */
/**********************/
static void do_get_stats(const std::string &if_n, json *j_d) {
    // get pcap descriptor
    auto pcap_d = pcap_mngr.get_pcap(if_n);
    // get stats
    std::map<std::string, uint64_t> out;
    pcap_d.get_stats(out);
    // contruct json rpc reply
    if (j_d) {
        (*j_d)[Jrpc::RESULT_].push_back(out);
    }
}


/****************************/
/* local CMD_NDPI_GET_STATS */
/****************************/
static void impl_local_get_stats(json_rpc::JsonRpc &jrpc, json *j_d) {
    std::string if_n;

    // process params
    jrpc.process_params([&if_n](int id, const std::string &s) {
        // address
        if (id == gdt_grpc::PT_NDPI_IF) {
            if_n = s;
        }
        return true;
    });

    // run
    if (if_n.empty()) {
        throw std::invalid_argument("interface name is missing");
    }
    do_get_stats(if_n, j_d);


}
/******************************/
/* plg2plg CMD_NDPI_GET_STATS */
/******************************/
static void impl_local_get_stats(mink_utils::Plugin_data_std *args) {
    // check args
    if (!(args && args->size() > 0))
        return;
    // interface
    std::string if_s = args->at(0).cbegin()->second;
    // clear args (will be used for output)
    args->clear();
    // get pcap descriptor
    auto pcap_d = pcap_mngr.get_pcap(if_s);
    // get stats
    std::map<std::string, uint64_t> out;
    pcap_d.get_stats(out);
    // prepare output
    for (auto it = out.cbegin(); it != out.cend(); ++it) {
        // column map
        std::map<std::string, std::string> cmap;
        // insert columns
        cmap.insert(std::make_pair(it->first, std::to_string(it->second)));
        // add row
        args->push_back(cmap);
    }
}

/*************************/
/* local command handler */
/*************************/
extern "C" int run_local(mink_utils::PluginManager *pm,
                         mink_utils::PluginDescriptor *pd,
                         int cmd_id,
                         mink_utils::PluginInputData &p_id){
    // sanity/type check
    if (!p_id.data())
        return -1;

    // UNIX socket local interface
    if(p_id.type() == mink_utils::PLG_DT_JSON_RPC){
        json *j_d = static_cast<json *>(p_id.data());
        int id = -1;
        int cmd_id = -1;
        try {
            // create json rpc parser
            Jrpc jrpc(*j_d);
            // verify
            jrpc.verify(true);
            // get method
            cmd_id = jrpc.get_method_id();
            // get JSON RPC id
            id = jrpc.get_id();
            // check command id
            switch (cmd_id) {
                case gdt_grpc::CMD_NDPI_GET_STATS:
                    impl_local_get_stats(jrpc, j_d);
                    break;

                default:
                    break;
            }

        } catch (std::exception &e) {
            mink::CURRENT_DAEMON->log(mink::LLT_ERROR,
                                      "plg_modbus: [%s]",
                                      e.what());
            auto j_err = Jrpc::gen_err(id, e.what());
            (*j_d)[Jrpc::ERROR_] = j_err[Jrpc::ERROR_];
        }
        return 0;
    }

    // plugin2plugin local interface (standard)
    if(p_id.type() == mink_utils::PLG_DT_STANDARD){
        // plugin in/out data
        auto *plg_d = static_cast<mink_utils::Plugin_data_std *>(p_id.data());
        // check cmd
        switch (cmd_id) {
            case gdt_grpc::CMD_NDPI_GET_STATS:
                impl_local_get_stats(plg_d);
                break;
        }

        return 0;
    }

    // unknown interface
    return -1;

}


/*******************/
/* command handler */
/*******************/
extern "C" int run(mink_utils::PluginManager *pm,
                   mink_utils::PluginDescriptor *pd,
                   int cmd_id,
                   mink_utils::PluginInputData &p_id){

    // sanity/type check
    if (!(p_id.data() && p_id.type() == mink_utils::PLG_DT_GDT))
        return 1;

    return 0;
}

