/*            _       _
 *  _ __ ___ (_)_ __ | | __
 * | '_ ` _ \| | '_ \| |/ /
 * | | | | | | | | | |   <
 * |_| |_| |_|_|_| |_|_|\_\
 *
 * SPDX-License-Identifier: MIT
 *
 */

#include "cfg_events.h"
#include "routing.h"

WRRConfigMod::WRRConfigMod() : gdts(NULL) {}

void WRRConfigMod::run(config::ConfigItem *cfg, 
                       unsigned int mod_index,
                       unsigned int mod_count) {
    // sanity check
    if (gdts->get_routing_handler() == NULL)
        return;
    // rebuild WRR rules
    config::ConfigItem *dests_root = cfg->children[0];
    // get destinations root
    dests_root = dests_root->find_parent("destinations");
    // sanity check
    if (dests_root == NULL)
        return;
    // tmp vars
    config::ConfigItem *dest_node_type = NULL;
    config::ConfigItem *nodes = NULL;
    config::ConfigItem *dest_node = NULL;
    config::ConfigItem *tmp_node = NULL;
    mink_utils::PooledVPMap<uint32_t> tmp_params;
    gdt::GDTClient *gdtc = NULL;
    mink_utils::WRRItem<gdt::GDTClient *> *wrr_item = NULL;
    // lock
    gdts->lock_clients();
    // clear current routing config
    // gdts->get_routing_handler()->clear();
    // loop destinations
    for (unsigned int i = 0; i < dests_root->children.size(); i++) {
        dest_node_type = dests_root->children[i];
        // dest type deleted, continue
        if (dest_node_type->node_state == config::CONFIG_NS_DELETED) {
            mink::CURRENT_DAEMON->log(mink::LLT_DEBUG,
                                      "Removing [%s] routing table...",
                                      dest_node_type->name.c_str());

            gdts->get_routing_handler()->remove_type(
                dest_node_type->name.c_str());
            continue;
        }
        // log
        mink::CURRENT_DAEMON->log(mink::LLT_DEBUG,
                                   "Processing configuration for destination "
                                   "type [%s] for node [%s]...",
                                   dest_node_type->name.c_str(),
                                   mink::CURRENT_DAEMON->get_daemon_id());

        // check for nodes
        if ((*dest_node_type)("nodes") == NULL) {
            mink::CURRENT_DAEMON->log(mink::LLT_WARNING,
                                       "Missing destination [%s] nodes "
                                       "configuration node set for node [%s]!",
                                       dest_node_type->name.c_str(),
                                       mink::CURRENT_DAEMON->get_daemon_id());
            continue;
        }
        // get nodes
        nodes = (*dest_node_type)("nodes");

        // process nodes
        for (unsigned int j = 0; j < nodes->children.size(); j++) {
            dest_node = nodes->children[j];
            // dest node deleted, continue
            if (dest_node->node_state == config::CONFIG_NS_DELETED) {
                // log
                mink::CURRENT_DAEMON->log(mink::LLT_DEBUG,
                                          "Removing node [%s] from [%s] routing table...",
                                           dest_node->name.c_str(), 
                                           dest_node_type->name.c_str());

                gdts->get_routing_handler()->remove_node(dest_node_type->name.c_str(), 
                                                         dest_node->name.c_str());
                continue;

                // new node
            } else if (dest_node->is_new) {
                // log
                mink::CURRENT_DAEMON->log(mink::LLT_DEBUG,
                                          "Adding node [%s] to [%s] routing "
                                          "table with weight [%d]...",
                                          dest_node->name.c_str(),
                                          dest_node_type->name.c_str(),
                                          dest_node->to_int("weight"));

                // set weight data
                tmp_params.set_int(0, dest_node->to_int("weight"));
                // check for gdt client connection
                gdtc =
                    gdts->get_registered_client(dest_node_type->name.c_str(),
                                                dest_node->name.c_str(), 
                                                true);
                // add to routing handler
                gdts->get_routing_handler()->add_node(gdtc, 
                                                      dest_node_type->name.c_str(),
                                                      dest_node->name.c_str(), 
                                                      &tmp_params);

                // modified node
            } else {
                tmp_node = (*dest_node)("weight");
                // check if modified
                if (tmp_node != NULL) {
                    if (tmp_node->node_state == config::CONFIG_NS_MODIFIED) {
                        // log
                        mink::CURRENT_DAEMON->log(mink::LLT_DEBUG,
                                                  "Setting weight to [%d] for node [%s] in [%s] "
                                                  "routing table...",
                                                  tmp_node->to_int(), 
                                                  dest_node->name.c_str(),
                                                  dest_node_type->name.c_str());

                        // get item
                        wrr_item = (mink_utils::WRRItem<gdt::GDTClient *> *)gdts
                                ->get_routing_handler()
                                ->get_node(dest_node_type->name.c_str(),
                                           dest_node->name.c_str());
                        // set weight
                        if (wrr_item != NULL && wrr_item->item != NULL) {
                            wrr_item->weight = tmp_node->to_int();
                            // recalc (done in update client)
                            gdts->get_routing_handler()->update_client(
                                wrr_item->item,
                                wrr_item->item->get_end_point_daemon_type(),
                                wrr_item->item->get_end_point_daemon_id());
                        }

                    } else if (tmp_node->node_state == config::CONFIG_NS_DELETED) {
                        // log
                        mink::CURRENT_DAEMON->log(mink::LLT_DEBUG,
                                                  "Disabling node [%s] in [%s] routing table, "
                                                  "setting weight to [0]",
                                                  dest_node->name.c_str(),
                                                  dest_node_type->name.c_str());

                        // get item
                        wrr_item = (mink_utils::WRRItem<gdt::GDTClient *> *)gdts
                                ->get_routing_handler()
                                ->get_node(dest_node_type->name.c_str(),
                                           dest_node->name.c_str());
                        // set weight
                        if (wrr_item != NULL && wrr_item->item != NULL) {
                            wrr_item->weight = 0;
                            // recalc (done in update client)
                            gdts->get_routing_handler()->update_client(wrr_item->item,
                                                                       wrr_item->item
                                                                               ->get_end_point_daemon_type(),
                                                                       wrr_item->item
                                                                               ->get_end_point_daemon_id());
                        }
                    }
                }
            }
        }
    }
    // unlock
    gdts->unlock_clients();
}
