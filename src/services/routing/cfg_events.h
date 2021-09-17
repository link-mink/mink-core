/*            _       _
 *  _ __ ___ (_)_ __ | | __
 * | '_ ` _ \| | '_ \| |/ /
 * | | | | | | | | | |   <
 * |_| |_| |_|_|_| |_|_|\_\
 *
 * SPDX-License-Identifier: MIT
 *
 */

#ifndef CFG_EVENTS_H_
#define CFG_EVENTS_H_

#include <gdt.h>
#include <mink_config.h>

class WRRConfigMod: public config::CfgNtfCallback {
public:
    WRRConfigMod() = default;
    void run(config::ConfigItem *cfg, 
             unsigned int mod_index,
             unsigned int mod_count) override;

    gdt::GDTSession* gdts = nullptr;
};




#endif /* CFG_EVENTS_H_ */
