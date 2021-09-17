/*            _       _
 *  _ __ ___ (_)_ __ | | __
 * | '_ ` _ \| | '_ \| |/ /
 * | | | | | | | | | |   <
 * |_| |_| |_|_|_| |_|_|\_\
 *
 * SPDX-License-Identifier: MIT
 *
 */

#ifndef GDT_REG_EVENTS_H_
#define GDT_REG_EVENTS_H_

#include <gdt.h>

namespace gdt {

    // fwd declaration
    class RegClientStreamDone;


    // Client registration stream done
    class RegClientStreamNew: public GDTCallbackMethod {
    public:
        explicit RegClientStreamNew(GDTClient* _client);
        ~RegClientStreamNew() override;

        // event handler method
        void run(gdt::GDTCallbackArgs* args) override;

        // members
        uint32_t pm_dtype;
        uint32_t pm_did;
        uint32_t pm_router;
        uint32_t reg_action;
        int router_flag;
        GDTClient* client;
        GDTCallbackMethod* sdone;
        mink::Atomic<uint8_t> done_signal;
        int status;

    };

    // Client registration stream next
    class RegClientStreamDone: public GDTCallbackMethod {
    public:
        // event handler method
        void run(gdt::GDTCallbackArgs* args) override;
        // members
        RegClientStreamNew* snew;
    };
}

#endif /* GDT_REG_EVENTS_H_ */
