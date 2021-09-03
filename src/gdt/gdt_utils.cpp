/*            _       _
 *  _ __ ___ (_)_ __ | | __
 * | '_ ` _ \| | '_ \| |/ /
 * | | | | | | | | | |   <
 * |_| |_| |_|_|_| |_|_|\_\
 *
 * SPDX-License-Identifier: MIT
 *
 */

#include <endian.h>
#include <errno.h>
#include <iomanip>
#include <gdt_utils.h>

bool gdt::ServiceParam::FRAGMENTATION_DONE = false;
bool gdt::ServiceParam::FRAGMENTATION_NEXT = true;
gdt::ServiceMessageAsyncDone gdt::ServiceMsgManager::cb_async_done;

gdt::ServiceParam::ServiceParam() {
    memset(data, 0, sizeof(data));
    data_p = data;
    in_data_p = data_p;
    data_size = 0;
    total_data_size = 0;
    id = 0;
    index = 0;
    extra_type = 0;
    fragment_index = 0;
    fragmented = false;
    fragments = 0;
    type = SPT_UNKNOWN;
    thread_safe = false;
    param_fctry = NULL;
    param_data_cb = &param_data_default;
    pthread_mutex_init(&mtx, NULL);
    linked_index = 0;
}

gdt::ServiceParam::~ServiceParam() { pthread_mutex_destroy(&mtx); }

void gdt::ServiceParam::fragment(const void *_data, unsigned int _data_size) {
    // set in data pointer
    in_data_p = _data;
    // set first fragment data
    data_size = 256;
    total_data_size = _data_size;
    // get param count needed to fit data size
    int pc = _data_size / 256;
    // remainder
    int rem = _data_size % 256;
    // set fragment index
    fragment_index = 0;
    // set total number of fragments
    fragments = pc + (rem > 0 ? 1 : 0);
    // set fragmentation flag
    fragmented = true;
}

int gdt::ServiceParam::param_data_file(ServiceParam *sc_param,
                                       const void *in,
                                       int in_size) {
    FILE *f = (FILE *)in;

    // get tmp service param buffer
    if (sc_param->linked_index >= sc_param->linked.size())
        sc_param->linked_index = 0;
    ServiceParam *new_sc_param = sc_param->linked[sc_param->linked_index++];
    // read file
    int bc = fread(new_sc_param->data, 1, sizeof(new_sc_param->data), f);
    // decrement from previous fread
    sc_param->total_data_size -= sc_param->data_size;

    // switch buffer of original param with new one
    sc_param->data_p = new_sc_param->data;
    // set data size
    sc_param->data_size = bc;
    return bc;
}

int gdt::ServiceParam::param_data_default(ServiceParam *sc_param, 
                                          const void *in,
                                          int in_size) {
    // calculate number of bytes needed for current fragment
    int bc = (sc_param->total_data_size > sizeof(sc_param->data)
                  ? sizeof(sc_param->data)
                  : sc_param->total_data_size);

    sc_param->data_p += bc;
    sc_param->total_data_size -= bc;
    return bc;
}

int gdt::ServiceParam::set_data(FILE *_data, unsigned int _file_size) {
    lock();
    if (_file_size > 256) {
        // file param data fetch method
        param_data_cb = &param_data_file;
        // fragmentation
        fragment(_data, _file_size);
        // read initial block
        data_size = fread(data, 1, 256, _data);
        // data_p points to internal buffer
        data_p = data;
        unlock();
        return 0;
    }
    fragmented = false;
    // read initial block
    data_size = fread(data, 1, 256, _data);
    total_data_size = data_size;
    data_p = data;
    unlock();
    return 0;
}

void gdt::ServiceParam::set(mink_utils::VariantParam *vparam) {
    switch (vparam->get_type()) {
    case mink_utils::DPT_INT: {
        uint64_t tmp = htobe64(vparam->get_data()->i64);
        set_data(&tmp, sizeof(tmp));
        extra_type = vparam->get_type();
        break;
    }
    case mink_utils::DPT_STRING:
        set_data(vparam->get_data()->str, vparam->get_size());
        extra_type = vparam->get_type();
        break;

    case mink_utils::DPT_DOUBLE:
        set_data(&vparam->get_data()->d, vparam->get_size());
        extra_type = vparam->get_type();
        break;

    case mink_utils::DPT_CHAR:
        set_data(&vparam->get_data()->c, vparam->get_size());
        extra_type = vparam->get_type();
        break;

    case mink_utils::DPT_BOOL:
        set_data(&vparam->get_data()->b, vparam->get_size());
        extra_type = vparam->get_type();
        break;

    case mink_utils::DPT_OCTETS:
        set_data(vparam->get_data()->str, vparam->get_size());
        extra_type = vparam->get_type();
        break;

    default:
        break;
    }
}

int gdt::ServiceParam::set_data(const void *_data, unsigned int _data_size) {
    lock();
    if (_data_size > 256) {
        // default param data fetch method
        param_data_cb = &param_data_default;
        // fragmentation
        fragment(_data, _data_size);
        // set data pointer (fragmented stream does not imply copying of data)
        data_p = (unsigned char *)_data;
        unlock();
        return 0;
    }
    fragmented = false;
    memcpy(data, _data, _data_size);
    data_size = _data_size;
    total_data_size = _data_size;
    data_p = data;
    unlock();
    return 0;
}

void gdt::ServiceParam::std_out() {
    lock();
    std::cout << data << std::endl;
    unlock();
}

unsigned char *gdt::ServiceParam::get_data() { return data; }

unsigned char *gdt::ServiceParam::get_data_p() { return data_p; }

void gdt::ServiceParam::set_data_p(unsigned char *_data_p) {
    data_p = _data_p;
}

void gdt::ServiceParam::reset_data_p() {
    data_p = data;
    in_data_p = data_p;
}

int gdt::ServiceParam::get_data_size() {
    lock();
    unsigned int tmp = data_size;
    unlock();
    return tmp;
}

void gdt::ServiceParam::inc_total_data_size(unsigned int _inc) {
    total_data_size += _inc;
    ++fragment_index;
}

int gdt::ServiceParam::get_total_data_size() const { return total_data_size; }

void gdt::ServiceParam::reset() {
    lock();
    data_size = 0;
    unlock();
    id = 0;
    fragmented = false;
    param_data_cb = &param_data_default;
}

void gdt::ServiceParam::set_thread_safety(bool _thread_safe) {
    thread_safe = _thread_safe;
}

void gdt::ServiceParam::set_param_factory(ServiceParamFactory *_pfact) {
    param_fctry = _pfact;
}

bool gdt::ServiceParam::is_fragmented() const { return fragmented; }

bool *gdt::ServiceParam::get_fragmentation_p() { return &fragmented; }

uint32_t gdt::ServiceParam::get_index() const { return index; }

int gdt::ServiceParam::get_extra_type() const { return extra_type; }

void gdt::ServiceParam::set_extra_type(int type) { extra_type = type; }

int gdt::ServiceParam::get_fragment_index() const { return fragment_index; }

void gdt::ServiceParam::set_fragmented(bool _fragmented) {
    fragmented = _fragmented;
}

void gdt::ServiceParam::set_callback(GDTEventType type,
                                      GDTCallbackMethod *cback) {
    cb_handler.set_callback(type, cback);
}

bool gdt::ServiceParam::process_callback(GDTEventType type,
                                          GDTCallbackArgs *args) {
    return cb_handler.process_callback(type, args);
}

void gdt::ServiceParam::clear_callbacks() { cb_handler.clear(); }

void gdt::ServiceParam::lock() {
    if (thread_safe)
        pthread_mutex_lock(&mtx);
}

void gdt::ServiceParam::unlock() {
    if (thread_safe)
        pthread_mutex_unlock(&mtx);
}

gdt::ServiceParamType gdt::ServiceParam::get_type() const { return type; }

void gdt::ServiceParam::set_id(uint32_t _id) { id = htobe32(_id); }

void gdt::ServiceParam::set_index(uint32_t idx) { index = idx; }

uint32_t gdt::ServiceParam::get_id() { return be32toh(id); }

uint32_t *gdt::ServiceParam::get_idp() { return &id; }

gdt::ServiceParamVARIANT::ServiceParamVARIANT() { type = SPT_VARIANT; }

gdt::ServiceParamVARIANT::~ServiceParamVARIANT() {}

int gdt::ServiceParamVARIANT::extract(void *_out) {
    lock();
    switch (extra_type) {
    case mink_utils::DPT_INT: {
        uint64_t *res = (uint64_t *)_out;
        uint64_t *src = (uint64_t *)data;
        lock();
        // Big endian -> little endian
        *res = be64toh(*src);
        break;
    }

    default:
        memcpy(_out, data, data_size);
        break;
    }
    unlock();
    return 0;
}

int gdt::ServiceParamVARIANT::set_data(void *_data, unsigned int _data_size) {
    return ServiceParam::set_data(_data, _data_size);
}

void gdt::ServiceParamVARIANT::std_out() {
    lock();
    for (unsigned int k = 0; k < data_size; k++) {
        std::cout << std::setfill('0') << std::setw(2) << std::hex
                  << (int)(data[k] & 0xff) << " ";
    }
    unlock();
    std::cout << std::dec << std::endl;
}

gdt::ServiceParamUNKNOWN::ServiceParamUNKNOWN() { type = SPT_UNKNOWN; }

gdt::ServiceParamUNKNOWN::~ServiceParamUNKNOWN() {}

int gdt::ServiceParamUNKNOWN::extract(void *_out) {
    lock();
    memcpy(_out, data, data_size);
    unlock();
    return 0;
}

int gdt::ServiceParamUNKNOWN::set_data(void *_data, unsigned int _data_size) {
    return ServiceParam::set_data(_data, _data_size);
}

void gdt::ServiceParamUNKNOWN::std_out() {
    lock();
    for (unsigned int k = 0; k < data_size; k++) {
        std::cout << std::setfill('0') << std::setw(2) << std::hex
                  << (int)(data[k] & 0xff) << " ";
    }
    unlock();
    std::cout << std::dec << std::endl;
}

gdt::ServiceParamBOOL::ServiceParamBOOL() { type = SPT_BOOL; }

gdt::ServiceParamBOOL::~ServiceParamBOOL() {}

int gdt::ServiceParamBOOL::extract(void *_out) {
    bool *res = (bool *)_out;
    bool *src = (bool *)data;
    lock();
    *res = *src;
    unlock();
    // success
    return 0;
}

int gdt::ServiceParamBOOL::set_bool(bool _data) {
    return ServiceParam::set_data(&_data, sizeof(bool));
}

void gdt::ServiceParamBOOL::std_out() {
    bool *tmp = (bool *)data;
    lock();
    std::cout << *tmp << std::endl;
    unlock();
}

gdt::ServiceParamUINT32::ServiceParamUINT32() { type = SPT_UINT32; }

gdt::ServiceParamUINT32::~ServiceParamUINT32() {}

int gdt::ServiceParamUINT32::extract(void *_out) {
    uint32_t *res = (uint32_t *)_out;
    uint32_t *src = (uint32_t *)data;
    lock();
    // Big endian -> little endian
    *res = be32toh(*src);
    unlock();
    // success
    return 0;
}

int gdt::ServiceParamUINT32::set_uint32(uint32_t _data) {
    uint32_t tmp = htobe32(_data);
    return ServiceParam::set_data(&tmp, sizeof(uint32_t));
}

void gdt::ServiceParamUINT32::std_out() {
    uint32_t *tmp = (uint32_t *)data;
    lock();
    std::cout << be32toh(*tmp) << std::endl;
    unlock();
}

gdt::ServiceParamUINT64::ServiceParamUINT64() { type = SPT_UINT64; }

gdt::ServiceParamUINT64::~ServiceParamUINT64() {}

void gdt::ServiceParamUINT64::std_out() {
    uint64_t *tmp = (uint64_t *)data;
    lock();
    std::cout << be64toh(*tmp) << std::endl;
    unlock();
}

int gdt::ServiceParamUINT64::extract(void *_out) {
    uint64_t *res = (uint64_t *)_out;
    uint64_t *src = (uint64_t *)data;
    lock();
    // Big endian -> little endian
    *res = be64toh(*src);
    unlock();
    // success
    return 0;
}

int gdt::ServiceParamUINT64::set_uint64(uint64_t _data) {
    uint64_t tmp = htobe64(_data);
    return ServiceParam::set_data(&tmp, sizeof(uint64_t));
}

gdt::ServiceParamCString::ServiceParamCString() { type = SPT_CSTRING; }

gdt::ServiceParamCString::~ServiceParamCString() {}

int gdt::ServiceParamCString::extract(void *_out) {
    char *_out_cs = (char *)_out;
    lock();
    strncpy(_out_cs, (char *)data, strlen((char *)data) + 1);
    unlock();
    // success
    return 0;
}

void gdt::ServiceParamCString::set_cstring(char *cstring) {
    if (cstring == NULL) {
        data_size = 0;
        return;
    }
    set_data(cstring, strlen(cstring) + 1);
}

gdt::ServiceParamOctets::ServiceParamOctets() { type = SPT_OCTETS; }

gdt::ServiceParamOctets::~ServiceParamOctets() {}

int gdt::ServiceParamOctets::extract(void *_out) {
    lock();
    memcpy(_out, data, data_size);
    unlock();
    // success
    return 0;
}

void gdt::ServiceParamOctets::std_out() {
    lock();
    for (unsigned int k = 0; k < data_size; k++) {
        std::cout << std::setfill('0') << std::setw(2) << std::hex
                  << (int)(data[k] & 0xff) << " ";
    }
    unlock();
    std::cout << std::dec << std::endl;
}

gdt::ServiceParamFactory::ServiceParamFactory(bool _pooled,
                                              bool _th_safe,
                                              unsigned int pool_size) {
    pooled = _pooled;

    if (pooled) {

        cstr_pool.init(pool_size);
        cstr_pool.construct_objects();

        oct_pool.init(pool_size);
        oct_pool.construct_objects();

        uint32_pool.init(pool_size);
        uint32_pool.construct_objects();

        uint64_pool.init(pool_size);
        uint64_pool.construct_objects();

        unknown_pool.init(pool_size);
        unknown_pool.construct_objects();

        bool_pool.init(pool_size);
        bool_pool.construct_objects();

        var_pool.init(pool_size);
        var_pool.construct_objects();

        ServiceParam *tmp_arr[pool_size];

        // cstr
        for (unsigned int i = 0; i < pool_size; i++) {
            tmp_arr[i] = cstr_pool.allocate_constructed();
            tmp_arr[i]->set_thread_safety(_th_safe);
            tmp_arr[i]->set_param_factory(this);
        }
        for (unsigned int i = 0; i < pool_size; i++)
            cstr_pool.deallocate_constructed((ServiceParamCString *)tmp_arr[i]);

        // oct
        for (unsigned int i = 0; i < pool_size; i++) {
            tmp_arr[i] = oct_pool.allocate_constructed();
            tmp_arr[i]->set_thread_safety(_th_safe);
            tmp_arr[i]->set_param_factory(this);
        }
        for (unsigned int i = 0; i < pool_size; i++)
            oct_pool.deallocate_constructed((ServiceParamOctets *)tmp_arr[i]);

        // uint32
        for (unsigned int i = 0; i < pool_size; i++) {
            tmp_arr[i] = uint32_pool.allocate_constructed();
            tmp_arr[i]->set_thread_safety(_th_safe);
            tmp_arr[i]->set_param_factory(this);
        }
        for (unsigned int i = 0; i < pool_size; i++)
            uint32_pool.deallocate_constructed(
                (ServiceParamUINT32 *)tmp_arr[i]);

        // uint64
        for (unsigned int i = 0; i < pool_size; i++) {
            tmp_arr[i] = uint64_pool.allocate_constructed();
            tmp_arr[i]->set_thread_safety(_th_safe);
            tmp_arr[i]->set_param_factory(this);
        }
        for (unsigned int i = 0; i < pool_size; i++)
            uint64_pool.deallocate_constructed(
                (ServiceParamUINT64 *)tmp_arr[i]);

        // unknown
        for (unsigned int i = 0; i < pool_size; i++) {
            tmp_arr[i] = unknown_pool.allocate_constructed();
            tmp_arr[i]->set_thread_safety(_th_safe);
            tmp_arr[i]->set_param_factory(this);
        }
        for (unsigned int i = 0; i < pool_size; i++)
            unknown_pool.deallocate_constructed(
                (ServiceParamUNKNOWN *)tmp_arr[i]);

        // bool
        for (unsigned int i = 0; i < pool_size; i++) {
            tmp_arr[i] = bool_pool.allocate_constructed();
            tmp_arr[i]->set_thread_safety(_th_safe);
            tmp_arr[i]->set_param_factory(this);
        }
        for (unsigned int i = 0; i < pool_size; i++)
            bool_pool.deallocate_constructed((ServiceParamBOOL *)tmp_arr[i]);

        // var
        for (unsigned int i = 0; i < pool_size; i++) {
            tmp_arr[i] = var_pool.allocate_constructed();
            tmp_arr[i]->set_thread_safety(_th_safe);
            tmp_arr[i]->set_param_factory(this);
        }
        for (unsigned int i = 0; i < pool_size; i++)
            var_pool.deallocate_constructed((ServiceParamVARIANT *)tmp_arr[i]);
    }
}

gdt::ServiceParamFactory::~ServiceParamFactory() {}

gdt::ServiceParam *gdt::ServiceParamFactory::new_param(ServiceParamType param_type) {
    ServiceParam *tmp = NULL;
    if (pooled) {
        switch (param_type) {
        case SPT_CSTRING:
            tmp = cstr_pool.allocate_constructed();
            break;
        case SPT_OCTETS:
            tmp = oct_pool.allocate_constructed();
            break;
        case SPT_UINT32:
            tmp = uint32_pool.allocate_constructed();
            break;
        case SPT_UINT64:
            tmp = uint64_pool.allocate_constructed();
            break;
        case SPT_BOOL:
            tmp = bool_pool.allocate_constructed();
            break;
        case SPT_VARIANT:
            tmp = var_pool.allocate_constructed();
            break;
        default:
            tmp = unknown_pool.allocate_constructed();
            break;
        }

    } else {
        switch (param_type) {
        case SPT_CSTRING:
            tmp = new ServiceParamCString();
            break;
        case SPT_OCTETS:
            tmp = new ServiceParamOctets();
            break;
        case SPT_UINT32:
            tmp = new ServiceParamUINT32();
            break;
        case SPT_UINT64:
            tmp = new ServiceParamUINT64();
            break;
        case SPT_BOOL:
            tmp = new ServiceParamBOOL();
            break;
        case SPT_VARIANT:
            tmp = new ServiceParamVARIANT();
            break;
        default:
            tmp = new ServiceParamUNKNOWN();
            break;
        }
    }
    return tmp;
}

int gdt::ServiceParamFactory::free_param(ServiceParam *param) {
    if (param == NULL)
        return 5;

    if (pooled) {
        int res = 0;
        switch (param->get_type()) {
        case SPT_CSTRING:
            res =
                cstr_pool.deallocate_constructed((ServiceParamCString *)param);
            break;

        case SPT_OCTETS:
            res = oct_pool.deallocate_constructed((ServiceParamOctets *)param);
            break;

        case SPT_UINT32:
            res =
                uint32_pool.deallocate_constructed((ServiceParamUINT32 *)param);
            break;

        case SPT_UINT64:
            res =
                uint64_pool.deallocate_constructed((ServiceParamUINT64 *)param);
            break;

        case SPT_UNKNOWN:
            res = unknown_pool.deallocate_constructed(
                (ServiceParamUNKNOWN *)param);
            break;

        case SPT_BOOL:
            res = bool_pool.deallocate_constructed((ServiceParamBOOL *)param);
            break;

        case SPT_VARIANT:
            res = var_pool.deallocate_constructed((ServiceParamVARIANT *)param);
            break;

        default:
            res = 7;
            break;
        }
        return res;

    } else {
        delete param;
        return 0;
    }

    return 6;
}

gdt::ParamIdTypeMap::ParamIdTypeMap() {}

gdt::ParamIdTypeMap::~ParamIdTypeMap() {}

int gdt::ParamIdTypeMap::add(uint32_t _id, ServiceParamType _type) {
    idtmap[_id] = _type;
    return 0;
}

int gdt::ParamIdTypeMap::remove(uint32_t id) {
    idtmap.erase(id);
    return 0;
}

gdt::ServiceParamType gdt::ParamIdTypeMap::get(uint32_t id) {
    // iterator type
    typedef std::map<uint32_t, ServiceParamType>::iterator it_type;
    // find
    it_type it = idtmap.find(id);
    if (it != idtmap.end())
        return it->second;
    return SPT_UNKNOWN;
}

int gdt::ParamIdTypeMap::clear() {
    idtmap.clear();
    return 0;
}

gdt::ServiceMessageDone::ServiceMessageDone() {
    usr_method = NULL;
    status = 0;
    smsg = NULL;
}

void gdt::ServiceMessageDone::run(GDTCallbackArgs *args) {
    asn1::GDTMessage *in_msg = (asn1::GDTMessage *)args->get_arg(gdt::GDT_CB_INPUT_ARGS,
                                                                 gdt::GDT_CB_ARG_IN_MSG);
    uint64_t *in_sess = (uint64_t *)args->get_arg(gdt::GDT_CB_INPUT_ARGS,
                                                  gdt::GDT_CB_ARG_IN_MSG_ID);
    // check status (in_msg is NULL in case if stream timeout)
    if (in_msg != NULL) {
        if (in_msg->_header->_status != NULL) {
            if (in_msg->_header->_status->has_linked_data(*in_sess)) {
                status = in_msg->_header->_status->linked_node->tlv->value[0];
            }
        }

        // stream timeout error
    } else
        status = 300;

    // run user handler (async mode)
    if (usr_method != NULL) {
        args->add_arg(GDT_CB_INPUT_ARGS, GDT_CB_ARGS_SRVC_MSG, smsg);
        usr_method->run(args);
    }
    // signal
    smsg->signal_post();
}

void gdt::ServiceMessageNext::run(GDTCallbackArgs *args) {
    gdt::GDTStream *stream = (gdt::GDTStream *)args->get_arg(gdt::GDT_CB_INPUT_ARGS,
                                                             gdt::GDT_CB_ARG_STREAM);
    asn1::GDTMessage *gdtm = stream->get_gdt_message();
    bool *include_body = (bool *)args->get_arg(gdt::GDT_CB_INPUT_ARGS,
                                               gdt::GDT_CB_ARG_BODY);

    // param map
    std::vector<ServiceParam *> *pmap = smsg->get_param_map();

    // more segments
    if (pindex < pc) {
        unsigned int bc;
        unsigned int tbc = 0;

        // prepare body
        if (gdtm->_body != NULL) {
            gdtm->_body->unlink(1);
            gdtm->_body->_service_msg->set_linked_data(1);

        } else {
            gdtm->set_body();
            gdtm->prepare();
        }
        asn1::ServiceMessage *sm = gdtm->_body->_service_msg;

        // set params, allocate 10 initial children
        if (sm->_params == NULL) {
            sm->set_params();
            // set children, allocate more
            for (int i = 0; i < 10; i++) {
                sm->_params->set_child(i);
                sm->_params->get_child(i)->set_value();
                sm->_params->get_child(i)->_value->set_child(0);
                sm->_params->get_child(i)->_value->set_child(1);
                sm->_params->get_child(i)->_value->set_child(2);
                sm->_params->get_child(i)->_value->set_child(3);
            }
            // prepare
            asn1::prepare(sm, sm->parent_node);
        }

        // set service id
        sm->_service_id->set_linked_data(1,
                                         (unsigned char *)smsg->get_service_idp(),
                                         sizeof(uint32_t));

        // set service action
        sm->_service_action->set_linked_data(1,
                                             (unsigned char *)smsg->get_service_actionp(),
                                             1);

        // params
        ServiceParam *sc_param = NULL;
        asn1::Parameters *params = sm->_params;

        unsigned int j;
        for (j = 0;
             tbc < ServiceMsgManager::MAX_PARAMS_SIZE && pos < pmap->size();
             pos++, j++, pindex++) {
            sc_param = (*pmap)[pos];

            // check if more allocations are needed
            if (params->get_child(j) == NULL) {
                params->set_child(j);
                params->get_child(j)->set_value();
                params->get_child(j)->_value->set_child(0);
                params->get_child(j)->_value->set_child(1);
                params->get_child(j)->_value->set_child(2);
                params->get_child(j)->_value->set_child(3);
                // prepare
                asn1::prepare(params, params->parent_node);
            }

            // check fragmentation
            if (sc_param->fragmented) {
                // process fragments
                while ((tbc < ServiceMsgManager::MAX_PARAMS_SIZE) &&
                       (sc_param->fragment_index < sc_param->fragments)) {
                    // calculate number of bytes needed for current fragment
                    bc = (sc_param->total_data_size > sizeof(sc_param->data)
                              ? sizeof(sc_param->data)
                              : sc_param->total_data_size);

                    // check if more allocations are needed
                    if (params->get_child(j) == NULL) {
                        params->set_child(j);
                        params->get_child(j)->set_value();
                        params->get_child(j)->_value->set_child(0);
                        params->get_child(j)->_value->set_child(1);
                        params->get_child(j)->_value->set_child(2);
                        params->get_child(j)->_value->set_child(3);
                        // prepare
                        asn1::prepare(params, params->parent_node);
                    }
                    // update total byte count
                    tbc += bc + 25;
                    // check if limit reached
                    if (tbc > ServiceMsgManager::MAX_PARAMS_SIZE)
                        break;

                    // set gdt values
                    params->get_child(j)
                          ->_id->set_linked_data(1,
                                                 (unsigned char *)sc_param->get_idp(),
                                                 sizeof(uint32_t));
                    params->get_child(j)
                          ->_value
                          ->get_child(0)
                          ->set_linked_data(1, sc_param->data_p, bc);

                    // variant param id index and type
                    params->get_child(j)
                          ->_value
                          ->get_child(2)
                          ->set_linked_data(1, (unsigned char *)&sc_param->index, 1);

                    params->get_child(j)
                          ->_value
                          ->get_child(3)
                          ->set_linked_data(1, (unsigned char *)&sc_param->extra_type, 1);

                    // check if last fragment, disable fragmentation flag (last
                    // fragment must not contain fragmentation flag)
                    if (sc_param->fragment_index == sc_param->fragments - 1) {
                        // set gdt fragmentation flag
                        params->get_child(j)
                              ->_value
                              ->get_child(1)
                              ->set_linked_data(1,
                                                (unsigned char*)&ServiceParam::FRAGMENTATION_DONE,
                                                1);

                    } else {
                        // set gdt fragmentation flag
                        params->get_child(j)
                              ->_value
                              ->get_child(1)
                              ->set_linked_data(1,
                                                (unsigned char*)&ServiceParam::FRAGMENTATION_NEXT,
                                                1);
                    }

                    // next
                    ++sc_param->fragment_index;
                    ++j;
                    ++pindex;
                    // run data fetch method
                    (*sc_param->param_data_cb)(sc_param,
                                               sc_param->in_data_p,
                                               sc_param->total_data_size);
                }

                // break if fragmentation in progress and not finished (to skip
                // increment, next call should process the same param again)
                if (sc_param->fragment_index < sc_param->fragments)
                    break;
                // rewind gdt param child count and packet index
                else {
                    --j;
                    --pindex;
                }

                // no fragmentation
            } else {
                // update total byte count
                tbc += sc_param->data_size + 25;
                // check if limit reached
                if (tbc > ServiceMsgManager::MAX_PARAMS_SIZE)
                    break;

                params->get_child(j)
                      ->_id->set_linked_data(1,
                                             (unsigned char *)sc_param->get_idp(),
                                             sizeof(uint32_t));
                params->get_child(j)
                      ->_value
                      ->get_child(0)
                      ->set_linked_data(1, sc_param->data, sc_param->data_size);
                params->get_child(j)
                      ->_value
                      ->get_child(1)
                      ->set_linked_data(1,
                                        (unsigned char *)&ServiceParam::FRAGMENTATION_DONE,
                                        1);
                params->get_child(j)
                      ->_value
                      ->get_child(2)
                      ->set_linked_data(1,
                                        (unsigned char *)&sc_param->index,
                                        1);
                params->get_child(j)
                      ->_value
                      ->get_child(3)
                      ->set_linked_data(1,
                                        (unsigned char *)&sc_param->extra_type,
                                        1);
            }
        }
        // remove unused chidren
        for (; j < params->children.size(); j++)
            params->get_child(j)->unlink(1);

        // include body
        *include_body = true;

        // continue
        if (pindex < pc)
            stream->continue_sequence();
    }
}

gdt::ServiceMessage::ServiceMessage() {

    idt_map = NULL;
    smsg_m = NULL;
    frag_param = NULL;
    service_id = 0;
    service_action = 0;
    sem_init(&smsg_sem, 0, 0);
    sem_init(&new_param_sem, 0, 0);
    msg_done.smsg = this;
    msg_next.smsg = this;
    auto_free = true;
    missing_params = false;
}

gdt::ServiceMessage::~ServiceMessage() { tlvs.clear(); }

int gdt::ServiceMessage::add_param(uint32_t id, ServiceParam *param,
                                    uint32_t index) {
    tlvs.push_back(param);
    param->set_id(id);
    param->index = index;
    return 0;
}

int gdt::ServiceMessage::remove_param(uint32_t id) {
    for (unsigned int i = 0; i < tlvs.size(); i++)
        if (tlvs[i]->get_id() == id) {
            tlvs.erase(tlvs.begin() + i);
        }
    return 0;
}

int gdt::ServiceMessage::get_param(uint32_t id,
                                    std::vector<ServiceParam *> *out) {
    for (unsigned int i = 0; i < tlvs.size(); i++)
        if (tlvs[i]->get_id() == id)
            out->push_back(tlvs[i]);
    return 0;
}

int gdt::ServiceMessage::reset() {
    ServiceParam *param = NULL;
    for (unsigned int i = 0; i < tlvs.size(); i++) {
        param = tlvs[i];
        smsg_m->get_param_factory()->free_param(param);
    }

    tlvs.clear();
    return 0;
}
uint32_t gdt::ServiceMessage::get_service_id() { return be32toh(service_id); }

uint32_t *gdt::ServiceMessage::get_service_idp() { return &service_id; }

uint32_t gdt::ServiceMessage::get_service_action() {
    return be32toh(service_action);
}

uint32_t *gdt::ServiceMessage::get_service_actionp() {
    return &service_action;
}

void gdt::ServiceMessage::set_service_id(uint32_t _service_id) {
    service_id = htobe32(_service_id);
}

void gdt::ServiceMessage::set_service_action(uint32_t _service_action) {
    service_action = htobe32(_service_action);
}

void gdt::ServiceMessage::set_smsg_manager(ServiceMsgManager *_smsg_m) {
    smsg_m = _smsg_m;
}

gdt::ServiceMsgManager *gdt::ServiceMessage::get_smsg_manager() {
    return smsg_m;
}

gdt::ServiceParam *gdt::ServiceMessage::get_frag_param() {
    return frag_param;
}

void gdt::ServiceMessage::set_frag_param(ServiceParam *_frag_param) {
    frag_param = _frag_param;
    if (frag_param != NULL)
        frag_param->fragment_index = 0;
}

bool gdt::ServiceMessage::is_complete() { return complete.get(); }

bool gdt::ServiceMessage::set_complete(bool _is_complete) {
    return complete.comp_swap(!_is_complete, _is_complete);
}

bool gdt::ServiceMessage::set_auto_free(bool _auto_free) {
    auto_free = _auto_free;
    return auto_free;
}

bool gdt::ServiceMessage::get_auto_free() const { return auto_free; }

void gdt::ServiceMessage::set_callback(GDTEventType type,
                                        GDTCallbackMethod *cback) {
    cb_handler.set_callback(type, cback);
}

bool gdt::ServiceMessage::process_callback(GDTEventType type,
                                            GDTCallbackArgs *args) {
    return cb_handler.process_callback(type, args);
}

void gdt::ServiceMessage::clear_callbacks() { cb_handler.clear(); }

std::vector<gdt::ServiceParam *> *gdt::ServiceMessage::get_param_map() {
    return &tlvs;
}
        mink_utils::VariantParam *vpget(uint32_t id, 
                                        uint32_t index = 0,
                                        uint32_t fragment = 0,
                                        uint32_t context = 0);


mink_utils::VariantParam *gdt::ServiceMessage::vpget(uint32_t id,
                                                     uint32_t index,
                                                     uint32_t fragment,
                                                     uint32_t context) {


    return vpmap.get_param(id, index, fragment, context);
}

mink_utils::VariantParam *gdt::ServiceMessage::vpset(uint32_t id,
                                                     const std::string &s,
                                                     uint32_t index,
                                                     uint32_t fragment,
                                                     uint32_t context) {
    return vpmap.set_cstr(id, s.c_str(), index, fragment, context);
}

gdt::ServiceMessageDone *gdt::ServiceMessage::get_sdone_hndlr() {
    return &msg_done;
}

gdt::ServiceMessageNext *gdt::ServiceMessage::get_snext_hndlr() {
    return &msg_next;
}

int gdt::ServiceMessage::signal_wait() {
    // wait for signal
    timespec ts;
    clock_gettime(0, &ts);
    ts.tv_sec += 5;

    int sres = sem_wait(&smsg_sem);
    // error check
    if (sres == -1) {
        return 1;
    }
    // ok
    return 0;
}

int gdt::ServiceMessage::signal_post() { return sem_post(&smsg_sem); }

void gdt::ServiceMessage::set_idt_map(ParamIdTypeMap *idtm) { idt_map = idtm; }

gdt::ServiceStreamHandlerNext::ServiceStreamHandlerNext(): ssh_new(NULL){}

void gdt::ServiceStreamHandlerNext::run(GDTCallbackArgs *args) {
    gdt::GDTStream *stream = (gdt::GDTStream *)args->get_arg(gdt::GDT_CB_INPUT_ARGS,
                                                             gdt::GDT_CB_ARG_STREAM);
    asn1::GDTMessage *in_msg = (asn1::GDTMessage *)args->get_arg(gdt::GDT_CB_INPUT_ARGS,
                                                                 gdt::GDT_CB_ARG_IN_MSG);
    uint64_t *in_sess = (uint64_t *)args->get_arg(gdt::GDT_CB_INPUT_ARGS,
                                                  gdt::GDT_CB_ARG_IN_MSG_ID);
    GDTCallbackArgs cb_args;

    // check for params part
    if (in_msg->_body->_service_msg->_params != NULL) {
        if (in_msg->_body->_service_msg->_params->has_linked_data(*in_sess)) {
            // get ID->TYPE map
            ParamIdTypeMap *idt_map = ssh_new->smsg_m->get_idt_map();
            // set default param type
            ServiceParamType ptype = SPT_UNKNOWN;
            // declare param pointer
            ServiceParam *sparam = NULL;
            // param id pointer
            uint32_t *param_id = NULL;
            // raw data pointer
            char *tmp_val = NULL;
            // ServiceMessage pointer
            ServiceMessage *smsg = (ServiceMessage *)stream->get_param(SMSG_PT_SMSG);

            // NULL check
            if (smsg != NULL) {
                // fragmentation
                bool frag = false;
                asn1::ServiceMessage *sm = in_msg->_body->_service_msg;
                // service id
                if (sm->_service_id->has_linked_data(*in_sess)) {
                    uint32_t *tmp_ui32 = (uint32_t *)sm->_service_id
                                                       ->linked_node
                                                       ->tlv
                                                       ->value;
                    smsg->set_service_id(be32toh(*tmp_ui32));
                }

                // process params
                for (unsigned int i = 0; i < sm->_params->children.size(); i++) {
                    // check for value
                    if (!sm->_params
                           ->get_child(i)
                           ->_value) continue;
                    // check if value exists in current session
                    if (!sm->_params
                           ->get_child(i)
                           ->_value
                           ->has_linked_data(*in_sess)) continue;
                     // check if child exists
                    if (!sm->_params
                            ->get_child(i)
                            ->_value
                            ->get_child(0)) continue;

                    // check if child exists in current sesion
                    if (!sm->_params
                           ->get_child(i)
                           ->_value
                           ->get_child(0)
                           ->has_linked_data(*in_sess)) continue;

                    // getr param id
                    param_id = (uint32_t *)sm->_params
                                             ->get_child(i)
                                             ->_id
                                             ->linked_node
                                             ->tlv
                                             ->value;
                    // get param type by id
                    ptype = idt_map->get(be32toh(*param_id));
                    // get extra type
                    int extra_type = sm->_params
                                       ->get_child(i)
                                       ->_value
                                       ->get_child(3)
                                       ->linked_node
                                       ->tlv
                                       ->value[0];
                    // create param
                    sparam = ssh_new->smsg_m->get_param_factory()
                                            ->new_param((extra_type > 0
                                                         ? SPT_VARIANT
                                                         : ptype));
                    // fragmentatio flag
                    frag = false;

                    if (sparam != NULL) {
                        // set id
                        sparam->set_id(be32toh(*param_id));
                        // reset data pointer
                        sparam->reset_data_p();
                        // reset index and extra type
                        sparam->index = 0;
                        sparam->extra_type = 0;

                        // get raw data
                        tmp_val = (char *)sm->_params
                                            ->get_child(i)
                                            ->_value
                                            ->get_child(0)
                                            ->linked_node
                                            ->tlv
                                            ->value;
                        int tmp_val_l = sm->_params
                                          ->get_child(i)
                                          ->_value
                                          ->get_child(0)
                                          ->linked_node
                                          ->tlv
                                          ->value_length;

                        // set service param data
                        sparam->set_data(tmp_val, tmp_val_l);

                        // check for fragmentation
                        if (sm->_params
                              ->get_child(i)
                              ->_value
                              ->get_child(1)) {

                            if (sm->_params
                                  ->get_child(i)
                                  ->_value
                                  ->get_child(1)
                                  ->has_linked_data(*in_sess)) {

                                asn1::TLVNode *tlv = sm->_params
                                                       ->get_child(i)
                                                       ->_value
                                                       ->get_child(1)
                                                       ->linked_node
                                                       ->tlv;
                                // fragmentation flag (value
                                // length 1 and value 1)
                                if (tlv->value_length == 1) {
                                    if (tlv->value[0] == 1)
                                        frag = true;
                                }
                            }
                        }

                        // variant param id index and type
                        sparam->index = sm->_params
                                          ->get_child(i)
                                          ->_value
                                          ->get_child(2)
                                          ->linked_node
                                          ->tlv
                                          ->value[0];
                        sparam->extra_type = extra_type;

                        // set fragmentation flag and pointer to
                        // first fragment
                        if (frag) {
                            sparam->set_fragmented(true);

                            // first fragment
                            if (!smsg->get_frag_param()) {
                                // set first fragment pointer
                                smsg->set_frag_param(sparam);
                                sparam->fragment_index = 0;

                                // reset callbacks
                                sparam->clear_callbacks();

                                // process vparam
                                if (sparam->get_type() == SPT_VARIANT) {
                                    smsg->vpmap.set_octets(sparam->get_id(),
                                                           sparam->get_data(),
                                                           sparam->get_data_size(),
                                                           sparam->get_index(),
                                                           smsg->get_frag_param()
                                                               ->get_fragment_index());
                                }

                                // run callback
                                cb_args.clear_all_args();
                                cb_args.add_arg(GDT_CB_INPUT_ARGS,
                                                GDT_CB_ARGS_SRVC_MSG,
                                                smsg);
                                cb_args.add_arg(GDT_CB_INPUT_ARGS,
                                                GDT_CB_ARGS_SRVC_PARAM,
                                                sparam);
                                smsg->process_callback(GDT_ET_SRVC_PARAM_STREAM_NEW,
                                                       &cb_args);

                                // more fragments
                            } else {
                                smsg->get_frag_param()
                                    ->inc_total_data_size(sparam->get_data_size());

                                // process vparam
                                if (sparam->get_type() == SPT_VARIANT) {
                                    smsg->vpmap.set_octets(sparam->get_id(),
                                                           sparam->get_data(),
                                                           sparam->get_data_size(),
                                                           sparam->get_index(),
                                                           smsg->get_frag_param()
                                                               ->get_fragment_index());
                                }

                                // run callback
                                cb_args.clear_all_args();
                                cb_args.add_arg(GDT_CB_INPUT_ARGS,
                                                GDT_CB_ARGS_SRVC_MSG,
                                                smsg);
                                cb_args.add_arg(GDT_CB_INPUT_ARGS,
                                                GDT_CB_ARGS_SRVC_PARAM,
                                                sparam);
                                smsg->get_frag_param()
                                    ->process_callback(GDT_ET_SRVC_PARAM_STREAM_NEXT,
                                                       &cb_args);

                                // return to pool (fragmented
                                // params are not retained in
                                // memory)
                                ssh_new->smsg_m
                                       ->get_param_factory()
                                       ->free_param(sparam);
                            }

                            // no fragmentation or last fragment
                        } else {
                            // last fragment
                            if (smsg->get_frag_param()) {
                                sparam->set_fragmented(true);
                                smsg->get_frag_param()
                                    ->inc_total_data_size(sparam->get_data_size());

                                // process vparam
                                if (sparam->get_type() == SPT_VARIANT) {
                                    smsg->vpmap.set_octets(sparam->get_id(),
                                                           sparam->get_data(),
                                                           sparam->get_data_size(),
                                                           sparam->get_index(),
                                                           smsg->get_frag_param()
                                                               ->get_fragment_index());

                                    mink_utils::VariantParam *vparam = smsg->vpmap.defragment(sparam->get_id(),
                                                                                              sparam->get_index());
                                    if (vparam) vparam->set_type((mink_utils::VariantParamType)sparam->get_extra_type());
                                }

                                // run callback
                                cb_args.clear_all_args();
                                cb_args.add_arg(GDT_CB_INPUT_ARGS,
                                                GDT_CB_ARGS_SRVC_MSG,
                                                smsg);
                                cb_args.add_arg(GDT_CB_INPUT_ARGS,
                                                GDT_CB_ARGS_SRVC_PARAM,
                                                sparam);

                                smsg->get_frag_param()->process_callback(GDT_ET_SRVC_PARAM_STREAM_END,
                                                                         &cb_args);

                                // return to pool (fragmented
                                // params are not retained in
                                // memory)
                                ssh_new->smsg_m
                                       ->get_param_factory()
                                       ->free_param(sparam);
                                ssh_new->smsg_m
                                       ->get_param_factory()
                                       ->free_param(smsg->get_frag_param());

                                // reset frag param
                                smsg->set_frag_param(NULL);

                                // no fragmentation
                            } else {
                                sparam->set_fragmented(false);
                                // add param
                                smsg->add_param(be32toh(*param_id),
                                                sparam,
                                                sparam->index);

                                // process vparam
                                if (sparam->get_type() == SPT_VARIANT) {
                                    // check param type
                                    switch (sparam->get_extra_type()) {
                                        // c string
                                        case mink_utils::DPT_STRING: {
                                            char tmp_str[256];
                                            sparam->extract(tmp_str);
                                            smsg->vpmap.set_cstr(sparam->get_id(),
                                                                 tmp_str,
                                                                 sparam->get_index());
                                            break;
                                        }

                                            // int
                                        case mink_utils::DPT_INT: {
                                            uint64_t tmp = 0;
                                            sparam->extract(&tmp);
                                            smsg->vpmap.set_int(sparam->get_id(),
                                                                tmp,
                                                                sparam->get_index());
                                            break;
                                        }
                                            // bool
                                        case mink_utils::DPT_BOOL: {
                                            bool tmp = false;
                                            sparam->extract(&tmp);
                                            smsg->vpmap.set_bool(sparam->get_id(),
                                                                 tmp,
                                                                 sparam->get_index());
                                            break;
                                        }

                                            // other
                                        default: {
                                            unsigned char tmp_buff[256];
                                            sparam->extract(&tmp_buff);
                                            smsg->vpmap.set_octets(sparam->get_id(),
                                                                   tmp_buff,
                                                                   sparam->get_data_size(),
                                                                    sparam->get_index());
                                            break;
                                        }
                                    }
                                }

                                // run callback
                                cb_args.clear_all_args();
                                cb_args.add_arg(GDT_CB_INPUT_ARGS,
                                                GDT_CB_ARGS_SRVC_MSG,
                                                smsg);
                                cb_args.add_arg(GDT_CB_INPUT_ARGS,
                                                GDT_CB_ARGS_SRVC_PARAM,
                                                sparam);
                                smsg->process_callback(GDT_ET_SRVC_SHORT_PARAM_NEW,
                                                       &cb_args);
                            }
                        }

                    } else {
                        smsg->missing_params = true;
                        ssh_new->smsg_m->stats.inc(
                            SST_RX_SPARAM_POOL_EMPTY, 1);
                    }

                }
                stream->continue_sequence();
            }
        }
    }
}

gdt::ServiceStreamHandlerDone::ServiceStreamHandlerDone(): ssh_new(NULL){

}

void gdt::ServiceStreamHandlerDone::run(GDTCallbackArgs *args) {
    gdt::GDTStream *stream = (gdt::GDTStream *)args->get_arg(gdt::GDT_CB_INPUT_ARGS,
                                                             gdt::GDT_CB_ARG_STREAM);
    ServiceMessage *smsg = (ServiceMessage *)stream->get_param(SMSG_PT_SMSG);
    asn1::GDTMessage *in_msg = (asn1::GDTMessage *)args->get_arg(gdt::GDT_CB_INPUT_ARGS,
                                                                 gdt::GDT_CB_ARG_IN_MSG);
    uint64_t *in_sess = (uint64_t *)args->get_arg(gdt::GDT_CB_INPUT_ARGS,
                                                  gdt::GDT_CB_ARG_IN_MSG_ID);

    // get ID->TYPE map
    ParamIdTypeMap *idt_map = ssh_new->smsg_m->get_idt_map();
    // set default param type
    ServiceParamType ptype = SPT_UNKNOWN;
    // declare param pointer
    ServiceParam *sparam = NULL;
    // param id pointer
    uint32_t *param_id = NULL;
    // raw data pointer
    char *tmp_val = NULL;
    // raw data length
    int tmp_val_l = 0;
    // fragmentation
    bool frag = false;
    // extra type
    int extra_type;
    GDTCallbackArgs cb_args;
    asn1::ServiceMessage *sm = NULL;
    asn1::Parameters *p = NULL;

    if(!smsg) return;
    if(!in_msg) goto stream_complete;
    sm = in_msg->_body->_service_msg;
    // in_msg is NULL in case of stream timeout
    // check for params part
    if (!sm->_params) goto stream_pre_complete;
    if (!sm->_params->has_linked_data(*in_sess)) goto stream_pre_complete;
    p = sm->_params;

    // service id
    if (sm->_service_id->has_linked_data(*in_sess)) {
        uint32_t *tmp_ui32 = (uint32_t *)sm->_service_id
                                           ->linked_node
                                           ->tlv
                                           ->value;
        smsg->set_service_id(be32toh(*tmp_ui32));
    }

    // process params
    for (unsigned int i = 0; i < p->children.size(); i++) {
        // check for value
        if (!p->get_child(i)->_value) continue;
        // check if value exists in current session
        if (!p->get_child(i)
              ->_value
              ->has_linked_data(*in_sess)) continue;
        // check if child exists
        if (!p->get_child(i)
              ->_value
              ->get_child(0)) continue;

        // check if child exists in current sesion
        if (!p->get_child(i)
              ->_value
              ->get_child(0)
              ->has_linked_data(*in_sess)) continue;

        // getr param id
        param_id = (uint32_t *)p->get_child(i)
                                ->_id
                                ->linked_node
                                ->tlv
                                ->value;
        // get param type by id
        ptype = idt_map->get(be32toh(*param_id));
        // get extra type
        extra_type = p->get_child(i)
                      ->_value
                      ->get_child(3)
                      ->linked_node
                      ->tlv
                      ->value[0];
        // create param
        sparam = ssh_new->smsg_m
                         ->get_param_factory()
                         ->new_param((extra_type > 0
                                     ? SPT_VARIANT
                                     : ptype));
        // fragmentatio flag
        frag = false;

        if (sparam != NULL) {
            // set id
            sparam->set_id(be32toh(*param_id));
            // reset data pointer
            sparam->reset_data_p();
            // reset index and extra type
            sparam->index = 0;
            sparam->extra_type = 0;

            // get raw data
            tmp_val = (char *)p->get_child(i)
                               ->_value
                               ->get_child(0)
                               ->linked_node
                               ->tlv
                               ->value;
            tmp_val_l = p->get_child(i)
                         ->_value
                         ->get_child(0)
                         ->linked_node
                         ->tlv
                         ->value_length;

            // set service param data
            sparam->set_data(tmp_val,
                             tmp_val_l);

            // check for fragmentation
            if (p->get_child(i)->_value->get_child(1)) {
                if (p->get_child(i)
                     ->_value->get_child(1)
                     ->has_linked_data(*in_sess)) {
                    asn1::TLVNode *tlv = p->get_child(i)
                                          ->_value
                                          ->get_child(1)
                                          ->linked_node
                                          ->tlv;
                    // fragmentation flag (value
                    // length 1 and value 1)
                    if (tlv->value_length == 1) {
                        if (tlv->value[0] == 1)
                            frag = true;
                    }
                }
            }

            // variant param id index and type
            sparam->index = p->get_child(i)
                             ->_value
                             ->get_child(2)
                             ->linked_node
                             ->tlv
                             ->value[0];
            sparam->extra_type = extra_type;

            // set fragmentation flag and
            // pointer to first fragment
            if (frag) {
                sparam->set_fragmented(true);

                // first fragment
                if (!smsg->get_frag_param()) {
                    // set first fragment
                    // pointer
                    smsg->set_frag_param(sparam);

                    // reset callbacks
                    sparam->clear_callbacks();

                    // process vparam
                    if (sparam->get_type() == SPT_VARIANT) {
                        smsg->vpmap.set_octets(sparam->get_id(),
                                               sparam->get_data(),
                                               sparam->get_data_size(),
                                               sparam->get_index(),
                                               smsg->get_frag_param()
                                                   ->get_fragment_index());
                    }

                    // run callback
                    cb_args.clear_all_args();
                    cb_args.add_arg(GDT_CB_INPUT_ARGS,
                                    GDT_CB_ARGS_SRVC_MSG,
                                    smsg);
                    cb_args.add_arg(GDT_CB_INPUT_ARGS,
                                    GDT_CB_ARGS_SRVC_PARAM,
                                    sparam);
                    smsg->process_callback(GDT_ET_SRVC_PARAM_STREAM_NEW,
                                           &cb_args);

                    // more fragments
                } else {
                    smsg->get_frag_param()
                        ->inc_total_data_size(sparam->get_data_size());

                    // process vparam
                    if (sparam->get_type() == SPT_VARIANT) {
                        smsg->vpmap.set_octets(sparam->get_id(),
                                               sparam->get_data(),
                                               sparam->get_data_size(),
                                               sparam->get_index(),
                                               smsg->get_frag_param()
                                                   ->get_fragment_index());
                    }

                    // run callback
                    cb_args.clear_all_args();
                    cb_args.add_arg(GDT_CB_INPUT_ARGS,
                                    GDT_CB_ARGS_SRVC_MSG,
                                    smsg);
                    cb_args.add_arg(GDT_CB_INPUT_ARGS,
                                    GDT_CB_ARGS_SRVC_PARAM,
                                    sparam);
                    smsg->get_frag_param()
                        ->process_callback(GDT_ET_SRVC_PARAM_STREAM_NEXT,
                                           &cb_args);

                    // return to pool
                    // (fragmented params are
                    // not retained in memory)
                    ssh_new->smsg_m
                           ->get_param_factory()
                           ->free_param(sparam);
                }

                // no fragmentation or last
                // fragment
            } else {
                // last fragment
                if (smsg->get_frag_param()) {
                    sparam->set_fragmented(true);
                    smsg->get_frag_param()
                         ->inc_total_data_size(sparam->get_data_size());

                    // process vparam
                    if (sparam->get_type() == SPT_VARIANT) {
                        smsg->vpmap.set_octets(sparam->get_id(),
                                               sparam->get_data(),
                                               sparam->get_data_size(),
                                               sparam->get_index(),
                                               smsg->get_frag_param()
                                                   ->get_fragment_index());

                        mink_utils::VariantParam *vparam = smsg->vpmap.defragment(sparam->get_id(),
                                                                                  sparam->get_index());
                        if (vparam != NULL)
                            vparam->set_type((mink_utils::VariantParamType)sparam->get_extra_type());
                    }

                    // run callback
                    cb_args.clear_all_args();
                    cb_args.add_arg(GDT_CB_INPUT_ARGS,
                                    GDT_CB_ARGS_SRVC_MSG,
                                    smsg);
                    cb_args.add_arg(GDT_CB_INPUT_ARGS,
                                    GDT_CB_ARGS_SRVC_PARAM,
                                    sparam);

                    smsg->get_frag_param()
                        ->process_callback(GDT_ET_SRVC_PARAM_STREAM_END,
                                           &cb_args);

                    // return to pool
                    // (fragmented params are
                    // not retained in memory)
                    ssh_new->smsg_m
                           ->get_param_factory()
                           ->free_param(sparam);
                    ssh_new->smsg_m
                           ->get_param_factory()
                           ->free_param(smsg->get_frag_param());

                    // reset frag param
                    smsg->set_frag_param(NULL);

                    // no fragmentation
                } else {
                    sparam->set_fragmented(false);
                    // add param
                    smsg->add_param(be32toh(*param_id),
                                    sparam,
                                    sparam->index);

                    // process vparam
                    if (sparam->get_type() == SPT_VARIANT) {
                        // check param type
                        switch (sparam->get_extra_type()) {
                            // c string
                            case mink_utils::DPT_STRING: {
                                char tmp_str[256];
                                sparam->extract(tmp_str);
                                smsg->vpmap.set_cstr(sparam->get_id(),
                                                     tmp_str,
                                                     sparam->get_index());
                                break;
                            }

                                // int
                            case mink_utils::DPT_INT: {
                                uint64_t tmp = 0;
                                sparam->extract(&tmp);
                                smsg->vpmap.set_int(sparam->get_id(),
                                                    tmp,
                                                    sparam->get_index());
                                break;
                            }
                                // bool
                            case mink_utils::DPT_BOOL: {
                                bool tmp = false;
                                sparam->extract(&tmp);
                                smsg->vpmap.set_bool(sparam->get_id(),
                                                     tmp,
                                                     sparam->get_index());
                                break;
                            }

                                // other
                            default: {
                                unsigned char tmp_buff[256];
                                sparam->extract(&tmp_buff);
                                smsg->vpmap.set_octets(sparam->get_id(),
                                                       tmp_buff,
                                                       sparam->get_data_size(),
                                                       sparam->get_index());
                                break;
                            }
                        }
                    }

                    // run callback
                    cb_args.clear_all_args();
                    cb_args.add_arg(GDT_CB_INPUT_ARGS,
                                    GDT_CB_ARGS_SRVC_MSG,
                                    smsg);
                    cb_args.add_arg(GDT_CB_INPUT_ARGS,
                                    GDT_CB_ARGS_SRVC_PARAM,
                                    sparam);
                    smsg->process_callback(GDT_ET_SRVC_SHORT_PARAM_NEW,
                                           &cb_args);
                }
            }

        } else {
            smsg->missing_params = true;
            ssh_new->smsg_m->stats.inc(SST_RX_SPARAM_POOL_EMPTY, 1);
        }
    }

stream_pre_complete:
    // set as completed if status is present and == ok (0)
    if (asn1::node_exists(in_msg->_header->_status, *in_sess)) {
        if (in_msg->_header->_status->linked_node->tlv->value[0] == 0)
            smsg->set_complete(true);

        // no status, set as completed
    } else
        smsg->set_complete(true);

stream_complete:
        // run callback
        cb_args.clear_all_args();
        cb_args.add_arg(GDT_CB_INPUT_ARGS, GDT_CB_ARG_STREAM, stream);
        cb_args.add_arg(GDT_CB_INPUT_ARGS, GDT_CB_ARGS_SRVC_MSG, smsg);
        cb_args.add_arg(GDT_CB_INPUT_ARGS,
                        GDT_CB_ARG_CLIENT,
                        stream->get_client());
        smsg->process_callback(GDT_ET_SRVC_MSG_COMPLETE, &cb_args);

        // check for pass param
        ServiceMessage *smsg_pass =
            (ServiceMessage *)stream->get_param(SMSG_PT_PASS);
        // if pass not set
        if (smsg_pass != smsg) {
            // free message if auto_free flag was set (default)
            if (smsg->get_auto_free())
                ssh_new->smsg_m->free_smsg(smsg);
        }
        // remove params
        stream->remove_param(SMSG_PT_SMSG);
        stream->remove_param(SMSG_PT_PASS);

        // smsg not allocated in new stream event
        // error should be handled in GDT_ET_SRVC_MSG_ERROR handler
}

gdt::ServiceStreamNewClient::ServiceStreamNewClient() {
    usr_stream_hndlr = NULL;
    usr_stream_nc_hndlr = NULL;
    smsg_m = NULL;
}

void gdt::ServiceStreamNewClient::run(GDTCallbackArgs *args) {
    gdt::GDTClient *client = (gdt::GDTClient *)args->get_arg(
        gdt::GDT_CB_INPUT_ARGS, gdt::GDT_CB_ARG_CLIENT);
    smsg_m->setup_client(client);
    // user NEW CLIENT handler
    if (usr_stream_nc_hndlr != NULL)
        usr_stream_nc_hndlr->run(args);
}

gdt::ServiceStreamHandlerNew::ServiceStreamHandlerNew(): smsg_m(NULL),
                                                         usr_stream_hndlr(NULL) {
}

void gdt::ServiceStreamHandlerNew::run(GDTCallbackArgs *args) {
    asn1::GDTMessage *in_msg = (asn1::GDTMessage *)args->get_arg(gdt::GDT_CB_INPUT_ARGS,
                                                                 gdt::GDT_CB_ARG_IN_MSG);
    uint64_t *in_sess = (uint64_t *)args->get_arg(gdt::GDT_CB_INPUT_ARGS,
                                                  gdt::GDT_CB_ARG_IN_MSG_ID);
    gdt::GDTStream *stream = (gdt::GDTStream *)args->get_arg(gdt::GDT_CB_INPUT_ARGS,
                                                             gdt::GDT_CB_ARG_STREAM);
    GDTCallbackArgs cb_args;

    // check for body
    if (!in_msg->_body) {
        // NON ServiceMessage user handler
        if (usr_stream_hndlr != NULL) usr_stream_hndlr->run(args);
        return;
    }

    // check for ServiceMessage
    if (!in_msg->_body->_service_msg->has_linked_data(*in_sess)) {
        if (usr_stream_hndlr != NULL) usr_stream_hndlr->run(args);
        return;
    }

    // set event handlers
    stream->set_callback(gdt::GDT_ET_STREAM_NEXT, &ssh_next);
    stream->set_callback(gdt::GDT_ET_STREAM_END, &ssh_done);
    stream->set_callback(gdt::GDT_ET_STREAM_TIMEOUT, &ssh_done);

    // create new ServiceMessage
    ServiceMessage *smsg = smsg_m->new_smsg();

    // NULL check
    if (!smsg) {
        smsg_m->stats.inc(SST_RX_SMSG_POOL_EMPTY, 1);
        // run callback
        cb_args.clear_all_args();
        cb_args.add_arg(GDT_CB_INPUT_ARGS, GDT_CB_ARG_STREAM, stream);
        smsg_m->process_callback(GDT_ET_SRVC_MSG_ERROR, &cb_args);
        return;
    }

    // reset frag
    smsg->set_frag_param(NULL);

    // reset callbacks
    smsg->clear_callbacks();

    // clear vpmap
    smsg->vpmap.clear_params();

    // set as incomplete
    smsg->set_complete(false);

    // clear stream params
    stream->clear_params();

    // set ServiceMessage as GDT stream param
    stream->set_param(SMSG_PT_SMSG, smsg);

    // reset auto free
    smsg->set_auto_free(true);
    // reset missing params
    smsg->missing_params = false;

    // run callback
    cb_args.clear_all_args();
    cb_args.add_arg(GDT_CB_INPUT_ARGS, GDT_CB_ARGS_SRVC_MSG,
                    smsg);
    smsg_m->process_callback(GDT_ET_SRVC_MSG_NEW, &cb_args);

    asn1::ServiceMessage *sm = in_msg->_body->_service_msg;
    asn1::Parameters *p = sm->_params;
    // get ID->TYPE map
    ParamIdTypeMap *idt_map = smsg_m->get_idt_map();
    // set default param type
    ServiceParamType ptype = SPT_UNKNOWN;
    // declare param pointer
    ServiceParam *sparam = NULL;
    // param id pointer
    uint32_t *param_id = NULL;
    // raw data pointer
    char *tmp_val = NULL;
    // raw data length
    int tmp_val_l = 0;
    // fragmentation
    bool frag = false;
    // extra type
    int extra_type;

    // check for params part
    if (!p) goto stream_continue;
    if (!p->has_linked_data(*in_sess)) goto stream_continue;

    // service id
    if (sm->_service_id->has_linked_data(*in_sess)) {
        uint32_t *tmp_ui32 = (uint32_t *)sm->_service_id
                                           ->linked_node
                                           ->tlv
                                           ->value;
        smsg->set_service_id(be32toh(*tmp_ui32));
    }

    // process params
    for (unsigned int i = 0; i < p->children.size(); i++) {
        // check for value
        if (!p->get_child(i)->_value) continue;
        // check if value exists in current session
        if (!p->get_child(i)
              ->_value
              ->has_linked_data(*in_sess)) continue;
        // check if child exists
        if (!p->get_child(i)
              ->_value
              ->get_child(0)) continue;
        // check if child exists in current
        // sesion
        if (!p->get_child(i)
              ->_value
              ->get_child(0)
              ->has_linked_data(*in_sess)) continue;


        // getr param id
        param_id = (uint32_t *)p->get_child(i)
                                ->_id
                                ->linked_node
                                ->tlv
                                ->value;
        // get param type by id
        ptype = idt_map->get(be32toh(*param_id));
        // get extra type
        extra_type = p->get_child(i)
                      ->_value
                      ->get_child(3)
                      ->linked_node
                      ->tlv
                      ->value[0];
        // create param
        sparam = smsg_m->get_param_factory()
                       ->new_param((extra_type > 0
                                   ? SPT_VARIANT
                                   : ptype));
        // fragmentation flag
        frag = false;

        if (sparam != NULL) {
            // set id
            sparam->set_id(be32toh(*param_id));
            // reset data pointer
            sparam->reset_data_p();
            // reset index and extra type
            sparam->index = 0;
            sparam->extra_type = 0;

            // get raw data
            tmp_val = (char *)p->get_child(i)
                               ->_value
                               ->get_child(0)
                               ->linked_node
                                ->tlv
                               ->value;
            tmp_val_l = p->get_child(i)
                         ->_value
                         ->get_child(0)
                         ->linked_node
                         ->tlv
                         ->value_length;

            // set service param data
            sparam->set_data(tmp_val,
                             tmp_val_l);

            // check for fragmentation
            if (p->get_child(i)
                 ->_value
                 ->get_child(1)) {
                if (p->get_child(i)
                     ->_value
                     ->get_child(1)
                     ->has_linked_data(*in_sess)) {
                    asn1::TLVNode *tlv = p->get_child(i)
                                          ->_value
                                          ->get_child(1)
                                          ->linked_node
                                          ->tlv;
                    // fragmentation flag
                    // (value length 1 and
                    // value 1)
                    if (tlv->value_length == 1) {
                        if (tlv->value[0] == 1)
                            frag = true;
                    }
                }
            }

            // variant param id index and
            // type
            sparam->index = p->get_child(i)
                             ->_value
                             ->get_child(2)
                             ->linked_node
                             ->tlv
                             ->value[0];
            sparam->extra_type = extra_type;

            // set fragmentation flag and
            // pointer to first fragment
            if (frag) {
                sparam->set_fragmented(true);

                // first fragment
                if (!smsg->get_frag_param()) {
                    // set first fragment
                    // pointer
                    smsg->set_frag_param(sparam);

                    // reset callbacks
                    sparam->clear_callbacks();

                    // process vparam
                    if (sparam->get_type() == SPT_VARIANT) {
                        smsg->vpmap.set_octets(sparam->get_id(),
                                               sparam->get_data(),
                                               sparam->get_data_size(),
                                               sparam->get_index(),
                                               smsg->get_frag_param()
                                                   ->get_fragment_index());
                    }

                    // run callback
                    cb_args.clear_all_args();
                    cb_args.add_arg(GDT_CB_INPUT_ARGS,
                                    GDT_CB_ARGS_SRVC_MSG,
                                    smsg);
                    cb_args.add_arg(GDT_CB_INPUT_ARGS,
                                    GDT_CB_ARGS_SRVC_PARAM,
                                    sparam);
                    smsg->process_callback(GDT_ET_SRVC_PARAM_STREAM_NEW,
                                           &cb_args);

                    // more fragments
                } else {
                    smsg->get_frag_param()
                        ->inc_total_data_size(sparam->get_data_size());

                    // process vparam
                    if (sparam->get_type() == SPT_VARIANT) {
                        smsg->vpmap.set_octets(sparam->get_id(),
                                               sparam->get_data(),
                                               sparam->get_data_size(),
                                               sparam->get_index(),
                                               smsg->get_frag_param()
                                                   ->get_fragment_index());
                    }

                    // run callback
                    cb_args.clear_all_args();
                    cb_args.add_arg(GDT_CB_INPUT_ARGS,
                                    GDT_CB_ARGS_SRVC_MSG,
                                    smsg);
                    cb_args.add_arg(GDT_CB_INPUT_ARGS,
                                    GDT_CB_ARGS_SRVC_PARAM,
                                    sparam);
                    smsg->get_frag_param()
                        ->process_callback(GDT_ET_SRVC_PARAM_STREAM_NEXT,
                                           &cb_args);

                    // return to pool
                    // (fragmented params
                    // are not retained in
                    // memory)
                    smsg_m->get_param_factory()
                          ->free_param(sparam);
                }

                // no fragmentation or last
                // fragment
            } else {
                // last fragment
                if (smsg->get_frag_param()) {
                    sparam->set_fragmented(true);
                    smsg->get_frag_param()
                        ->inc_total_data_size(sparam->get_data_size());

                    // process vparam
                    if (sparam->get_type() == SPT_VARIANT) {
                        smsg->vpmap.set_octets(sparam->get_id(),
                                               sparam->get_data(),
                                               sparam->get_data_size(),
                                               sparam->get_index(),
                                               smsg->get_frag_param()
                                                   ->get_fragment_index());

                        mink_utils::VariantParam *vparam = smsg->vpmap.defragment(sparam->get_id(),
                                                                                  sparam->get_index());
                        if (vparam != NULL)
                            vparam->set_type((mink_utils::VariantParamType)sparam->get_extra_type());
                    }

                    // run callback
                    cb_args.clear_all_args();
                    cb_args.add_arg(GDT_CB_INPUT_ARGS,
                                    GDT_CB_ARGS_SRVC_MSG,
                                    smsg);
                    cb_args.add_arg(GDT_CB_INPUT_ARGS,
                                    GDT_CB_ARGS_SRVC_PARAM,
                                    sparam);
                    smsg->get_frag_param()
                        ->process_callback(GDT_ET_SRVC_PARAM_STREAM_END,
                                           &cb_args);

                    // return to pool
                    // (fragmented params
                    // are not retained in
                    // memory)
                    smsg_m->get_param_factory()->free_param(sparam);
                    smsg_m->get_param_factory()->free_param(smsg->get_frag_param());

                    // reset frag param
                    smsg->set_frag_param(NULL);

                    // no fragmentation
                } else {
                    sparam->set_fragmented(false);
                    // add param
                    smsg->add_param(be32toh(*param_id),
                                    sparam,
                                    sparam->index);

                    // process vparam
                    if (sparam->get_type() == SPT_VARIANT) {
                        // check param type
                        switch (sparam->get_extra_type()) {
                            // c string
                            case mink_utils::DPT_STRING: {
                                char tmp_str[256];
                                sparam->extract(tmp_str);
                                smsg->vpmap.set_cstr(sparam->get_id(),
                                                     tmp_str,
                                                     sparam->get_index());
                                break;
                            }

                                // int
                            case mink_utils::DPT_INT: {
                                uint64_t tmp = 0;
                                sparam->extract(&tmp);
                                smsg->vpmap.set_int(sparam->get_id(),
                                                    tmp,
                                                    sparam->get_index());
                                break;
                            }
                                // bool
                            case mink_utils::DPT_BOOL: {
                                bool tmp = false;
                                sparam->extract(&tmp);
                                smsg->vpmap.set_bool(sparam->get_id(),
                                                     tmp,
                                                     sparam->get_index());
                                break;
                            }

                                // other
                            default: {
                                unsigned char tmp_buff[256];
                                sparam->extract(&tmp_buff);
                                smsg->vpmap.set_octets(sparam->get_id(),
                                                       tmp_buff,
                                                       sparam->get_data_size(),
                                                       sparam->get_index());
                                break;
                            }
                        }
                    }

                    // run callback
                    cb_args.clear_all_args();
                    cb_args.add_arg(GDT_CB_INPUT_ARGS,
                                    GDT_CB_ARGS_SRVC_MSG,
                                    smsg);
                    cb_args.add_arg(GDT_CB_INPUT_ARGS,
                                    GDT_CB_ARGS_SRVC_PARAM,
                                    sparam);
                    smsg->process_callback(GDT_ET_SRVC_SHORT_PARAM_NEW,
                                           &cb_args);
                }
            }

        } else {
            smsg->missing_params = true;
            smsg_m->stats.inc(SST_RX_SPARAM_POOL_EMPTY, 1);
        }
    }
stream_continue:
    // continue
    stream->continue_sequence();

}

gdt::ServiceMsgManager::ServiceMsgManager(ParamIdTypeMap *_idt_map,
                                          GDTCallbackMethod *_new_msg_hndlr,
                                          GDTCallbackMethod *_nonsrvc_stream_hndlr,
                                          unsigned int pool_size,
                                          unsigned int param_pool_size) {

    idt_map = _idt_map;
    param_factory = new ServiceParamFactory(true, false, param_pool_size);
    sem_init(&q_sem, 0, 0);
    srvcs_hndlr.smsg_m = this;
    srvcs_nc.smsg_m = this;
    srvcs_hndlr.usr_stream_hndlr = _nonsrvc_stream_hndlr;
    srvcs_hndlr.ssh_next.ssh_new = &srvcs_hndlr;
    srvcs_hndlr.ssh_done.ssh_new = &srvcs_hndlr;
    msg_pool.init(pool_size);
    msg_pool.construct_objects();
    cb_handler.set_callback(GDT_ET_SRVC_MSG_NEW, _new_msg_hndlr);

    // set manager pointers
    ServiceMessage *tmp_arr[pool_size];
    for (unsigned int i = 0; i < pool_size; i++) {
        tmp_arr[i] = msg_pool.allocate_constructed();
        tmp_arr[i]->set_smsg_manager(this);
    }
    // return back to pool
    for (unsigned int i = 0; i < pool_size; i++)
        msg_pool.deallocate_constructed(tmp_arr[i]);
    // random generator
    timespec tmp_time;
    clock_gettime(0, &tmp_time);

    // stats
    stats.register_item(SST_RX_SMSG_POOL_EMPTY);
    stats.register_item(SST_RX_SPARAM_POOL_EMPTY);
}

gdt::ServiceMsgManager::~ServiceMsgManager() {
    sem_destroy(&q_sem);
    delete param_factory;
}

void gdt::ServiceMsgManager::generate_uuid(unsigned char *out) {
    random_gen.generate(out, 16);
}

gdt::GDTCallbackMethod *gdt::ServiceMsgManager::get_srvcs_hndlr() {
    return &srvcs_hndlr;
}

gdt::GDTCallbackMethod *gdt::ServiceMsgManager::get_srvcs_nc_hndlr() {
    return &srvcs_nc;
}

void gdt::ServiceMsgManager::set_new_msg_handler(GDTCallbackMethod *hndlr) {
    cb_handler.set_callback(GDT_ET_SRVC_MSG_NEW, hndlr);
}

void gdt::ServiceMsgManager::set_msg_err_handler(GDTCallbackMethod *hndlr) {
    cb_handler.set_callback(GDT_ET_SRVC_MSG_ERROR, hndlr);
}

bool gdt::ServiceMsgManager::process_callback(GDTEventType type,
                                              GDTCallbackArgs *args) {
    return cb_handler.process_callback(type, args);
}

void gdt::ServiceMsgManager::setup_server(GDTSession *gdts,
                                          gdt::GDTCallbackMethod *_usr_stream_nc_hndlr,
                                          gdt::GDTCallbackMethod *_usr_stream_hndlr) {
    // set extra user stream handler
    srvcs_nc.usr_stream_nc_hndlr = _usr_stream_nc_hndlr;
    srvcs_nc.usr_stream_hndlr = _usr_stream_hndlr;
    // set end event handler
    gdts->set_callback(gdt::GDT_ET_CLIENT_NEW, &srvcs_nc);
}

void gdt::ServiceMsgManager::setup_client(GDTClient *gdtc) {
    // NULL check
    if (gdtc == NULL)
        return;
    // set end event handler
    gdtc->set_callback(gdt::GDT_ET_STREAM_NEW, &srvcs_hndlr);
}

gdt::ServiceMessage *gdt::ServiceMsgManager::new_smsg() {
    ServiceMessage *tmp = msg_pool.allocate_constructed();
    return tmp;
}

int gdt::ServiceMsgManager::free_smsg(ServiceMessage *msg,
                                      bool params_only,
                                      bool clear_vpmap) {
    // free params
    std::vector<ServiceParam *> *params = msg->get_param_map();

    ServiceParam *param = NULL;
    for (unsigned int i = 0; i < params->size(); i++) {
        param = (*params)[i];
        // check for temp linked buffer params
        for (unsigned int j = 0; j < param->linked.size(); j++) {
            param_factory->free_param(param->linked[j]);
        }
        param->linked.clear();
        // free param
        param_factory->free_param(param);
    }

    // check frag param
    if (msg->get_frag_param() != NULL) {
        // check for temp linked buffer params in frag param
        for (unsigned int j = 0; j < msg->get_frag_param()->linked.size();
             j++) {
            param_factory->free_param(msg->get_frag_param()->linked[j]);
        }
        msg->get_frag_param()->linked.clear();
        // free frag param
        param_factory->free_param(msg->get_frag_param());
    }

    // clear params
    params->clear();
    // clear vpmap
    if (clear_vpmap)
        msg->vpmap.clear_params();

    // if freeing smsg also
    if (!params_only) {
        // return to pool
        int res = msg_pool.deallocate_constructed(msg);
        // result
        return res;
    }
    // ok
    return 0;
}

gdt::ServiceParamFactory *gdt::ServiceMsgManager::get_param_factory() {
    return param_factory;
}

gdt::ParamIdTypeMap *gdt::ServiceMsgManager::get_idt_map() { return idt_map; }

int gdt::ServiceMsgManager::vpmap_sparam_sync(ServiceMessage *msg, 
                                              const std::vector<ServiceParam*> *pmap) {
    // freee sparams, do not clear vpmap
    free_smsg(msg, true, false);
    // vars
    ServiceParam *param = NULL;
    bool err = false;

    // process vpmap
    for (mink_utils::VariantParamMap<uint32_t>::it_t it =
             msg->vpmap.get_begin();
         it != msg->vpmap.get_end(); it++) {
        // skip pointer param type
        if (it->second.get_type() == mink_utils::DPT_POINTER)
            continue;
        // skip context other then default 0
        if (it->first.context != 0)
            continue;
        // allocate new service param
        param = get_param_factory()->new_param(gdt::SPT_VARIANT);
        // sanity check
        if (param == NULL) {
            err = true;
            break;
        }
        // set service param data from decoded param
        param->set(&it->second);
        // add service param to service message
        msg->add_param(it->first.key, param, it->first.index);
    }
    // extra params
    if(pmap != NULL){
        for(auto it = pmap->begin(); it != pmap->end(); it++){
            // add service param to service message
            msg->add_param((*it)->get_id(), (*it), (*it)->get_index());
        }
    }

    // result
    return err;
}

int gdt::ServiceMsgManager::send(ServiceMessage *msg,
                                 GDTClient *gdtc,
                                 const char *dtype,
                                 const char *did,
                                 bool async,
                                 gdt::GDTCallbackMethod *on_sent) {
    if (msg != NULL && gdtc != NULL) {

        // start new GDT stream
        GDTStream *gdt_stream = gdtc->allocate_stream_pool();

        // if stream cannot be created, return err
        if (gdt_stream == NULL) {
            gdtc->get_stats(GDT_OUTBOUND_STATS)
                ->strm_alloc_errors.add_fetch(1);
            return 10;
        }

        // setup stream directly
        gdt_stream->set_client(gdtc);
        gdt_stream->reset(true);
        gdt_stream->clear_callbacks();
        gdt_stream->clear_params();
        gdt_stream->set_destination(dtype, did);

        unsigned int pc;
        unsigned int bc;
        unsigned int tbc = 0;

        // param map
        std::vector<ServiceParam *> *pmap = msg->get_param_map();
        pc = pmap->size();

        // calculate total param size (add extra 3 bytes for dual byte length
        // and single byte tag)
        ServiceParam *tmp_param = NULL;
        for (unsigned int i = 0; i < pmap->size(); i++) {
            tmp_param = (*pmap)[i];
            // check fragmentation
            if (tmp_param->is_fragmented()) {
                // -1 to exclude already included first fragment
                pc += tmp_param->fragments - 1;
                // add extra 3 bytes to size calculation (Tag + Length (BER
                // Definite long))
            }
        }

        // add extra buffer for fragmented params (used when streaming from non
        // pre-allocated sources) max size is pps
        ServiceParam *new_param = NULL;

        for (unsigned int i = 0; i < pmap->size(); i++) {
            tmp_param = (*pmap)[i];
            if (tmp_param->is_fragmented()) {
                for (unsigned int j = 0; j < 4; j++) {
                    new_param = param_factory->new_param(tmp_param->type);
                    if (new_param != NULL)
                        tmp_param->linked.push_back(new_param);
                }
                tmp_param->linked_index = 0;
            }
        }

        // reset user handler from previous instance
        msg->get_sdone_hndlr()->usr_method = NULL;
        // reset status from previous instance
        msg->get_sdone_hndlr()->status = 0;
        // set end event handler
        gdt_stream->set_callback(gdt::GDT_ET_STREAM_END,
                                  msg->get_sdone_hndlr());
        gdt_stream->set_callback(gdt::GDT_ET_STREAM_TIMEOUT,
                                  msg->get_sdone_hndlr());
        // if async mode, set user handler
        if (async)
            msg->get_sdone_hndlr()->usr_method = on_sent;
        // get handler
        ServiceMessageNext *cb = msg->get_snext_hndlr();
        // reset pos (param pos)
        cb->pos = 0;
        // reset pindex (param pos including fragments)
        cb->pindex = 0;

        cb->pc = pc;
        // set callback
        gdt_stream->set_callback(gdt::GDT_ET_STREAM_NEXT, cb);

        // create body
        asn1::GDTMessage *gdtm = gdt_stream->get_gdt_message();
        // prepare body
        if (gdtm->_body != NULL) {
            gdtm->_body->unlink(1);
            gdtm->_body->_service_msg->set_linked_data(1);

        } else {
            gdtm->set_body();
            gdtm->prepare();
        }
        asn1::ServiceMessage *sm = gdtm->_body->_service_msg;

        // set params, allocate 10 initial children
        if (!sm->_params) {
            sm->set_params();
            asn1::Parameters *p = sm->_params;
            // set children, allocate more
            for (int i = 0; i < 10; i++) {
                p->set_child(i);
                p->get_child(i)->set_value();
                p->get_child(i)->_value->set_child(0);
                p->get_child(i)->_value->set_child(1);
                p->get_child(i)->_value->set_child(2);
                p->get_child(i)->_value->set_child(3);
            }
            // prepare
            asn1::prepare(sm, sm->parent_node);
        }

        // set service id
        sm->_service_id->set_linked_data(1,
                                         (unsigned char *)msg->get_service_idp(),
                                         sizeof(uint32_t));

        // set service action
        sm->_service_action->set_linked_data(1,
                                             (unsigned char *)msg->get_service_actionp(),
                                             1);

        // params
        ServiceParam *sc_param = NULL;
        asn1::Parameters *params = gdtm->_body->_service_msg->_params;

        // loop params
        for (unsigned int j = 0;
             tbc < MAX_PARAMS_SIZE && cb->pos < pmap->size();
             j++, cb->pos++, cb->pindex++) {
            sc_param = (*pmap)[cb->pos];
            // check if more allocations are needed
            if (params->get_child(j) == NULL) {
                params->set_child(j);
                params->get_child(j)->set_value();
                params->get_child(j)->_value->set_child(0);
                params->get_child(j)->_value->set_child(1);
                params->get_child(j)->_value->set_child(2);
                params->get_child(j)->_value->set_child(3);
                // prepare
                asn1::prepare(params, params->parent_node);
            }

            // update total byte count
            tbc += sc_param->data_size + 25;
            // check if limit reached
            if (tbc > MAX_PARAMS_SIZE)
                break;

            // set gdt param id and data
            params->get_child(j)->_id->set_linked_data(1,
                                                       (unsigned char *)sc_param->get_idp(),
                                                       sizeof(uint32_t));
            params->get_child(j)->_value->get_child(0)->set_linked_data(1,
                                                                        sc_param->data_p,
                                                                        sc_param->data_size);

            // check fragmentation
            if (sc_param->is_fragmented()) {
                params->get_child(j)->_value->get_child(1)->set_linked_data(1,
                                                                            (unsigned char *)sc_param->get_fragmentation_p(),
                                                                            1);
                // variant param id index and type
                params->get_child(j)->_value->get_child(2)->set_linked_data(1,
                                                                            (unsigned char *)&sc_param->index,
                                                                            1);
                params->get_child(j)->_value->get_child(3)->set_linked_data(1,
                                                                            (unsigned char *)&sc_param->extra_type,
                                                                            1);

                // next fragment
                ++sc_param->fragment_index;
                ++j;
                ++cb->pindex;
                // run data fetch method
                (*sc_param->param_data_cb)(sc_param,
                                           sc_param->in_data_p,
                                           sc_param->total_data_size);

                // process fragments
                while ((tbc < MAX_PARAMS_SIZE) && (sc_param->fragment_index < sc_param->fragments)) {
                    // calculate number of bytes needed for current fragment
                    bc = (sc_param->total_data_size > sizeof(sc_param->data)
                              ? sizeof(sc_param->data)
                              : sc_param->total_data_size);

                    // check if more allocations are needed
                    if (params->get_child(j) == NULL) {
                        params->set_child(j);
                        params->get_child(j)->set_value();
                        params->get_child(j)->_value->set_child(0);
                        params->get_child(j)->_value->set_child(1);
                        params->get_child(j)->_value->set_child(2);
                        params->get_child(j)->_value->set_child(3);
                        // prepare
                        asn1::prepare(params, params->parent_node);
                    }

                    // update total byte count
                    tbc += bc + 25;
                    // check if limit reached
                    if (tbc > MAX_PARAMS_SIZE)
                        break;

                    // set gdt values
                    params->get_child(j)->_id->set_linked_data(1,
                                                               (unsigned char *)sc_param->get_idp(),
                                                               sizeof(uint32_t));
                    params->get_child(j)->_value->get_child(0)->set_linked_data(1,
                                                                                sc_param->data_p,
                                                                                bc);
                    // variant param id index and type
                    params->get_child(j)->_value->get_child(2)->set_linked_data(1,
                                                                                (unsigned char *)&sc_param->index,
                                                                                1);
                    params->get_child(j)->_value->get_child(3)->set_linked_data(1,
                                                                                (unsigned char *)&sc_param->extra_type,
                                                                                1);

                    // check if last fragment, disable fragmentation flag (last
                    // fragment must not contain fragmentation flag)
                    if (sc_param->fragment_index == sc_param->fragments - 1) {
                        params->get_child(j)
                              ->_value
                              ->get_child(1)
                              ->set_linked_data(1,
                                                (unsigned char*)&ServiceParam::FRAGMENTATION_DONE,
                                                1);

                    } else {
                        // set gdt fragmentation flag
                        params->get_child(j)
                              ->_value->get_child(1)
                              ->set_linked_data(1,
                                                (unsigned char*)&ServiceParam::FRAGMENTATION_NEXT,
                                                1);
                    }

                    // next
                    ++sc_param->fragment_index;
                    ++j;
                    ++cb->pindex;
                    // run data fetch method
                    (*sc_param->param_data_cb)(sc_param,
                                               sc_param->in_data_p,
                                               sc_param->total_data_size);
                }
                // break if fragmentation in progress and not finished (to skip
                // increment, next call should process the same param again)
                if (sc_param->fragment_index < sc_param->fragments)
                    break;
                // rewind gdt param child count and packet index
                else {
                    --j;
                    --cb->pindex;
                }

                // no fragmentation
            } else {
                params->get_child(j)->_value->get_child(1)->set_linked_data(1,
                                                                            (unsigned char *)sc_param->get_fragmentation_p(),
                                                                            1);
                // variant param id index and type
                params->get_child(j)->_value->get_child(2)->set_linked_data(1,
                                                                            (unsigned char *)&sc_param->index,
                                                                            1);
                params->get_child(j)->_value->get_child(3)->set_linked_data(1,
                                                                            (unsigned char *)&sc_param->extra_type,
                                                                            1);
            }
        }

        // remove unused chidren
        for (unsigned int i = cb->pindex; i < params->children.size(); i++)
            params->get_child(i)->unlink(1);

        // add to list of active streams directly
        gdtc->add_stream(gdt_stream);
        // start stream
        gdt_stream->send(true);

        // sync mode
        if (!async) {
            if (msg->signal_wait() == 1)
                return 100;
            else
                return msg->get_sdone_hndlr()->status;

            // async mode
        } else {
            // ok
            return 0;
        }
    }
    // err
    return 1;
}

void gdt::ServiceMessageAsyncDone::run(GDTCallbackArgs *args) {
    gdt::ServiceMessage *smsg = (gdt::ServiceMessage *)args->get_arg(
        gdt::GDT_CB_INPUT_ARGS, gdt::GDT_CB_ARGS_SRVC_MSG);
    smsg->get_smsg_manager()->free_smsg(smsg);
}

