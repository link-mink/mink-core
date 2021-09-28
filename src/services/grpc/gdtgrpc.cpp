/*            _       _
 *  _ __ ___ (_)_ __ | | __
 * | '_ ` _ \| | '_ \| |/ /
 * | | | | | | | | | |   <
 * |_| |_| |_|_|_| |_|_|\_\
 *
 * SPDX-License-Identifier: MIT
 *
 */

#include "gdtgrpc.h"
#include "grpc.h"

/***********************/
/* extra user callback */
/***********************/
class EVUserCB: public gdt::GDTCallbackMethod {
public:
    EVUserCB() = default;
    EVUserCB(const EVUserCB &o) = delete;
    EVUserCB &operator=(const EVUserCB &o) = delete;
    ~EVUserCB() override {std::cout << "==========+FREEING ===============" << std::endl;  }

    // param map for non-variant params
    std::vector<gdt::ServiceParam*> pmap;
};


/************/
/* RPCBase */
/************/
RPCBase::RPCBase(gdt_grpc::SysagentGrpcService::AsyncService *service,
                   grpc::ServerCompletionQueue *cq) : service_(service), 
                                                      cq_(cq), 
                                                      responder_(&ctx_), 
                                                      status_(CREATE) {
    proceed();
}

RPCBase::~RPCBase(){
    std::cout << "RPCBase::~RPCBase: " << this << std::endl;

}
void RPCBase::proceed(){
    std::cout << "Calldata:proceed: " << this << std::endl;
}

bool RPCBase::gdt_push(const gdt_grpc::CommonRequest &req, 
                        RPCBase *data,
                        uint32_t cmd_id) const {

    auto dd = static_cast<GrpcdDescriptor*>(mink::CURRENT_DAEMON);
    // local routing daemon pointer
    gdt::GDTClient *gdtc = nullptr;
    // smsg
    gdt::ServiceMessage *msg = nullptr;
    // payload
    GrpcPayload *pld = nullptr;
    // randomizer
    mink_utils::Randomizer rand;
    // tmp guid
    uint8_t guid[16];

    // *********************************************
    // ************ push via GDT *******************
    // *********************************************
    // get new router if connection broken
    if (!(dd->rtrd_gdtc && dd->rtrd_gdtc->is_registered()))
        dd->rtrd_gdtc = dd->gdts->get_registered_client("routingd");
    // local routing daemon pointer
    gdtc = dd->rtrd_gdtc;
    // null check
    if (!gdtc) {
        // TODO stats
        return false;
    }
    // allocate new service message
    msg = dd->gdtsmm->new_smsg();
    // msg sanity check
    if (!msg) {
        // TODO stats
        return false;
    }
    // header and body
    const gdt_grpc::Header &hdr = req.header();
    const gdt_grpc::Body &bdy = req.body();

    // service id
    msg->set_service_id(bdy.service_id());

    // extra params
    EVUserCB *ev_usr_cb = nullptr;
    std::vector<gdt::ServiceParam*> *pmap = nullptr;
    // params
    for(size_t i = 0; i<bdy.params_size(); i++){
        // param
        const gdt_grpc::Body::Param &p = bdy.params(i);
        // check if param streaming if necessary
        if(p.value().size() > msg->vpmap.get_max()) {
            gdt::ServiceParam *sp = msg->get_smsg_manager()
                                       ->get_param_factory()
                                       ->new_param(gdt::SPT_OCTETS);
            if(sp){
                // creat only once
                if (!ev_usr_cb) {
                    ev_usr_cb = new EVUserCB();
                    msg->params.set_param(3, ev_usr_cb);
                    pmap = &ev_usr_cb->pmap;
                }
                sp->set_data(p.value().c_str(), p.value().size());
                sp->set_id(p.id());
                sp->set_index(p.index());
                sp->set_extra_type(0);
                pmap->push_back(sp);
            }
         
            continue;

        }
        // set gdt data 
        msg->vpmap.set_cstr(p.id(), p.value().c_str());
    }
 
    // set source daemon type
    msg->vpmap.set_cstr(asn1::ParameterType::_pt_mink_daemon_type,
                        dd->get_daemon_type());
    // set source daemon id
    msg->vpmap.set_cstr(asn1::ParameterType::_pt_mink_daemon_id,
                        dd->get_daemon_id());

    // allocate payload object for correlation (grpc <-> gdt)
    pld = dd->cpool.allocate_constructed();
    if (!pld) {
        // TODO stats
        dd->gdtsmm->free_smsg(msg);
        return false;
    }
    
    // command id
    msg->vpmap.erase_param(asn1::ParameterType::_pt_mink_command_id);
    msg->vpmap.set_int(asn1::ParameterType::_pt_mink_command_id,
                       cmd_id);

    // set correlation payload data
    pld->cdata = data;
    // generate guid
    rand.generate(guid, 16);
    pld->guid.set(guid);
    msg->vpmap.set_octets(asn1::ParameterType::_pt_mink_guid, 
                          pld->guid.data(), 
                          16);
 
    // sync vpmap
    if (dd->gdtsmm->vpmap_sparam_sync(msg, pmap) != 0) {
        // TODO stats
        dd->gdtsmm->free_smsg(msg);
        return false;
    }

    // destination id
    std::string dest_id = hdr.destination().id();
    std::cout << "DESTINATIN ID: " << dest_id << std::endl;

    // send service message
    int r = dd->gdtsmm->send(msg, 
                             gdtc, 
                             hdr.destination().type().c_str(), 
                             (!dest_id.empty() ? dest_id.c_str() : nullptr),
                             true, 
                             &dd->ev_srvcm_tx);
    if (r) {
        // TODO stats
        dd->gdtsmm->free_smsg(msg);
        return false;
    }

    // save to correlarion map
    dd->cmap.lock();
    dd->cmap.set(pld->guid, pld);
    dd->cmap.unlock();

    return true;
}

bool RPCBase::verify(const gdt_grpc::CommonRequest &req, uint32_t *cmd_id) const {
    // header
    const gdt_grpc::Header &hdr = req.header();
    // body
    const gdt_grpc::Body &bdy = req.body();
    // destination type
    if(hdr.destination().type().empty()) return false;
    // service id
    if (bdy.service_id() == gdt_grpc::Body_ServiceId_UNKNOWN_SERVICE_ID)
        return false;
    // params
    if(bdy.params_size() == 0) return false;
    // param command id
    for (int i = 0; i < bdy.params_size(); i++) {
        // param
        const gdt_grpc::Body::Param &p = bdy.params(i);
        // look for command id
        if (p.id() == asn1::ParameterType::_pt_mink_command_id) {
            try {
                *cmd_id = stoi(p.value());
            } catch (const std::exception &ex) {
                return false;
            }
            return true;
        }
    }
    // err
    return false;
}

/***************/
/* GetDataCall */
/***************/
GetDataCall::GetDataCall(gdt_grpc::SysagentGrpcService::AsyncService *service,
                         grpc::ServerCompletionQueue *cq): RPCBase(service, cq){
    proceed();

}

void GetDataCall::proceed() {
    if (status_ == CREATE) {
        // Make this instance progress to the PROCESS state.
        status_ = PROCESS;

        // As part of the initial CREATE state, we *request* that the system
        // start processing SayHello requests. In this request, "this" acts are
        // the tag uniquely identifying the request (so that different RPCBase
        // instances can serve different requests concurrently), in this case
        // the memory address of this RPCBase instance.
        service_->RequestGetData(&ctx_, 
                                 &request_, 
                                 &responder_, 
                                 cq_, 
                                 cq_,
                                 this);
    } else if (status_ == PROCESS) {
        // Spawn a new RPCBase instance to serve new clients while we process
        // the one for this RPCBase. The instance will deallocate itself as
        // part of its FINISH state.
        new GetDataCall(service_, cq_);

        // defulalt res
        grpc::Status status;
        // command id
        uint32_t cmd_id = 0;

        // verify header
        if(!verify(request_, &cmd_id)){
            status = grpc::Status(grpc::INVALID_ARGUMENT, "");
        }else{
            std::cout << "=== CMD ID: " << cmd_id << std::endl;
            // send via GDT (GRPC reply conversion in GDT callback)
            if(!gdt_push(request_, this, cmd_id)){
                // And we are done! Let the gRPC runtime know we've finished,
                // using the memory address of this instance as the uniquely
                // identifying tag for the event.
                status = grpc::Status(grpc::ABORTED, "");
                status_ = FINISH;
                responder_.Finish(reply_, status, this);
                return;
            }
        }


    } else {
        GPR_ASSERT(status_ == FINISH);
        // Once in the FINISH state, deallocate ourselves (RPCBase).
        delete this;
    }
}

/*****************/
/* GdtGrpcServer */
/*****************/
GdtGrpcServer::~GdtGrpcServer(){
    server_->Shutdown();
    // Always shutdown the completion queue after the server.
    cq_->Shutdown();
}

void GdtGrpcServer::run(){
    std::string server_address("0.0.0.0:50051");
    grpc::ServerBuilder builder;
    builder.SetMaxReceiveMessageSize(50*1024*1024);
    // Listen on the given address without any authentication mechanism.
    builder.AddListeningPort(server_address, grpc::InsecureServerCredentials());
    // Register "service_" as the instance through which we'll communicate with
    // clients. In this case it corresponds to an *asynchronous* service.
    builder.RegisterService(&service_);
    // Get hold of the completion queue used for the asynchronous communication
    // with the gRPC runtime.
    cq_ = builder.AddCompletionQueue();
    // Finally assemble the server.
    server_ = builder.BuildAndStart();
    std::cout << "Server listening on " << server_address << std::endl;
    // proceed to the server's main loop.
    handle_rpcs();
}

void GdtGrpcServer::handle_rpcs() {
    auto dd = static_cast<GrpcdDescriptor*>(mink::CURRENT_DAEMON);
    // Spawn a new RPCBase instance to serve new clients.
    new GetDataCall(&service_, cq_.get());
    void *tag; // uniquely identifies a request.
    bool ok;
    while (true) {
        // Block waiting to read the next event from the completion queue. The
        // event is uniquely identified by its tag, which in this case is the
        // memory address of a RPCBase instance.
        // The return value of Next should always be checked. This return value
        // tells us whether there is any kind of event or cq_ is shutting down.
        GPR_ASSERT(cq_->Next(&tag, &ok));

        auto call = static_cast<RPCBase*>(tag);
        call->proceed();
        // process timeout
        dd->cmap_process_timeout();
    }
}


