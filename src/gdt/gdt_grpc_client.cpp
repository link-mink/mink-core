/*            _       _
 *  _ __ ___ (_)_ __ | | __
 * | '_ ` _ \| | '_ \| |/ /
 * | | | | | | | | | |   <
 * |_| |_| |_|_|_| |_|_|\_\
 *
 * SPDX-License-Identifier: MIT
 *
 */

#include <iostream>
#include <memory>
#include <string>
#include <grpcpp/grpcpp.h>
#include <gdt_def.h>
#include <gdt.grpc.pb.h>

using grpc::Channel;
using grpc::ClientContext;
using grpc::Status;

class Client {
public:
    Client(std::shared_ptr<Channel> channel)
        : stub_(gdt_grpc::SysagentGrpcService::NewStub(channel)) {}

    std::string GetData(int cmd_id, const std::string &dest_id) {
        // Data we are sending to the server.
        gdt_grpc::CommonRequest request;
        gdt_grpc::Header *hdr = request.mutable_header();
        gdt_grpc::Body *bdy = request.mutable_body();
        gdt_grpc::EndPointDescriptor *dest = hdr->mutable_destination();
        
        // dest
        dest->set_type("sysagentd");
        dest->set_id(dest_id);
        // set service id
        bdy->set_service_id(gdt_grpc::Body_ServiceId_SYSAGENT);
        
        // params
        gdt_grpc::Body::Param *p = bdy->add_params();
        p->set_id(asn1::ParameterType::_pt_mink_command_id);
        p->set_value(std::to_string(cmd_id));

        // Container for the data we expect from the server.
        gdt_grpc::CommonReply reply;

        // Context for the client. It could be used to convey extra information
        // to the server and/or tweak certain RPC behaviors.
        ClientContext context;
        gpr_timespec ts;
        ts.tv_sec = 5;
        ts.tv_nsec = 0;
        ts.clock_type = GPR_TIMESPAN;
        context.set_deadline(ts);

        // The actual RPC.
        Status status = stub_->GetData(&context, request, &reply);

        // Act upon its status.
        if (status.ok()) {
            using namespace gdt_grpc;
            using namespace google::protobuf;;
            const Body &bdy = reply.body();
            const EnumDescriptor *ed = ParameterType_descriptor();
            // process params
            for(int i = 0; i<bdy.params_size(); i++){
                const gdt_grpc::Body::Param &p = bdy.params(i);
                std::cout << "[" << p.id() << "." << p.index();
                const EnumValueDescriptor *vd = ed->FindValueByNumber(p.id());
                if(vd){
                    std::cout << " (" << vd->name() << ")";

                }
                std::cout << "] = " << p.value() << std::endl;
 
            }

            return "OK";
        } else {
            return "RPC failed";
        }
    }

private:
    std::unique_ptr<gdt_grpc::SysagentGrpcService::Stub> stub_;
};

int main(int argc, char **argv) {
    std::string target_str = "localhost:50051";
    Client c(grpc::CreateChannel(target_str, grpc::InsecureChannelCredentials()));

    const google::protobuf::EnumDescriptor *ed = gdt_grpc::SysagentCommand_descriptor();

    if(argc < 2 || !ed->FindValueByName(argv[1])){
        for(int i = 1; i<ed->value_count(); i++){
            const google::protobuf::EnumValueDescriptor *vd = ed->value(i);
            std::cout << vd->name() << std::endl;
        }
        return 0;
    }
    // dest id
    std::string dest_id;
    if(argc > 2 && argv[2]) dest_id.assign(argv[2]);

    // process 
    const google::protobuf::EnumValueDescriptor *vd = ed->FindValueByName(argv[1]);
    std::cout << "=== calling " << vd->name() << " ===" << std::endl;
    std::string reply = c.GetData(vd->number(), dest_id);
    std::cout << "received: " << reply << std::endl << std::endl;
    return 0;

}
