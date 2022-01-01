/*            _       _
 *  _ __ ___ (_)_ __ | | __
 * | '_ ` _ \| | '_ \| |/ /
 * | | | | | | | | | |   <
 * |_| |_| |_|_|_| |_|_|\_\
 *
 * SPDX-License-Identifier: MIT
 *
 */

#ifndef GRPC_GDT_H
#define GRPC_GDT_H 

#include <grpcpp/impl/codegen/status_code_enum.h>
#include <grpcpp/grpcpp.h>
#include <gdt.grpc.pb.h>

// Class encompasing the state and logic needed to serve a request.
class RPCBase {
public:
    // Take in the "service" instance (in this case representing an
    // asynchronous server) and the completion queue "cq" used for
    // asynchronous communication with the gRPC runtime.
    RPCBase(gdt_grpc::SysagentGrpcService::AsyncService *service, 
             grpc::ServerCompletionQueue *cq);
    virtual ~RPCBase();

    virtual void proceed();
    bool verify(const gdt_grpc::CommonRequest &req, uint32_t *cmd_id) const;
    bool gdt_push(const gdt_grpc::CommonRequest &req, 
                  RPCBase *data,
                  uint32_t cmd_id) const;

    // The means of communication with the gRPC runtime for an asynchronous
    // server.
    gdt_grpc::SysagentGrpcService::AsyncService *service_;
    // The producer-consumer queue where for asynchronous server
    // notifications.
    grpc::ServerCompletionQueue *cq_;
    // Context for the rpc, allowing to tweak aspects of it such as the use
    // of compression, authentication, as well as to send metadata back to
    // the client.
    grpc::ServerContext ctx_;

    // What we get from the client.
    gdt_grpc::CommonRequest request_;
    // What we send back to the client.
    gdt_grpc::CommonReply reply_;

    // The means to get back to the client.
    grpc::ServerAsyncResponseWriter<gdt_grpc::CommonReply> responder_;

    // Let's implement a tiny state machine with the following states.
    enum CallStatus { CREATE, PROCESS, FINISH };
    CallStatus status_; // The current serving state.
};

class GetDataCall: public RPCBase {
public:
    GetDataCall(gdt_grpc::SysagentGrpcService::AsyncService *service,
                grpc::ServerCompletionQueue *cq);

    void proceed() override;
};

class GdtGrpcServer final {
public:
    ~GdtGrpcServer();
    // There is no shutdown handling in this code.
    void run(); 

private:
    // This can be run in multiple threads if needed.
    void handle_rpcs();

    std::unique_ptr<grpc::ServerCompletionQueue> cq_;
    gdt_grpc::SysagentGrpcService::AsyncService service_;
    std::unique_ptr<grpc::Server> server_;
};



#endif /* ifndef GRPC_GDT_H */
