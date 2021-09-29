// Generated by the gRPC C++ plugin.
// If you make any local change, they will be lost.
// source: gdt.proto

#include "gdt.pb.h"
#include "gdt.grpc.pb.h"

#include <functional>
#include <grpcpp/impl/codegen/async_stream.h>
#include <grpcpp/impl/codegen/async_unary_call.h>
#include <grpcpp/impl/codegen/channel_interface.h>
#include <grpcpp/impl/codegen/client_unary_call.h>
#include <grpcpp/impl/codegen/client_callback.h>
#include <grpcpp/impl/codegen/message_allocator.h>
#include <grpcpp/impl/codegen/method_handler.h>
#include <grpcpp/impl/codegen/rpc_service_method.h>
#include <grpcpp/impl/codegen/server_callback.h>
#include <grpcpp/impl/codegen/server_callback_handlers.h>
#include <grpcpp/impl/codegen/server_context.h>
#include <grpcpp/impl/codegen/service_type.h>
#include <grpcpp/impl/codegen/sync_stream.h>
namespace gdt_grpc {

static const char* SysagentGrpcService_method_names[] = {
  "/gdt_grpc.SysagentGrpcService/GetCpuStats",
  "/gdt_grpc.SysagentGrpcService/GetSysinfo",
  "/gdt_grpc.SysagentGrpcService/GetData",
};

std::unique_ptr< SysagentGrpcService::Stub> SysagentGrpcService::NewStub(const std::shared_ptr< ::grpc::ChannelInterface>& channel, const ::grpc::StubOptions& options) {
  (void)options;
  std::unique_ptr< SysagentGrpcService::Stub> stub(new SysagentGrpcService::Stub(channel, options));
  return stub;
}

SysagentGrpcService::Stub::Stub(const std::shared_ptr< ::grpc::ChannelInterface>& channel, const ::grpc::StubOptions& options)
  : channel_(channel), rpcmethod_GetCpuStats_(SysagentGrpcService_method_names[0], options.suffix_for_stats(),::grpc::internal::RpcMethod::NORMAL_RPC, channel)
  , rpcmethod_GetSysinfo_(SysagentGrpcService_method_names[1], options.suffix_for_stats(),::grpc::internal::RpcMethod::NORMAL_RPC, channel)
  , rpcmethod_GetData_(SysagentGrpcService_method_names[2], options.suffix_for_stats(),::grpc::internal::RpcMethod::NORMAL_RPC, channel)
  {}

::grpc::Status SysagentGrpcService::Stub::GetCpuStats(::grpc::ClientContext* context, const ::gdt_grpc::CommonRequest& request, ::gdt_grpc::CommonReply* response) {
  return ::grpc::internal::BlockingUnaryCall< ::gdt_grpc::CommonRequest, ::gdt_grpc::CommonReply, ::grpc::protobuf::MessageLite, ::grpc::protobuf::MessageLite>(channel_.get(), rpcmethod_GetCpuStats_, context, request, response);
}

void SysagentGrpcService::Stub::experimental_async::GetCpuStats(::grpc::ClientContext* context, const ::gdt_grpc::CommonRequest* request, ::gdt_grpc::CommonReply* response, std::function<void(::grpc::Status)> f) {
  ::grpc::internal::CallbackUnaryCall< ::gdt_grpc::CommonRequest, ::gdt_grpc::CommonReply, ::grpc::protobuf::MessageLite, ::grpc::protobuf::MessageLite>(stub_->channel_.get(), stub_->rpcmethod_GetCpuStats_, context, request, response, std::move(f));
}

void SysagentGrpcService::Stub::experimental_async::GetCpuStats(::grpc::ClientContext* context, const ::gdt_grpc::CommonRequest* request, ::gdt_grpc::CommonReply* response, ::grpc::experimental::ClientUnaryReactor* reactor) {
  ::grpc::internal::ClientCallbackUnaryFactory::Create< ::grpc::protobuf::MessageLite, ::grpc::protobuf::MessageLite>(stub_->channel_.get(), stub_->rpcmethod_GetCpuStats_, context, request, response, reactor);
}

::grpc::ClientAsyncResponseReader< ::gdt_grpc::CommonReply>* SysagentGrpcService::Stub::PrepareAsyncGetCpuStatsRaw(::grpc::ClientContext* context, const ::gdt_grpc::CommonRequest& request, ::grpc::CompletionQueue* cq) {
  return ::grpc::internal::ClientAsyncResponseReaderHelper::Create< ::gdt_grpc::CommonReply, ::gdt_grpc::CommonRequest, ::grpc::protobuf::MessageLite, ::grpc::protobuf::MessageLite>(channel_.get(), cq, rpcmethod_GetCpuStats_, context, request);
}

::grpc::ClientAsyncResponseReader< ::gdt_grpc::CommonReply>* SysagentGrpcService::Stub::AsyncGetCpuStatsRaw(::grpc::ClientContext* context, const ::gdt_grpc::CommonRequest& request, ::grpc::CompletionQueue* cq) {
  auto* result =
    this->PrepareAsyncGetCpuStatsRaw(context, request, cq);
  result->StartCall();
  return result;
}

::grpc::Status SysagentGrpcService::Stub::GetSysinfo(::grpc::ClientContext* context, const ::gdt_grpc::CommonRequest& request, ::gdt_grpc::CommonReply* response) {
  return ::grpc::internal::BlockingUnaryCall< ::gdt_grpc::CommonRequest, ::gdt_grpc::CommonReply, ::grpc::protobuf::MessageLite, ::grpc::protobuf::MessageLite>(channel_.get(), rpcmethod_GetSysinfo_, context, request, response);
}

void SysagentGrpcService::Stub::experimental_async::GetSysinfo(::grpc::ClientContext* context, const ::gdt_grpc::CommonRequest* request, ::gdt_grpc::CommonReply* response, std::function<void(::grpc::Status)> f) {
  ::grpc::internal::CallbackUnaryCall< ::gdt_grpc::CommonRequest, ::gdt_grpc::CommonReply, ::grpc::protobuf::MessageLite, ::grpc::protobuf::MessageLite>(stub_->channel_.get(), stub_->rpcmethod_GetSysinfo_, context, request, response, std::move(f));
}

void SysagentGrpcService::Stub::experimental_async::GetSysinfo(::grpc::ClientContext* context, const ::gdt_grpc::CommonRequest* request, ::gdt_grpc::CommonReply* response, ::grpc::experimental::ClientUnaryReactor* reactor) {
  ::grpc::internal::ClientCallbackUnaryFactory::Create< ::grpc::protobuf::MessageLite, ::grpc::protobuf::MessageLite>(stub_->channel_.get(), stub_->rpcmethod_GetSysinfo_, context, request, response, reactor);
}

::grpc::ClientAsyncResponseReader< ::gdt_grpc::CommonReply>* SysagentGrpcService::Stub::PrepareAsyncGetSysinfoRaw(::grpc::ClientContext* context, const ::gdt_grpc::CommonRequest& request, ::grpc::CompletionQueue* cq) {
  return ::grpc::internal::ClientAsyncResponseReaderHelper::Create< ::gdt_grpc::CommonReply, ::gdt_grpc::CommonRequest, ::grpc::protobuf::MessageLite, ::grpc::protobuf::MessageLite>(channel_.get(), cq, rpcmethod_GetSysinfo_, context, request);
}

::grpc::ClientAsyncResponseReader< ::gdt_grpc::CommonReply>* SysagentGrpcService::Stub::AsyncGetSysinfoRaw(::grpc::ClientContext* context, const ::gdt_grpc::CommonRequest& request, ::grpc::CompletionQueue* cq) {
  auto* result =
    this->PrepareAsyncGetSysinfoRaw(context, request, cq);
  result->StartCall();
  return result;
}

::grpc::Status SysagentGrpcService::Stub::GetData(::grpc::ClientContext* context, const ::gdt_grpc::CommonRequest& request, ::gdt_grpc::CommonReply* response) {
  return ::grpc::internal::BlockingUnaryCall< ::gdt_grpc::CommonRequest, ::gdt_grpc::CommonReply, ::grpc::protobuf::MessageLite, ::grpc::protobuf::MessageLite>(channel_.get(), rpcmethod_GetData_, context, request, response);
}

void SysagentGrpcService::Stub::experimental_async::GetData(::grpc::ClientContext* context, const ::gdt_grpc::CommonRequest* request, ::gdt_grpc::CommonReply* response, std::function<void(::grpc::Status)> f) {
  ::grpc::internal::CallbackUnaryCall< ::gdt_grpc::CommonRequest, ::gdt_grpc::CommonReply, ::grpc::protobuf::MessageLite, ::grpc::protobuf::MessageLite>(stub_->channel_.get(), stub_->rpcmethod_GetData_, context, request, response, std::move(f));
}

void SysagentGrpcService::Stub::experimental_async::GetData(::grpc::ClientContext* context, const ::gdt_grpc::CommonRequest* request, ::gdt_grpc::CommonReply* response, ::grpc::experimental::ClientUnaryReactor* reactor) {
  ::grpc::internal::ClientCallbackUnaryFactory::Create< ::grpc::protobuf::MessageLite, ::grpc::protobuf::MessageLite>(stub_->channel_.get(), stub_->rpcmethod_GetData_, context, request, response, reactor);
}

::grpc::ClientAsyncResponseReader< ::gdt_grpc::CommonReply>* SysagentGrpcService::Stub::PrepareAsyncGetDataRaw(::grpc::ClientContext* context, const ::gdt_grpc::CommonRequest& request, ::grpc::CompletionQueue* cq) {
  return ::grpc::internal::ClientAsyncResponseReaderHelper::Create< ::gdt_grpc::CommonReply, ::gdt_grpc::CommonRequest, ::grpc::protobuf::MessageLite, ::grpc::protobuf::MessageLite>(channel_.get(), cq, rpcmethod_GetData_, context, request);
}

::grpc::ClientAsyncResponseReader< ::gdt_grpc::CommonReply>* SysagentGrpcService::Stub::AsyncGetDataRaw(::grpc::ClientContext* context, const ::gdt_grpc::CommonRequest& request, ::grpc::CompletionQueue* cq) {
  auto* result =
    this->PrepareAsyncGetDataRaw(context, request, cq);
  result->StartCall();
  return result;
}

SysagentGrpcService::Service::Service() {
  AddMethod(new ::grpc::internal::RpcServiceMethod(
      SysagentGrpcService_method_names[0],
      ::grpc::internal::RpcMethod::NORMAL_RPC,
      new ::grpc::internal::RpcMethodHandler< SysagentGrpcService::Service, ::gdt_grpc::CommonRequest, ::gdt_grpc::CommonReply, ::grpc::protobuf::MessageLite, ::grpc::protobuf::MessageLite>(
          [](SysagentGrpcService::Service* service,
             ::grpc::ServerContext* ctx,
             const ::gdt_grpc::CommonRequest* req,
             ::gdt_grpc::CommonReply* resp) {
               return service->GetCpuStats(ctx, req, resp);
             }, this)));
  AddMethod(new ::grpc::internal::RpcServiceMethod(
      SysagentGrpcService_method_names[1],
      ::grpc::internal::RpcMethod::NORMAL_RPC,
      new ::grpc::internal::RpcMethodHandler< SysagentGrpcService::Service, ::gdt_grpc::CommonRequest, ::gdt_grpc::CommonReply, ::grpc::protobuf::MessageLite, ::grpc::protobuf::MessageLite>(
          [](SysagentGrpcService::Service* service,
             ::grpc::ServerContext* ctx,
             const ::gdt_grpc::CommonRequest* req,
             ::gdt_grpc::CommonReply* resp) {
               return service->GetSysinfo(ctx, req, resp);
             }, this)));
  AddMethod(new ::grpc::internal::RpcServiceMethod(
      SysagentGrpcService_method_names[2],
      ::grpc::internal::RpcMethod::NORMAL_RPC,
      new ::grpc::internal::RpcMethodHandler< SysagentGrpcService::Service, ::gdt_grpc::CommonRequest, ::gdt_grpc::CommonReply, ::grpc::protobuf::MessageLite, ::grpc::protobuf::MessageLite>(
          [](SysagentGrpcService::Service* service,
             ::grpc::ServerContext* ctx,
             const ::gdt_grpc::CommonRequest* req,
             ::gdt_grpc::CommonReply* resp) {
               return service->GetData(ctx, req, resp);
             }, this)));
}

SysagentGrpcService::Service::~Service() {
}

::grpc::Status SysagentGrpcService::Service::GetCpuStats(::grpc::ServerContext* context, const ::gdt_grpc::CommonRequest* request, ::gdt_grpc::CommonReply* response) {
  (void) context;
  (void) request;
  (void) response;
  return ::grpc::Status(::grpc::StatusCode::UNIMPLEMENTED, "");
}

::grpc::Status SysagentGrpcService::Service::GetSysinfo(::grpc::ServerContext* context, const ::gdt_grpc::CommonRequest* request, ::gdt_grpc::CommonReply* response) {
  (void) context;
  (void) request;
  (void) response;
  return ::grpc::Status(::grpc::StatusCode::UNIMPLEMENTED, "");
}

::grpc::Status SysagentGrpcService::Service::GetData(::grpc::ServerContext* context, const ::gdt_grpc::CommonRequest* request, ::gdt_grpc::CommonReply* response) {
  (void) context;
  (void) request;
  (void) response;
  return ::grpc::Status(::grpc::StatusCode::UNIMPLEMENTED, "");
}


}  // namespace gdt_grpc

