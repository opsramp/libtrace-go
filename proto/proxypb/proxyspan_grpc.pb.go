// Code generated by protoc-gen-go-grpc. DO NOT EDIT.
// versions:
// - protoc-gen-go-grpc v1.2.0
// - protoc             v3.19.1
// source: api/proxyspan.proto

package proxypb

import (
	context "context"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
)

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
// Requires gRPC-Go v1.32.0 or later.
const _ = grpc.SupportPackageIsVersion7

// TraceProxyServiceClient is the client API for TraceProxyService service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type TraceProxyServiceClient interface {
	// For performance reasons, it is recommended to keep this RPC
	// alive for the entire life of the application.
	Export(ctx context.Context, in *ExportTraceProxyServiceRequest, opts ...grpc.CallOption) (*ExportTraceProxyServiceResponse, error)
}

type traceProxyServiceClient struct {
	cc grpc.ClientConnInterface
}

func NewTraceProxyServiceClient(cc grpc.ClientConnInterface) TraceProxyServiceClient {
	return &traceProxyServiceClient{cc}
}

func (c *traceProxyServiceClient) Export(ctx context.Context, in *ExportTraceProxyServiceRequest, opts ...grpc.CallOption) (*ExportTraceProxyServiceResponse, error) {
	out := new(ExportTraceProxyServiceResponse)
	err := c.cc.Invoke(ctx, "/proto.TraceProxyService/Export", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// TraceProxyServiceServer is the server API for TraceProxyService service.
// All implementations must embed UnimplementedTraceProxyServiceServer
// for forward compatibility
type TraceProxyServiceServer interface {
	// For performance reasons, it is recommended to keep this RPC
	// alive for the entire life of the application.
	Export(context.Context, *ExportTraceProxyServiceRequest) (*ExportTraceProxyServiceResponse, error)
	mustEmbedUnimplementedTraceProxyServiceServer()
}

// UnimplementedTraceProxyServiceServer must be embedded to have forward compatible implementations.
type UnimplementedTraceProxyServiceServer struct {
}

func (UnimplementedTraceProxyServiceServer) Export(context.Context, *ExportTraceProxyServiceRequest) (*ExportTraceProxyServiceResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Export not implemented")
}
func (UnimplementedTraceProxyServiceServer) mustEmbedUnimplementedTraceProxyServiceServer() {}

// UnsafeTraceProxyServiceServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to TraceProxyServiceServer will
// result in compilation errors.
type UnsafeTraceProxyServiceServer interface {
	mustEmbedUnimplementedTraceProxyServiceServer()
}

func RegisterTraceProxyServiceServer(s grpc.ServiceRegistrar, srv TraceProxyServiceServer) {
	s.RegisterService(&TraceProxyService_ServiceDesc, srv)
}

func _TraceProxyService_Export_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ExportTraceProxyServiceRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(TraceProxyServiceServer).Export(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/proto.TraceProxyService/Export",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(TraceProxyServiceServer).Export(ctx, req.(*ExportTraceProxyServiceRequest))
	}
	return interceptor(ctx, in, info, handler)
}

// TraceProxyService_ServiceDesc is the grpc.ServiceDesc for TraceProxyService service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var TraceProxyService_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "proto.TraceProxyService",
	HandlerType: (*TraceProxyServiceServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "Export",
			Handler:    _TraceProxyService_Export_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "api/proxyspan.proto",
}