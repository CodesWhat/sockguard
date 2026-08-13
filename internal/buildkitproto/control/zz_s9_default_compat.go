package control

import (
	pb "github.com/codeswhat/sockguard/internal/buildkitproto/pb"

	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"

	reflect "reflect"
	sourcepolicy "github.com/codeswhat/sockguard/internal/buildkitproto/sourcepolicy"

	sync "sync"
	timestamppb "google.golang.org/protobuf/types/known/timestamppb"

	unsafe "unsafe"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type SolveRequest struct {
	state      protoimpl.MessageState `protogen:"open.v1"`
	Ref        string                 `protobuf:"bytes,1,opt,name=Ref,proto3" json:"Ref,omitempty"`
	Definition *pb.Definition         `protobuf:"bytes,2,opt,name=Definition,proto3" json:"Definition,omitempty"`
	// ExporterDeprecated and ExporterAttrsDeprecated are deprecated in favor
	// of the new Exporters. If these fields are set, then they will be
	// appended to the Exporters field if Exporters was not explicitly set.
	ExporterDeprecated      string                    `protobuf:"bytes,3,opt,name=ExporterDeprecated,proto3" json:"ExporterDeprecated,omitempty"`
	ExporterAttrsDeprecated map[string]string         `protobuf:"bytes,4,rep,name=ExporterAttrsDeprecated,proto3" json:"ExporterAttrsDeprecated,omitempty" protobuf_key:"bytes,1,opt,name=key" protobuf_val:"bytes,2,opt,name=value"`
	Session                 string                    `protobuf:"bytes,5,opt,name=Session,proto3" json:"Session,omitempty"`
	Frontend                string                    `protobuf:"bytes,6,opt,name=Frontend,proto3" json:"Frontend,omitempty"`
	FrontendAttrs           map[string]string         `protobuf:"bytes,7,rep,name=FrontendAttrs,proto3" json:"FrontendAttrs,omitempty" protobuf_key:"bytes,1,opt,name=key" protobuf_val:"bytes,2,opt,name=value"`
	Cache                   *CacheOptions             `protobuf:"bytes,8,opt,name=Cache,proto3" json:"Cache,omitempty"`
	Entitlements            []string                  `protobuf:"bytes,9,rep,name=Entitlements,proto3" json:"Entitlements,omitempty"`
	FrontendInputs          map[string]*pb.Definition `protobuf:"bytes,10,rep,name=FrontendInputs,proto3" json:"FrontendInputs,omitempty" protobuf_key:"bytes,1,opt,name=key" protobuf_val:"bytes,2,opt,name=value"`
	Internal                bool                      `protobuf:"varint,11,opt,name=Internal,proto3" json:"Internal,omitempty"` // Internal builds are not recorded in build history
	SourcePolicy            *sourcepolicy.Policy      `protobuf:"bytes,12,opt,name=SourcePolicy,proto3" json:"SourcePolicy,omitempty"`
	Exporters               []*Exporter               `protobuf:"bytes,13,rep,name=Exporters,proto3" json:"Exporters,omitempty"`
	EnableSessionExporter   bool                      `protobuf:"varint,14,opt,name=EnableSessionExporter,proto3" json:"EnableSessionExporter,omitempty"`
	SourcePolicySession     string                    `protobuf:"bytes,15,opt,name=SourcePolicySession,proto3" json:"SourcePolicySession,omitempty"`
	CompatibilityVersion    int64                     `protobuf:"varint,16,opt,name=CompatibilityVersion,proto3" json:"CompatibilityVersion,omitempty"`
	ProxyNetwork            bool                      `protobuf:"varint,17,opt,name=ProxyNetwork,proto3" json:"ProxyNetwork,omitempty"`
	unknownFields           protoimpl.UnknownFields
	sizeCache               protoimpl.SizeCache
}

func (x *SolveRequest) Reset() {
	*x = SolveRequest{}
	mi := &file_github_com_moby_buildkit_api_services_control_control_proto_msgTypes[0]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *SolveRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*SolveRequest) ProtoMessage() {}

func (x *SolveRequest) ProtoReflect() protoreflect.Message {
	mi := &file_github_com_moby_buildkit_api_services_control_control_proto_msgTypes[0]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use SolveRequest.ProtoReflect.Descriptor instead.
func (*SolveRequest) Descriptor() ([]byte, []int) {
	return file_github_com_moby_buildkit_api_services_control_control_proto_rawDescGZIP(), []int{0}
}

func (x *SolveRequest) GetRef() string {
	if x != nil {
		return x.Ref
	}
	return ""
}

func (x *SolveRequest) GetDefinition() *pb.Definition {
	if x != nil {
		return x.Definition
	}
	return nil
}

func (x *SolveRequest) GetExporterDeprecated() string {
	if x != nil {
		return x.ExporterDeprecated
	}
	return ""
}

func (x *SolveRequest) GetExporterAttrsDeprecated() map[string]string {
	if x != nil {
		return x.ExporterAttrsDeprecated
	}
	return nil
}

func (x *SolveRequest) GetSession() string {
	if x != nil {
		return x.Session
	}
	return ""
}

func (x *SolveRequest) GetFrontend() string {
	if x != nil {
		return x.Frontend
	}
	return ""
}

func (x *SolveRequest) GetFrontendAttrs() map[string]string {
	if x != nil {
		return x.FrontendAttrs
	}
	return nil
}

func (x *SolveRequest) GetCache() *CacheOptions {
	if x != nil {
		return x.Cache
	}
	return nil
}

func (x *SolveRequest) GetEntitlements() []string {
	if x != nil {
		return x.Entitlements
	}
	return nil
}

func (x *SolveRequest) GetFrontendInputs() map[string]*pb.Definition {
	if x != nil {
		return x.FrontendInputs
	}
	return nil
}

func (x *SolveRequest) GetInternal() bool {
	if x != nil {
		return x.Internal
	}
	return false
}

func (x *SolveRequest) GetSourcePolicy() *sourcepolicy.Policy {
	if x != nil {
		return x.SourcePolicy
	}
	return nil
}

func (x *SolveRequest) GetExporters() []*Exporter {
	if x != nil {
		return x.Exporters
	}
	return nil
}

func (x *SolveRequest) GetEnableSessionExporter() bool {
	if x != nil {
		return x.EnableSessionExporter
	}
	return false
}

func (x *SolveRequest) GetSourcePolicySession() string {
	if x != nil {
		return x.SourcePolicySession
	}
	return ""
}

func (x *SolveRequest) GetCompatibilityVersion() int64 {
	if x != nil {
		return x.CompatibilityVersion
	}
	return 0
}

func (x *SolveRequest) GetProxyNetwork() bool {
	if x != nil {
		return x.ProxyNetwork
	}
	return false
}

type CacheOptions struct {
	state protoimpl.MessageState `protogen:"open.v1"`
	// ExportRefDeprecated is deprecated in favor or the new Exports since BuildKit v0.4.0.
	// When ExportRefDeprecated is set, the solver appends
	// {.Type = "registry", .Attrs = ExportAttrs.add("ref", ExportRef)}
	// to Exports for compatibility. (planned to be removed)
	ExportRefDeprecated string `protobuf:"bytes,1,opt,name=ExportRefDeprecated,proto3" json:"ExportRefDeprecated,omitempty"`
	// ImportRefsDeprecated is deprecated in favor or the new Imports since BuildKit v0.4.0.
	// When ImportRefsDeprecated is set, the solver appends
	// {.Type = "registry", .Attrs = {"ref": importRef}}
	// for each of the ImportRefs entry to Imports for compatibility. (planned to be removed)
	ImportRefsDeprecated []string `protobuf:"bytes,2,rep,name=ImportRefsDeprecated,proto3" json:"ImportRefsDeprecated,omitempty"`
	// ExportAttrsDeprecated is deprecated since BuildKit v0.4.0.
	// See the description of ExportRefDeprecated.
	ExportAttrsDeprecated map[string]string `protobuf:"bytes,3,rep,name=ExportAttrsDeprecated,proto3" json:"ExportAttrsDeprecated,omitempty" protobuf_key:"bytes,1,opt,name=key" protobuf_val:"bytes,2,opt,name=value"`
	// Exports was introduced in BuildKit v0.4.0.
	Exports []*CacheOptionsEntry `protobuf:"bytes,4,rep,name=Exports,proto3" json:"Exports,omitempty"`
	// Imports was introduced in BuildKit v0.4.0.
	Imports       []*CacheOptionsEntry `protobuf:"bytes,5,rep,name=Imports,proto3" json:"Imports,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *CacheOptions) Reset() {
	*x = CacheOptions{}
	mi := &file_github_com_moby_buildkit_api_services_control_control_proto_msgTypes[1]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *CacheOptions) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*CacheOptions) ProtoMessage() {}

func (x *CacheOptions) ProtoReflect() protoreflect.Message {
	mi := &file_github_com_moby_buildkit_api_services_control_control_proto_msgTypes[1]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use CacheOptions.ProtoReflect.Descriptor instead.
func (*CacheOptions) Descriptor() ([]byte, []int) {
	return file_github_com_moby_buildkit_api_services_control_control_proto_rawDescGZIP(), []int{1}
}

func (x *CacheOptions) GetExportRefDeprecated() string {
	if x != nil {
		return x.ExportRefDeprecated
	}
	return ""
}

func (x *CacheOptions) GetImportRefsDeprecated() []string {
	if x != nil {
		return x.ImportRefsDeprecated
	}
	return nil
}

func (x *CacheOptions) GetExportAttrsDeprecated() map[string]string {
	if x != nil {
		return x.ExportAttrsDeprecated
	}
	return nil
}

func (x *CacheOptions) GetExports() []*CacheOptionsEntry {
	if x != nil {
		return x.Exports
	}
	return nil
}

func (x *CacheOptions) GetImports() []*CacheOptionsEntry {
	if x != nil {
		return x.Imports
	}
	return nil
}

type CacheOptionsEntry struct {
	state protoimpl.MessageState `protogen:"open.v1"`
	// Type is like "registry" or "local"
	Type string `protobuf:"bytes,1,opt,name=Type,proto3" json:"Type,omitempty"`
	// Attrs are like mode=(min,max), ref=example.com:5000/foo/bar .
	// See cache importer/exporter implementations' documentation.
	Attrs         map[string]string `protobuf:"bytes,2,rep,name=Attrs,proto3" json:"Attrs,omitempty" protobuf_key:"bytes,1,opt,name=key" protobuf_val:"bytes,2,opt,name=value"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *CacheOptionsEntry) Reset() {
	*x = CacheOptionsEntry{}
	mi := &file_github_com_moby_buildkit_api_services_control_control_proto_msgTypes[2]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *CacheOptionsEntry) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*CacheOptionsEntry) ProtoMessage() {}

func (x *CacheOptionsEntry) ProtoReflect() protoreflect.Message {
	mi := &file_github_com_moby_buildkit_api_services_control_control_proto_msgTypes[2]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use CacheOptionsEntry.ProtoReflect.Descriptor instead.
func (*CacheOptionsEntry) Descriptor() ([]byte, []int) {
	return file_github_com_moby_buildkit_api_services_control_control_proto_rawDescGZIP(), []int{2}
}

func (x *CacheOptionsEntry) GetType() string {
	if x != nil {
		return x.Type
	}
	return ""
}

func (x *CacheOptionsEntry) GetAttrs() map[string]string {
	if x != nil {
		return x.Attrs
	}
	return nil
}

type SolveResponse struct {
	state            protoimpl.MessageState `protogen:"open.v1"`
	ExporterResponse map[string]string      `protobuf:"bytes,1,rep,name=ExporterResponse,proto3" json:"ExporterResponse,omitempty" protobuf_key:"bytes,1,opt,name=key" protobuf_val:"bytes,2,opt,name=value"`
	unknownFields    protoimpl.UnknownFields
	sizeCache        protoimpl.SizeCache
}

func (x *SolveResponse) Reset() {
	*x = SolveResponse{}
	mi := &file_github_com_moby_buildkit_api_services_control_control_proto_msgTypes[3]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *SolveResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*SolveResponse) ProtoMessage() {}

func (x *SolveResponse) ProtoReflect() protoreflect.Message {
	mi := &file_github_com_moby_buildkit_api_services_control_control_proto_msgTypes[3]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use SolveResponse.ProtoReflect.Descriptor instead.
func (*SolveResponse) Descriptor() ([]byte, []int) {
	return file_github_com_moby_buildkit_api_services_control_control_proto_rawDescGZIP(), []int{3}
}

func (x *SolveResponse) GetExporterResponse() map[string]string {
	if x != nil {
		return x.ExporterResponse
	}
	return nil
}

type StatusRequest struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	Ref           string                 `protobuf:"bytes,1,opt,name=Ref,proto3" json:"Ref,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *StatusRequest) Reset() {
	*x = StatusRequest{}
	mi := &file_github_com_moby_buildkit_api_services_control_control_proto_msgTypes[4]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *StatusRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*StatusRequest) ProtoMessage() {}

func (x *StatusRequest) ProtoReflect() protoreflect.Message {
	mi := &file_github_com_moby_buildkit_api_services_control_control_proto_msgTypes[4]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use StatusRequest.ProtoReflect.Descriptor instead.
func (*StatusRequest) Descriptor() ([]byte, []int) {
	return file_github_com_moby_buildkit_api_services_control_control_proto_rawDescGZIP(), []int{4}
}

func (x *StatusRequest) GetRef() string {
	if x != nil {
		return x.Ref
	}
	return ""
}

type StatusResponse struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	Vertexes      []*Vertex              `protobuf:"bytes,1,rep,name=vertexes,proto3" json:"vertexes,omitempty"`
	Statuses      []*VertexStatus        `protobuf:"bytes,2,rep,name=statuses,proto3" json:"statuses,omitempty"`
	Logs          []*VertexLog           `protobuf:"bytes,3,rep,name=logs,proto3" json:"logs,omitempty"`
	Warnings      []*VertexWarning       `protobuf:"bytes,4,rep,name=warnings,proto3" json:"warnings,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *StatusResponse) Reset() {
	*x = StatusResponse{}
	mi := &file_github_com_moby_buildkit_api_services_control_control_proto_msgTypes[5]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *StatusResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*StatusResponse) ProtoMessage() {}

func (x *StatusResponse) ProtoReflect() protoreflect.Message {
	mi := &file_github_com_moby_buildkit_api_services_control_control_proto_msgTypes[5]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use StatusResponse.ProtoReflect.Descriptor instead.
func (*StatusResponse) Descriptor() ([]byte, []int) {
	return file_github_com_moby_buildkit_api_services_control_control_proto_rawDescGZIP(), []int{5}
}

func (x *StatusResponse) GetVertexes() []*Vertex {
	if x != nil {
		return x.Vertexes
	}
	return nil
}

func (x *StatusResponse) GetStatuses() []*VertexStatus {
	if x != nil {
		return x.Statuses
	}
	return nil
}

func (x *StatusResponse) GetLogs() []*VertexLog {
	if x != nil {
		return x.Logs
	}
	return nil
}

func (x *StatusResponse) GetWarnings() []*VertexWarning {
	if x != nil {
		return x.Warnings
	}
	return nil
}

type Vertex struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	Digest        string                 `protobuf:"bytes,1,opt,name=digest,proto3" json:"digest,omitempty"`
	Inputs        []string               `protobuf:"bytes,2,rep,name=inputs,proto3" json:"inputs,omitempty"`
	Name          string                 `protobuf:"bytes,3,opt,name=name,proto3" json:"name,omitempty"`
	Cached        bool                   `protobuf:"varint,4,opt,name=cached,proto3" json:"cached,omitempty"`
	Started       *timestamppb.Timestamp `protobuf:"bytes,5,opt,name=started,proto3" json:"started,omitempty"`
	Completed     *timestamppb.Timestamp `protobuf:"bytes,6,opt,name=completed,proto3" json:"completed,omitempty"`
	Error         string                 `protobuf:"bytes,7,opt,name=error,proto3" json:"error,omitempty"` // typed errors?
	ProgressGroup *pb.ProgressGroup      `protobuf:"bytes,8,opt,name=progressGroup,proto3" json:"progressGroup,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *Vertex) Reset() {
	*x = Vertex{}
	mi := &file_github_com_moby_buildkit_api_services_control_control_proto_msgTypes[6]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *Vertex) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Vertex) ProtoMessage() {}

func (x *Vertex) ProtoReflect() protoreflect.Message {
	mi := &file_github_com_moby_buildkit_api_services_control_control_proto_msgTypes[6]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Vertex.ProtoReflect.Descriptor instead.
func (*Vertex) Descriptor() ([]byte, []int) {
	return file_github_com_moby_buildkit_api_services_control_control_proto_rawDescGZIP(), []int{6}
}

func (x *Vertex) GetDigest() string {
	if x != nil {
		return x.Digest
	}
	return ""
}

func (x *Vertex) GetInputs() []string {
	if x != nil {
		return x.Inputs
	}
	return nil
}

func (x *Vertex) GetName() string {
	if x != nil {
		return x.Name
	}
	return ""
}

func (x *Vertex) GetCached() bool {
	if x != nil {
		return x.Cached
	}
	return false
}

func (x *Vertex) GetStarted() *timestamppb.Timestamp {
	if x != nil {
		return x.Started
	}
	return nil
}

func (x *Vertex) GetCompleted() *timestamppb.Timestamp {
	if x != nil {
		return x.Completed
	}
	return nil
}

func (x *Vertex) GetError() string {
	if x != nil {
		return x.Error
	}
	return ""
}

func (x *Vertex) GetProgressGroup() *pb.ProgressGroup {
	if x != nil {
		return x.ProgressGroup
	}
	return nil
}

type VertexStatus struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	ID            string                 `protobuf:"bytes,1,opt,name=ID,proto3" json:"ID,omitempty"`
	Vertex        string                 `protobuf:"bytes,2,opt,name=vertex,proto3" json:"vertex,omitempty"`
	Name          string                 `protobuf:"bytes,3,opt,name=name,proto3" json:"name,omitempty"`
	Current       int64                  `protobuf:"varint,4,opt,name=current,proto3" json:"current,omitempty"`
	Total         int64                  `protobuf:"varint,5,opt,name=total,proto3" json:"total,omitempty"`
	Timestamp     *timestamppb.Timestamp `protobuf:"bytes,6,opt,name=timestamp,proto3" json:"timestamp,omitempty"`
	Started       *timestamppb.Timestamp `protobuf:"bytes,7,opt,name=started,proto3" json:"started,omitempty"`
	Completed     *timestamppb.Timestamp `protobuf:"bytes,8,opt,name=completed,proto3" json:"completed,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *VertexStatus) Reset() {
	*x = VertexStatus{}
	mi := &file_github_com_moby_buildkit_api_services_control_control_proto_msgTypes[7]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *VertexStatus) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*VertexStatus) ProtoMessage() {}

func (x *VertexStatus) ProtoReflect() protoreflect.Message {
	mi := &file_github_com_moby_buildkit_api_services_control_control_proto_msgTypes[7]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use VertexStatus.ProtoReflect.Descriptor instead.
func (*VertexStatus) Descriptor() ([]byte, []int) {
	return file_github_com_moby_buildkit_api_services_control_control_proto_rawDescGZIP(), []int{7}
}

func (x *VertexStatus) GetID() string {
	if x != nil {
		return x.ID
	}
	return ""
}

func (x *VertexStatus) GetVertex() string {
	if x != nil {
		return x.Vertex
	}
	return ""
}

func (x *VertexStatus) GetName() string {
	if x != nil {
		return x.Name
	}
	return ""
}

func (x *VertexStatus) GetCurrent() int64 {
	if x != nil {
		return x.Current
	}
	return 0
}

func (x *VertexStatus) GetTotal() int64 {
	if x != nil {
		return x.Total
	}
	return 0
}

func (x *VertexStatus) GetTimestamp() *timestamppb.Timestamp {
	if x != nil {
		return x.Timestamp
	}
	return nil
}

func (x *VertexStatus) GetStarted() *timestamppb.Timestamp {
	if x != nil {
		return x.Started
	}
	return nil
}

func (x *VertexStatus) GetCompleted() *timestamppb.Timestamp {
	if x != nil {
		return x.Completed
	}
	return nil
}

type VertexLog struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	Vertex        string                 `protobuf:"bytes,1,opt,name=vertex,proto3" json:"vertex,omitempty"`
	Timestamp     *timestamppb.Timestamp `protobuf:"bytes,2,opt,name=timestamp,proto3" json:"timestamp,omitempty"`
	Stream        int64                  `protobuf:"varint,3,opt,name=stream,proto3" json:"stream,omitempty"`
	Msg           []byte                 `protobuf:"bytes,4,opt,name=msg,proto3" json:"msg,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *VertexLog) Reset() {
	*x = VertexLog{}
	mi := &file_github_com_moby_buildkit_api_services_control_control_proto_msgTypes[8]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *VertexLog) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*VertexLog) ProtoMessage() {}

func (x *VertexLog) ProtoReflect() protoreflect.Message {
	mi := &file_github_com_moby_buildkit_api_services_control_control_proto_msgTypes[8]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use VertexLog.ProtoReflect.Descriptor instead.
func (*VertexLog) Descriptor() ([]byte, []int) {
	return file_github_com_moby_buildkit_api_services_control_control_proto_rawDescGZIP(), []int{8}
}

func (x *VertexLog) GetVertex() string {
	if x != nil {
		return x.Vertex
	}
	return ""
}

func (x *VertexLog) GetTimestamp() *timestamppb.Timestamp {
	if x != nil {
		return x.Timestamp
	}
	return nil
}

func (x *VertexLog) GetStream() int64 {
	if x != nil {
		return x.Stream
	}
	return 0
}

func (x *VertexLog) GetMsg() []byte {
	if x != nil {
		return x.Msg
	}
	return nil
}

type VertexWarning struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	Vertex        string                 `protobuf:"bytes,1,opt,name=vertex,proto3" json:"vertex,omitempty"`
	Level         int64                  `protobuf:"varint,2,opt,name=level,proto3" json:"level,omitempty"`
	Short         []byte                 `protobuf:"bytes,3,opt,name=short,proto3" json:"short,omitempty"`
	Detail        [][]byte               `protobuf:"bytes,4,rep,name=detail,proto3" json:"detail,omitempty"`
	Url           string                 `protobuf:"bytes,5,opt,name=url,proto3" json:"url,omitempty"`
	Info          *pb.SourceInfo         `protobuf:"bytes,6,opt,name=info,proto3" json:"info,omitempty"`
	Ranges        []*pb.Range            `protobuf:"bytes,7,rep,name=ranges,proto3" json:"ranges,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *VertexWarning) Reset() {
	*x = VertexWarning{}
	mi := &file_github_com_moby_buildkit_api_services_control_control_proto_msgTypes[9]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *VertexWarning) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*VertexWarning) ProtoMessage() {}

func (x *VertexWarning) ProtoReflect() protoreflect.Message {
	mi := &file_github_com_moby_buildkit_api_services_control_control_proto_msgTypes[9]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use VertexWarning.ProtoReflect.Descriptor instead.
func (*VertexWarning) Descriptor() ([]byte, []int) {
	return file_github_com_moby_buildkit_api_services_control_control_proto_rawDescGZIP(), []int{9}
}

func (x *VertexWarning) GetVertex() string {
	if x != nil {
		return x.Vertex
	}
	return ""
}

func (x *VertexWarning) GetLevel() int64 {
	if x != nil {
		return x.Level
	}
	return 0
}

func (x *VertexWarning) GetShort() []byte {
	if x != nil {
		return x.Short
	}
	return nil
}

func (x *VertexWarning) GetDetail() [][]byte {
	if x != nil {
		return x.Detail
	}
	return nil
}

func (x *VertexWarning) GetUrl() string {
	if x != nil {
		return x.Url
	}
	return ""
}

func (x *VertexWarning) GetInfo() *pb.SourceInfo {
	if x != nil {
		return x.Info
	}
	return nil
}

func (x *VertexWarning) GetRanges() []*pb.Range {
	if x != nil {
		return x.Ranges
	}
	return nil
}

// Exporter describes the output exporter
type Exporter struct {
	state protoimpl.MessageState `protogen:"open.v1"`
	// Type identifies the exporter
	Type string `protobuf:"bytes,1,opt,name=Type,proto3" json:"Type,omitempty"`
	// Attrs specifies exporter configuration
	Attrs         map[string]string `protobuf:"bytes,2,rep,name=Attrs,proto3" json:"Attrs,omitempty" protobuf_key:"bytes,1,opt,name=key" protobuf_val:"bytes,2,opt,name=value"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *Exporter) Reset() {
	*x = Exporter{}
	mi := &file_github_com_moby_buildkit_api_services_control_control_proto_msgTypes[10]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *Exporter) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Exporter) ProtoMessage() {}

func (x *Exporter) ProtoReflect() protoreflect.Message {
	mi := &file_github_com_moby_buildkit_api_services_control_control_proto_msgTypes[10]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Exporter.ProtoReflect.Descriptor instead.
func (*Exporter) Descriptor() ([]byte, []int) {
	return file_github_com_moby_buildkit_api_services_control_control_proto_rawDescGZIP(), []int{10}
}

func (x *Exporter) GetType() string {
	if x != nil {
		return x.Type
	}
	return ""
}

func (x *Exporter) GetAttrs() map[string]string {
	if x != nil {
		return x.Attrs
	}
	return nil
}

var File_github_com_moby_buildkit_api_services_control_control_proto protoreflect.FileDescriptor

const file_github_com_moby_buildkit_api_services_control_control_proto_rawDesc = "" +
	"\n" +
	";github.com/moby/buildkit/api/services/control/control.proto\x12\x10moby.buildkit.v1\x1a,github.com/moby/buildkit/solver/pb/ops.proto\x1a5github.com/moby/buildkit/sourcepolicy/pb/policy.proto\x1a\x1fgoogle/protobuf/timestamp.proto\"\xfe\b\n" +
	"\fSolveRequest\x12\x10\n" +
	"\x03Ref\x18\x01 \x01(\tR\x03Ref\x12.\n" +
	"\n" +
	"Definition\x18\x02 \x01(\v2\x0e.pb.DefinitionR\n" +
	"Definition\x12.\n" +
	"\x12ExporterDeprecated\x18\x03 \x01(\tR\x12ExporterDeprecated\x12u\n" +
	"\x17ExporterAttrsDeprecated\x18\x04 \x03(\v2;.moby.buildkit.v1.SolveRequest.ExporterAttrsDeprecatedEntryR\x17ExporterAttrsDeprecated\x12\x18\n" +
	"\aSession\x18\x05 \x01(\tR\aSession\x12\x1a\n" +
	"\bFrontend\x18\x06 \x01(\tR\bFrontend\x12W\n" +
	"\rFrontendAttrs\x18\a \x03(\v21.moby.buildkit.v1.SolveRequest.FrontendAttrsEntryR\rFrontendAttrs\x124\n" +
	"\x05Cache\x18\b \x01(\v2\x1e.moby.buildkit.v1.CacheOptionsR\x05Cache\x12\"\n" +
	"\fEntitlements\x18\t \x03(\tR\fEntitlements\x12Z\n" +
	"\x0eFrontendInputs\x18\n" +
	" \x03(\v22.moby.buildkit.v1.SolveRequest.FrontendInputsEntryR\x0eFrontendInputs\x12\x1a\n" +
	"\bInternal\x18\v \x01(\bR\bInternal\x12I\n" +
	"\fSourcePolicy\x18\f \x01(\v2%.moby.buildkit.v1.sourcepolicy.PolicyR\fSourcePolicy\x128\n" +
	"\tExporters\x18\r \x03(\v2\x1a.moby.buildkit.v1.ExporterR\tExporters\x124\n" +
	"\x15EnableSessionExporter\x18\x0e \x01(\bR\x15EnableSessionExporter\x120\n" +
	"\x13SourcePolicySession\x18\x0f \x01(\tR\x13SourcePolicySession\x122\n" +
	"\x14CompatibilityVersion\x18\x10 \x01(\x03R\x14CompatibilityVersion\x12\"\n" +
	"\fProxyNetwork\x18\x11 \x01(\bR\fProxyNetwork\x1aJ\n" +
	"\x1cExporterAttrsDeprecatedEntry\x12\x10\n" +
	"\x03key\x18\x01 \x01(\tR\x03key\x12\x14\n" +
	"\x05value\x18\x02 \x01(\tR\x05value:\x028\x01\x1a@\n" +
	"\x12FrontendAttrsEntry\x12\x10\n" +
	"\x03key\x18\x01 \x01(\tR\x03key\x12\x14\n" +
	"\x05value\x18\x02 \x01(\tR\x05value:\x028\x01\x1aQ\n" +
	"\x13FrontendInputsEntry\x12\x10\n" +
	"\x03key\x18\x01 \x01(\tR\x03key\x12$\n" +
	"\x05value\x18\x02 \x01(\v2\x0e.pb.DefinitionR\x05value:\x028\x01\"\xad\x03\n" +
	"\fCacheOptions\x120\n" +
	"\x13ExportRefDeprecated\x18\x01 \x01(\tR\x13ExportRefDeprecated\x122\n" +
	"\x14ImportRefsDeprecated\x18\x02 \x03(\tR\x14ImportRefsDeprecated\x12o\n" +
	"\x15ExportAttrsDeprecated\x18\x03 \x03(\v29.moby.buildkit.v1.CacheOptions.ExportAttrsDeprecatedEntryR\x15ExportAttrsDeprecated\x12=\n" +
	"\aExports\x18\x04 \x03(\v2#.moby.buildkit.v1.CacheOptionsEntryR\aExports\x12=\n" +
	"\aImports\x18\x05 \x03(\v2#.moby.buildkit.v1.CacheOptionsEntryR\aImports\x1aH\n" +
	"\x1aExportAttrsDeprecatedEntry\x12\x10\n" +
	"\x03key\x18\x01 \x01(\tR\x03key\x12\x14\n" +
	"\x05value\x18\x02 \x01(\tR\x05value:\x028\x01\"\xa7\x01\n" +
	"\x11CacheOptionsEntry\x12\x12\n" +
	"\x04Type\x18\x01 \x01(\tR\x04Type\x12D\n" +
	"\x05Attrs\x18\x02 \x03(\v2..moby.buildkit.v1.CacheOptionsEntry.AttrsEntryR\x05Attrs\x1a8\n" +
	"\n" +
	"AttrsEntry\x12\x10\n" +
	"\x03key\x18\x01 \x01(\tR\x03key\x12\x14\n" +
	"\x05value\x18\x02 \x01(\tR\x05value:\x028\x01\"\xb7\x01\n" +
	"\rSolveResponse\x12a\n" +
	"\x10ExporterResponse\x18\x01 \x03(\v25.moby.buildkit.v1.SolveResponse.ExporterResponseEntryR\x10ExporterResponse\x1aC\n" +
	"\x15ExporterResponseEntry\x12\x10\n" +
	"\x03key\x18\x01 \x01(\tR\x03key\x12\x14\n" +
	"\x05value\x18\x02 \x01(\tR\x05value:\x028\x01\"!\n" +
	"\rStatusRequest\x12\x10\n" +
	"\x03Ref\x18\x01 \x01(\tR\x03Ref\"\xf0\x01\n" +
	"\x0eStatusResponse\x124\n" +
	"\bvertexes\x18\x01 \x03(\v2\x18.moby.buildkit.v1.VertexR\bvertexes\x12:\n" +
	"\bstatuses\x18\x02 \x03(\v2\x1e.moby.buildkit.v1.VertexStatusR\bstatuses\x12/\n" +
	"\x04logs\x18\x03 \x03(\v2\x1b.moby.buildkit.v1.VertexLogR\x04logs\x12;\n" +
	"\bwarnings\x18\x04 \x03(\v2\x1f.moby.buildkit.v1.VertexWarningR\bwarnings\"\xa3\x02\n" +
	"\x06Vertex\x12\x16\n" +
	"\x06digest\x18\x01 \x01(\tR\x06digest\x12\x16\n" +
	"\x06inputs\x18\x02 \x03(\tR\x06inputs\x12\x12\n" +
	"\x04name\x18\x03 \x01(\tR\x04name\x12\x16\n" +
	"\x06cached\x18\x04 \x01(\bR\x06cached\x124\n" +
	"\astarted\x18\x05 \x01(\v2\x1a.google.protobuf.TimestampR\astarted\x128\n" +
	"\tcompleted\x18\x06 \x01(\v2\x1a.google.protobuf.TimestampR\tcompleted\x12\x14\n" +
	"\x05error\x18\a \x01(\tR\x05error\x127\n" +
	"\rprogressGroup\x18\b \x01(\v2\x11.pb.ProgressGroupR\rprogressGroup\"\xa4\x02\n" +
	"\fVertexStatus\x12\x0e\n" +
	"\x02ID\x18\x01 \x01(\tR\x02ID\x12\x16\n" +
	"\x06vertex\x18\x02 \x01(\tR\x06vertex\x12\x12\n" +
	"\x04name\x18\x03 \x01(\tR\x04name\x12\x18\n" +
	"\acurrent\x18\x04 \x01(\x03R\acurrent\x12\x14\n" +
	"\x05total\x18\x05 \x01(\x03R\x05total\x128\n" +
	"\ttimestamp\x18\x06 \x01(\v2\x1a.google.protobuf.TimestampR\ttimestamp\x124\n" +
	"\astarted\x18\a \x01(\v2\x1a.google.protobuf.TimestampR\astarted\x128\n" +
	"\tcompleted\x18\b \x01(\v2\x1a.google.protobuf.TimestampR\tcompleted\"\x87\x01\n" +
	"\tVertexLog\x12\x16\n" +
	"\x06vertex\x18\x01 \x01(\tR\x06vertex\x128\n" +
	"\ttimestamp\x18\x02 \x01(\v2\x1a.google.protobuf.TimestampR\ttimestamp\x12\x16\n" +
	"\x06stream\x18\x03 \x01(\x03R\x06stream\x12\x10\n" +
	"\x03msg\x18\x04 \x01(\fR\x03msg\"\xc4\x01\n" +
	"\rVertexWarning\x12\x16\n" +
	"\x06vertex\x18\x01 \x01(\tR\x06vertex\x12\x14\n" +
	"\x05level\x18\x02 \x01(\x03R\x05level\x12\x14\n" +
	"\x05short\x18\x03 \x01(\fR\x05short\x12\x16\n" +
	"\x06detail\x18\x04 \x03(\fR\x06detail\x12\x10\n" +
	"\x03url\x18\x05 \x01(\tR\x03url\x12\"\n" +
	"\x04info\x18\x06 \x01(\v2\x0e.pb.SourceInfoR\x04info\x12!\n" +
	"\x06ranges\x18\a \x03(\v2\t.pb.RangeR\x06ranges\"\x95\x01\n" +
	"\bExporter\x12\x12\n" +
	"\x04Type\x18\x01 \x01(\tR\x04Type\x12;\n" +
	"\x05Attrs\x18\x02 \x03(\v2%.moby.buildkit.v1.Exporter.AttrsEntryR\x05Attrs\x1a8\n" +
	"\n" +
	"AttrsEntry\x12\x10\n" +
	"\x03key\x18\x01 \x01(\tR\x03key\x12\x14\n" +
	"\x05value\x18\x02 \x01(\tR\x05value:\x028\x012\xa2\x01\n" +
	"\aControl\x12H\n" +
	"\x05Solve\x12\x1e.moby.buildkit.v1.SolveRequest\x1a\x1f.moby.buildkit.v1.SolveResponse\x12M\n" +
	"\x06Status\x12\x1f.moby.buildkit.v1.StatusRequest\x1a .moby.buildkit.v1.StatusResponse0\x01BGZEgithub.com/codeswhat/sockguard/internal/buildkitproto/control;controlb\x06proto3"

var (
	file_github_com_moby_buildkit_api_services_control_control_proto_rawDescOnce sync.Once
	file_github_com_moby_buildkit_api_services_control_control_proto_rawDescData []byte
)

func file_github_com_moby_buildkit_api_services_control_control_proto_rawDescGZIP() []byte {
	file_github_com_moby_buildkit_api_services_control_control_proto_rawDescOnce.Do(func() {
		file_github_com_moby_buildkit_api_services_control_control_proto_rawDescData = protoimpl.X.CompressGZIP(unsafe.Slice(unsafe.StringData(file_github_com_moby_buildkit_api_services_control_control_proto_rawDesc), len(file_github_com_moby_buildkit_api_services_control_control_proto_rawDesc)))
	})
	return file_github_com_moby_buildkit_api_services_control_control_proto_rawDescData
}

var file_github_com_moby_buildkit_api_services_control_control_proto_msgTypes = make([]protoimpl.MessageInfo, 18)
var file_github_com_moby_buildkit_api_services_control_control_proto_goTypes = []any{
	(*SolveRequest)(nil),
	(*CacheOptions)(nil),
	(*CacheOptionsEntry)(nil),
	(*SolveResponse)(nil),
	(*StatusRequest)(nil),
	(*StatusResponse)(nil),
	(*Vertex)(nil),
	(*VertexStatus)(nil),
	(*VertexLog)(nil),
	(*VertexWarning)(nil),
	(*Exporter)(nil),
	nil,
	nil,
	nil,
	nil,
	nil,
	nil,
	nil,
	(*pb.Definition)(nil),
	(*sourcepolicy.Policy)(nil),
	(*timestamppb.Timestamp)(nil),
	(*pb.ProgressGroup)(nil),
	(*pb.SourceInfo)(nil),
	(*pb.Range)(nil),
}
var file_github_com_moby_buildkit_api_services_control_control_proto_depIdxs = []int32{
	18,
	11,
	12,
	1,
	13,
	19,
	10,
	14,
	2,
	2,
	15,
	16,
	6,
	7,
	8,
	9,
	20,
	20,
	21,
	20,
	20,
	20,
	20,
	22,
	23,
	17,
	18,
	0,
	4,
	3,
	5,
	29,
	27,
	27,
	27,
	0,
}

func init() { file_github_com_moby_buildkit_api_services_control_control_proto_init() }
func file_github_com_moby_buildkit_api_services_control_control_proto_init() {
	if File_github_com_moby_buildkit_api_services_control_control_proto != nil {
		return
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: unsafe.Slice(unsafe.StringData(file_github_com_moby_buildkit_api_services_control_control_proto_rawDesc), len(file_github_com_moby_buildkit_api_services_control_control_proto_rawDesc)),
			NumEnums:      0,
			NumMessages:   18,
			NumExtensions: 0,
			NumServices:   1,
		},
		GoTypes:           file_github_com_moby_buildkit_api_services_control_control_proto_goTypes,
		DependencyIndexes: file_github_com_moby_buildkit_api_services_control_control_proto_depIdxs,
		MessageInfos:      file_github_com_moby_buildkit_api_services_control_control_proto_msgTypes,
	}.Build()
	File_github_com_moby_buildkit_api_services_control_control_proto = out.File
	file_github_com_moby_buildkit_api_services_control_control_proto_goTypes = nil
	file_github_com_moby_buildkit_api_services_control_control_proto_depIdxs = nil
}
