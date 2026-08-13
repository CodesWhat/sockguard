package fsutiltypes

import (
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"

	reflect "reflect"
	sync "sync"
	unsafe "unsafe"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type Stat struct {
	state   protoimpl.MessageState `protogen:"open.v1"`
	Path    string                 `protobuf:"bytes,1,opt,name=path,proto3" json:"path,omitempty"`
	Mode    uint32                 `protobuf:"varint,2,opt,name=mode,proto3" json:"mode,omitempty"`
	Uid     uint32                 `protobuf:"varint,3,opt,name=uid,proto3" json:"uid,omitempty"`
	Gid     uint32                 `protobuf:"varint,4,opt,name=gid,proto3" json:"gid,omitempty"`
	Size    int64                  `protobuf:"varint,5,opt,name=size,proto3" json:"size,omitempty"`
	ModTime int64                  `protobuf:"varint,6,opt,name=modTime,proto3" json:"modTime,omitempty"`
	// int32 typeflag = 7;
	Linkname      string            `protobuf:"bytes,7,opt,name=linkname,proto3" json:"linkname,omitempty"`
	Devmajor      int64             `protobuf:"varint,8,opt,name=devmajor,proto3" json:"devmajor,omitempty"`
	Devminor      int64             `protobuf:"varint,9,opt,name=devminor,proto3" json:"devminor,omitempty"`
	Xattrs        map[string][]byte `protobuf:"bytes,10,rep,name=xattrs,proto3" json:"xattrs,omitempty" protobuf_key:"bytes,1,opt,name=key" protobuf_val:"bytes,2,opt,name=value"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *Stat) Reset() {
	*x = Stat{}
	mi := &file_github_com_tonistiigi_fsutil_types_stat_proto_msgTypes[0]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *Stat) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Stat) ProtoMessage() {}

func (x *Stat) ProtoReflect() protoreflect.Message {
	mi := &file_github_com_tonistiigi_fsutil_types_stat_proto_msgTypes[0]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Stat.ProtoReflect.Descriptor instead.
func (*Stat) Descriptor() ([]byte, []int) {
	return file_github_com_tonistiigi_fsutil_types_stat_proto_rawDescGZIP(), []int{0}
}

func (x *Stat) GetPath() string {
	if x != nil {
		return x.Path
	}
	return ""
}

func (x *Stat) GetMode() uint32 {
	if x != nil {
		return x.Mode
	}
	return 0
}

func (x *Stat) GetUid() uint32 {
	if x != nil {
		return x.Uid
	}
	return 0
}

func (x *Stat) GetGid() uint32 {
	if x != nil {
		return x.Gid
	}
	return 0
}

func (x *Stat) GetSize() int64 {
	if x != nil {
		return x.Size
	}
	return 0
}

func (x *Stat) GetModTime() int64 {
	if x != nil {
		return x.ModTime
	}
	return 0
}

func (x *Stat) GetLinkname() string {
	if x != nil {
		return x.Linkname
	}
	return ""
}

func (x *Stat) GetDevmajor() int64 {
	if x != nil {
		return x.Devmajor
	}
	return 0
}

func (x *Stat) GetDevminor() int64 {
	if x != nil {
		return x.Devminor
	}
	return 0
}

func (x *Stat) GetXattrs() map[string][]byte {
	if x != nil {
		return x.Xattrs
	}
	return nil
}

var File_github_com_tonistiigi_fsutil_types_stat_proto protoreflect.FileDescriptor

const file_github_com_tonistiigi_fsutil_types_stat_proto_rawDesc = "" +
	"\n" +
	"-github.com/tonistiigi/fsutil/types/stat.proto\x12\ffsutil.types\"\xc7\x02\n" +
	"\x04Stat\x12\x12\n" +
	"\x04path\x18\x01 \x01(\tR\x04path\x12\x12\n" +
	"\x04mode\x18\x02 \x01(\rR\x04mode\x12\x10\n" +
	"\x03uid\x18\x03 \x01(\rR\x03uid\x12\x10\n" +
	"\x03gid\x18\x04 \x01(\rR\x03gid\x12\x12\n" +
	"\x04size\x18\x05 \x01(\x03R\x04size\x12\x18\n" +
	"\amodTime\x18\x06 \x01(\x03R\amodTime\x12\x1a\n" +
	"\blinkname\x18\a \x01(\tR\blinkname\x12\x1a\n" +
	"\bdevmajor\x18\b \x01(\x03R\bdevmajor\x12\x1a\n" +
	"\bdevminor\x18\t \x01(\x03R\bdevminor\x126\n" +
	"\x06xattrs\x18\n" +
	" \x03(\v2\x1e.fsutil.types.Stat.XattrsEntryR\x06xattrs\x1a9\n" +
	"\vXattrsEntry\x12\x10\n" +
	"\x03key\x18\x01 \x01(\tR\x03key\x12\x14\n" +
	"\x05value\x18\x02 \x01(\fR\x05value:\x028\x01BOZMgithub.com/codeswhat/sockguard/internal/buildkitproto/fsutiltypes;fsutiltypesb\x06proto3"

var (
	file_github_com_tonistiigi_fsutil_types_stat_proto_rawDescOnce sync.Once
	file_github_com_tonistiigi_fsutil_types_stat_proto_rawDescData []byte
)

func file_github_com_tonistiigi_fsutil_types_stat_proto_rawDescGZIP() []byte {
	file_github_com_tonistiigi_fsutil_types_stat_proto_rawDescOnce.Do(func() {
		file_github_com_tonistiigi_fsutil_types_stat_proto_rawDescData = protoimpl.X.CompressGZIP(unsafe.Slice(unsafe.StringData(file_github_com_tonistiigi_fsutil_types_stat_proto_rawDesc), len(file_github_com_tonistiigi_fsutil_types_stat_proto_rawDesc)))
	})
	return file_github_com_tonistiigi_fsutil_types_stat_proto_rawDescData
}

var file_github_com_tonistiigi_fsutil_types_stat_proto_msgTypes = make([]protoimpl.MessageInfo, 2)
var file_github_com_tonistiigi_fsutil_types_stat_proto_goTypes = []any{
	(*Stat)(nil),
	nil,
}
var file_github_com_tonistiigi_fsutil_types_stat_proto_depIdxs = []int32{
	1,
	1,
	1,
	1,
	1,
	0,
}

func init() { file_github_com_tonistiigi_fsutil_types_stat_proto_init() }
func file_github_com_tonistiigi_fsutil_types_stat_proto_init() {
	if File_github_com_tonistiigi_fsutil_types_stat_proto != nil {
		return
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: unsafe.Slice(unsafe.StringData(file_github_com_tonistiigi_fsutil_types_stat_proto_rawDesc), len(file_github_com_tonistiigi_fsutil_types_stat_proto_rawDesc)),
			NumEnums:      0,
			NumMessages:   2,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_github_com_tonistiigi_fsutil_types_stat_proto_goTypes,
		DependencyIndexes: file_github_com_tonistiigi_fsutil_types_stat_proto_depIdxs,
		MessageInfos:      file_github_com_tonistiigi_fsutil_types_stat_proto_msgTypes,
	}.Build()
	File_github_com_tonistiigi_fsutil_types_stat_proto = out.File
	file_github_com_tonistiigi_fsutil_types_stat_proto_goTypes = nil
	file_github_com_tonistiigi_fsutil_types_stat_proto_depIdxs = nil
}

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type Packet_PacketType int32

const (
	Packet_PACKET_STAT Packet_PacketType = 0
	Packet_PACKET_REQ  Packet_PacketType = 1
	Packet_PACKET_DATA Packet_PacketType = 2
	Packet_PACKET_FIN  Packet_PacketType = 3
	Packet_PACKET_ERR  Packet_PacketType = 4
)

// Enum value maps for Packet_PacketType.
var (
	Packet_PacketType_name = map[int32]string{
		0: "PACKET_STAT",
		1: "PACKET_REQ",
		2: "PACKET_DATA",
		3: "PACKET_FIN",
		4: "PACKET_ERR",
	}
	Packet_PacketType_value = map[string]int32{
		"PACKET_STAT": 0,
		"PACKET_REQ":  1,
		"PACKET_DATA": 2,
		"PACKET_FIN":  3,
		"PACKET_ERR":  4,
	}
)

func (x Packet_PacketType) Enum() *Packet_PacketType {
	p := new(Packet_PacketType)
	*p = x
	return p
}

func (x Packet_PacketType) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (Packet_PacketType) Descriptor() protoreflect.EnumDescriptor {
	return file_github_com_tonistiigi_fsutil_types_wire_proto_enumTypes[0].Descriptor()
}

func (Packet_PacketType) Type() protoreflect.EnumType {
	return &file_github_com_tonistiigi_fsutil_types_wire_proto_enumTypes[0]
}

func (x Packet_PacketType) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use Packet_PacketType.Descriptor instead.
func (Packet_PacketType) EnumDescriptor() ([]byte, []int) {
	return file_github_com_tonistiigi_fsutil_types_wire_proto_rawDescGZIP(), []int{0, 0}
}

type Packet struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	Type          Packet_PacketType      `protobuf:"varint,1,opt,name=type,proto3,enum=fsutil.types.Packet_PacketType" json:"type,omitempty"`
	Stat          *Stat                  `protobuf:"bytes,2,opt,name=stat,proto3" json:"stat,omitempty"`
	ID            uint32                 `protobuf:"varint,3,opt,name=ID,proto3" json:"ID,omitempty"`
	Data          []byte                 `protobuf:"bytes,4,opt,name=data,proto3" json:"data,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *Packet) Reset() {
	*x = Packet{}
	mi := &file_github_com_tonistiigi_fsutil_types_wire_proto_msgTypes[0]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *Packet) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Packet) ProtoMessage() {}

func (x *Packet) ProtoReflect() protoreflect.Message {
	mi := &file_github_com_tonistiigi_fsutil_types_wire_proto_msgTypes[0]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Packet.ProtoReflect.Descriptor instead.
func (*Packet) Descriptor() ([]byte, []int) {
	return file_github_com_tonistiigi_fsutil_types_wire_proto_rawDescGZIP(), []int{0}
}

func (x *Packet) GetType() Packet_PacketType {
	if x != nil {
		return x.Type
	}
	return Packet_PACKET_STAT
}

func (x *Packet) GetStat() *Stat {
	if x != nil {
		return x.Stat
	}
	return nil
}

func (x *Packet) GetID() uint32 {
	if x != nil {
		return x.ID
	}
	return 0
}

func (x *Packet) GetData() []byte {
	if x != nil {
		return x.Data
	}
	return nil
}

var File_github_com_tonistiigi_fsutil_types_wire_proto protoreflect.FileDescriptor

const file_github_com_tonistiigi_fsutil_types_wire_proto_rawDesc = "" +
	"\n" +
	"-github.com/tonistiigi/fsutil/types/wire.proto\x12\ffsutil.types\x1a-github.com/tonistiigi/fsutil/types/stat.proto\"\xe9\x01\n" +
	"\x06Packet\x123\n" +
	"\x04type\x18\x01 \x01(\x0e2\x1f.fsutil.types.Packet.PacketTypeR\x04type\x12&\n" +
	"\x04stat\x18\x02 \x01(\v2\x12.fsutil.types.StatR\x04stat\x12\x0e\n" +
	"\x02ID\x18\x03 \x01(\rR\x02ID\x12\x12\n" +
	"\x04data\x18\x04 \x01(\fR\x04data\"^\n" +
	"\n" +
	"PacketType\x12\x0f\n" +
	"\vPACKET_STAT\x10\x00\x12\x0e\n" +
	"\n" +
	"PACKET_REQ\x10\x01\x12\x0f\n" +
	"\vPACKET_DATA\x10\x02\x12\x0e\n" +
	"\n" +
	"PACKET_FIN\x10\x03\x12\x0e\n" +
	"\n" +
	"PACKET_ERR\x10\x04BOZMgithub.com/codeswhat/sockguard/internal/buildkitproto/fsutiltypes;fsutiltypesb\x06proto3"

var (
	file_github_com_tonistiigi_fsutil_types_wire_proto_rawDescOnce sync.Once
	file_github_com_tonistiigi_fsutil_types_wire_proto_rawDescData []byte
)

func file_github_com_tonistiigi_fsutil_types_wire_proto_rawDescGZIP() []byte {
	file_github_com_tonistiigi_fsutil_types_wire_proto_rawDescOnce.Do(func() {
		file_github_com_tonistiigi_fsutil_types_wire_proto_rawDescData = protoimpl.X.CompressGZIP(unsafe.Slice(unsafe.StringData(file_github_com_tonistiigi_fsutil_types_wire_proto_rawDesc), len(file_github_com_tonistiigi_fsutil_types_wire_proto_rawDesc)))
	})
	return file_github_com_tonistiigi_fsutil_types_wire_proto_rawDescData
}

var file_github_com_tonistiigi_fsutil_types_wire_proto_enumTypes = make([]protoimpl.EnumInfo, 1)
var file_github_com_tonistiigi_fsutil_types_wire_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_github_com_tonistiigi_fsutil_types_wire_proto_goTypes = []any{
	(Packet_PacketType)(0),
	(*Packet)(nil),
	(*Stat)(nil),
}
var file_github_com_tonistiigi_fsutil_types_wire_proto_depIdxs = []int32{
	0,
	2,
	2,
	2,
	2,
	2,
	0,
}

func init() { file_github_com_tonistiigi_fsutil_types_wire_proto_init() }
func file_github_com_tonistiigi_fsutil_types_wire_proto_init() {
	if File_github_com_tonistiigi_fsutil_types_wire_proto != nil {
		return
	}
	file_github_com_tonistiigi_fsutil_types_stat_proto_init()
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: unsafe.Slice(unsafe.StringData(file_github_com_tonistiigi_fsutil_types_wire_proto_rawDesc), len(file_github_com_tonistiigi_fsutil_types_wire_proto_rawDesc)),
			NumEnums:      1,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_github_com_tonistiigi_fsutil_types_wire_proto_goTypes,
		DependencyIndexes: file_github_com_tonistiigi_fsutil_types_wire_proto_depIdxs,
		EnumInfos:         file_github_com_tonistiigi_fsutil_types_wire_proto_enumTypes,
		MessageInfos:      file_github_com_tonistiigi_fsutil_types_wire_proto_msgTypes,
	}.Build()
	File_github_com_tonistiigi_fsutil_types_wire_proto = out.File
	file_github_com_tonistiigi_fsutil_types_wire_proto_goTypes = nil
	file_github_com_tonistiigi_fsutil_types_wire_proto_depIdxs = nil
}
