# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: protos/xrefs.proto
"""Generated protocol buffer code."""
from google.protobuf import descriptor as _descriptor
from google.protobuf import descriptor_pool as _descriptor_pool
from google.protobuf import message as _message
from google.protobuf import reflection as _reflection
from google.protobuf import symbol_database as _symbol_database
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()


from . import primitives_pb2 as protos_dot_primitives__pb2


DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(b'\n\x12protos/xrefs.proto\x12\x0b\x61ngr.protos\x1a\x17protos/primitives.proto\"2\n\x05XRefs\x12)\n\x05xrefs\x18\x01 \x03(\x0b\x32\x1a.angr.protos.CodeReferenceb\x06proto3')



_XREFS = DESCRIPTOR.message_types_by_name['XRefs']
XRefs = _reflection.GeneratedProtocolMessageType('XRefs', (_message.Message,), {
  'DESCRIPTOR' : _XREFS,
  '__module__' : 'protos.xrefs_pb2'
  # @@protoc_insertion_point(class_scope:angr.protos.XRefs)
  })
_sym_db.RegisterMessage(XRefs)

if _descriptor._USE_C_DESCRIPTORS == False:

  DESCRIPTOR._options = None
  _XREFS._serialized_start=60
  _XREFS._serialized_end=110
# @@protoc_insertion_point(module_scope)
