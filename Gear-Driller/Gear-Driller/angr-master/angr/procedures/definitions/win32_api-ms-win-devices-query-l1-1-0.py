# pylint:disable=line-too-long
import logging

from ...sim_type import SimTypeFunction,     SimTypeShort, SimTypeInt, SimTypeLong, SimTypeLongLong, SimTypeDouble, SimTypeFloat,     SimTypePointer,     SimTypeChar,     SimStruct,     SimTypeFixedSizeArray,     SimTypeBottom,     SimUnion,     SimTypeBool
from ...calling_conventions import SimCCStdcall, SimCCMicrosoftAMD64
from .. import SIM_PROCEDURES as P
from . import SimLibrary


_l = logging.getLogger(name=__name__)


lib = SimLibrary()
lib.set_default_cc('X86', SimCCStdcall)
lib.set_default_cc('AMD64', SimCCMicrosoftAMD64)
lib.set_library_names("api-ms-win-devices-query-l1-1-0.dll")
prototypes = \
    {
        #
        'DevCreateObjectQuery': SimTypeFunction([SimTypeInt(signed=False, label="DEV_OBJECT_TYPE"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimStruct({"Key": SimStruct({"fmtid": SimTypeBottom(label="Guid"), "pid": SimTypeInt(signed=False, label="UInt32")}, name="DEVPROPKEY", pack=False, align=None), "Store": SimTypeInt(signed=False, label="DEVPROPSTORE"), "LocaleName": SimTypePointer(SimTypeChar(label="Char"), offset=0)}, name="DEVPROPCOMPKEY", pack=False, align=None), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimStruct({"Operator": SimTypeInt(signed=False, label="DEVPROP_OPERATOR"), "Property": SimTypeBottom(label="DEVPROPERTY")}, name="DEVPROP_FILTER_EXPRESSION", pack=False, align=None), label="LPArray", offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimStruct({"unused": SimTypeInt(signed=True, label="Int32")}, name="HDEVQUERY__", pack=False, align=None), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimStruct({"Action": SimTypeInt(signed=False, label="DEV_QUERY_RESULT_ACTION"), "Data": SimUnion({"State": SimTypeInt(signed=False, label="DEV_QUERY_STATE"), "DeviceObject": SimStruct({"ObjectType": SimTypeInt(signed=False, label="DEV_OBJECT_TYPE"), "pszObjectId": SimTypeBottom(label="PWSTR"), "cPropertyCount": SimTypeInt(signed=False, label="UInt32"), "pProperties": SimTypePointer(SimTypeBottom(label="DEVPROPERTY"), offset=0)}, name="DEV_OBJECT", pack=False, align=None)}, name="<anon>", label="None")}, name="DEV_QUERY_RESULT_ACTION_DATA", pack=False, align=None), offset=0)], SimTypeBottom(label="Void"), arg_names=["hDevQuery", "pContext", "pActionData"]), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypePointer(SimStruct({"unused": SimTypeInt(signed=True, label="Int32")}, name="HDEVQUERY__", pack=False, align=None), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ObjectType", "QueryFlags", "cRequestedProperties", "pRequestedProperties", "cFilterExpressionCount", "pFilter", "pCallback", "pContext", "phDevQuery"]),
        #
        'DevCreateObjectQueryFromId': SimTypeFunction([SimTypeInt(signed=False, label="DEV_OBJECT_TYPE"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimStruct({"Key": SimStruct({"fmtid": SimTypeBottom(label="Guid"), "pid": SimTypeInt(signed=False, label="UInt32")}, name="DEVPROPKEY", pack=False, align=None), "Store": SimTypeInt(signed=False, label="DEVPROPSTORE"), "LocaleName": SimTypePointer(SimTypeChar(label="Char"), offset=0)}, name="DEVPROPCOMPKEY", pack=False, align=None), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimStruct({"Operator": SimTypeInt(signed=False, label="DEVPROP_OPERATOR"), "Property": SimTypeBottom(label="DEVPROPERTY")}, name="DEVPROP_FILTER_EXPRESSION", pack=False, align=None), label="LPArray", offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimStruct({"unused": SimTypeInt(signed=True, label="Int32")}, name="HDEVQUERY__", pack=False, align=None), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimStruct({"Action": SimTypeInt(signed=False, label="DEV_QUERY_RESULT_ACTION"), "Data": SimUnion({"State": SimTypeInt(signed=False, label="DEV_QUERY_STATE"), "DeviceObject": SimStruct({"ObjectType": SimTypeInt(signed=False, label="DEV_OBJECT_TYPE"), "pszObjectId": SimTypeBottom(label="PWSTR"), "cPropertyCount": SimTypeInt(signed=False, label="UInt32"), "pProperties": SimTypePointer(SimTypeBottom(label="DEVPROPERTY"), offset=0)}, name="DEV_OBJECT", pack=False, align=None)}, name="<anon>", label="None")}, name="DEV_QUERY_RESULT_ACTION_DATA", pack=False, align=None), offset=0)], SimTypeBottom(label="Void"), arg_names=["hDevQuery", "pContext", "pActionData"]), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypePointer(SimStruct({"unused": SimTypeInt(signed=True, label="Int32")}, name="HDEVQUERY__", pack=False, align=None), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ObjectType", "pszObjectId", "QueryFlags", "cRequestedProperties", "pRequestedProperties", "cFilterExpressionCount", "pFilter", "pCallback", "pContext", "phDevQuery"]),
        #
        'DevCreateObjectQueryFromIds': SimTypeFunction([SimTypeInt(signed=False, label="DEV_OBJECT_TYPE"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimStruct({"Key": SimStruct({"fmtid": SimTypeBottom(label="Guid"), "pid": SimTypeInt(signed=False, label="UInt32")}, name="DEVPROPKEY", pack=False, align=None), "Store": SimTypeInt(signed=False, label="DEVPROPSTORE"), "LocaleName": SimTypePointer(SimTypeChar(label="Char"), offset=0)}, name="DEVPROPCOMPKEY", pack=False, align=None), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimStruct({"Operator": SimTypeInt(signed=False, label="DEVPROP_OPERATOR"), "Property": SimTypeBottom(label="DEVPROPERTY")}, name="DEVPROP_FILTER_EXPRESSION", pack=False, align=None), label="LPArray", offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimStruct({"unused": SimTypeInt(signed=True, label="Int32")}, name="HDEVQUERY__", pack=False, align=None), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimStruct({"Action": SimTypeInt(signed=False, label="DEV_QUERY_RESULT_ACTION"), "Data": SimUnion({"State": SimTypeInt(signed=False, label="DEV_QUERY_STATE"), "DeviceObject": SimStruct({"ObjectType": SimTypeInt(signed=False, label="DEV_OBJECT_TYPE"), "pszObjectId": SimTypeBottom(label="PWSTR"), "cPropertyCount": SimTypeInt(signed=False, label="UInt32"), "pProperties": SimTypePointer(SimTypeBottom(label="DEVPROPERTY"), offset=0)}, name="DEV_OBJECT", pack=False, align=None)}, name="<anon>", label="None")}, name="DEV_QUERY_RESULT_ACTION_DATA", pack=False, align=None), offset=0)], SimTypeBottom(label="Void"), arg_names=["hDevQuery", "pContext", "pActionData"]), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypePointer(SimStruct({"unused": SimTypeInt(signed=True, label="Int32")}, name="HDEVQUERY__", pack=False, align=None), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ObjectType", "pszzObjectIds", "QueryFlags", "cRequestedProperties", "pRequestedProperties", "cFilterExpressionCount", "pFilter", "pCallback", "pContext", "phDevQuery"]),
        #
        'DevCloseObjectQuery': SimTypeFunction([SimTypePointer(SimStruct({"unused": SimTypeInt(signed=True, label="Int32")}, name="HDEVQUERY__", pack=False, align=None), offset=0)], SimTypeBottom(label="Void"), arg_names=["hDevQuery"]),
        #
        'DevGetObjects': SimTypeFunction([SimTypeInt(signed=False, label="DEV_OBJECT_TYPE"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimStruct({"Key": SimStruct({"fmtid": SimTypeBottom(label="Guid"), "pid": SimTypeInt(signed=False, label="UInt32")}, name="DEVPROPKEY", pack=False, align=None), "Store": SimTypeInt(signed=False, label="DEVPROPSTORE"), "LocaleName": SimTypePointer(SimTypeChar(label="Char"), offset=0)}, name="DEVPROPCOMPKEY", pack=False, align=None), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimStruct({"Operator": SimTypeInt(signed=False, label="DEVPROP_OPERATOR"), "Property": SimTypeBottom(label="DEVPROPERTY")}, name="DEVPROP_FILTER_EXPRESSION", pack=False, align=None), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypePointer(SimStruct({"ObjectType": SimTypeInt(signed=False, label="DEV_OBJECT_TYPE"), "pszObjectId": SimTypeBottom(label="PWSTR"), "cPropertyCount": SimTypeInt(signed=False, label="UInt32"), "pProperties": SimTypePointer(SimTypeBottom(label="DEVPROPERTY"), offset=0)}, name="DEV_OBJECT", pack=False, align=None), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ObjectType", "QueryFlags", "cRequestedProperties", "pRequestedProperties", "cFilterExpressionCount", "pFilter", "pcObjectCount", "ppObjects"]),
        #
        'DevFreeObjects': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimStruct({"ObjectType": SimTypeInt(signed=False, label="DEV_OBJECT_TYPE"), "pszObjectId": SimTypeBottom(label="PWSTR"), "cPropertyCount": SimTypeInt(signed=False, label="UInt32"), "pProperties": SimTypePointer(SimTypeBottom(label="DEVPROPERTY"), offset=0)}, name="DEV_OBJECT", pack=False, align=None), label="LPArray", offset=0)], SimTypeBottom(label="Void"), arg_names=["cObjectCount", "pObjects"]),
        #
        'DevGetObjectProperties': SimTypeFunction([SimTypeInt(signed=False, label="DEV_OBJECT_TYPE"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimStruct({"Key": SimStruct({"fmtid": SimTypeBottom(label="Guid"), "pid": SimTypeInt(signed=False, label="UInt32")}, name="DEVPROPKEY", pack=False, align=None), "Store": SimTypeInt(signed=False, label="DEVPROPSTORE"), "LocaleName": SimTypePointer(SimTypeChar(label="Char"), offset=0)}, name="DEVPROPCOMPKEY", pack=False, align=None), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypePointer(SimStruct({"CompKey": SimStruct({"Key": SimStruct({"fmtid": SimTypeBottom(label="Guid"), "pid": SimTypeInt(signed=False, label="UInt32")}, name="DEVPROPKEY", pack=False, align=None), "Store": SimTypeInt(signed=False, label="DEVPROPSTORE"), "LocaleName": SimTypePointer(SimTypeChar(label="Char"), offset=0)}, name="DEVPROPCOMPKEY", pack=False, align=None), "Type": SimTypeInt(signed=False, label="UInt32"), "BufferSize": SimTypeInt(signed=False, label="UInt32"), "Buffer": SimTypePointer(SimTypeBottom(label="Void"), offset=0)}, name="DEVPROPERTY", pack=False, align=None), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ObjectType", "pszObjectId", "QueryFlags", "cRequestedProperties", "pRequestedProperties", "pcPropertyCount", "ppProperties"]),
        #
        'DevFreeObjectProperties': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimStruct({"CompKey": SimStruct({"Key": SimStruct({"fmtid": SimTypeBottom(label="Guid"), "pid": SimTypeInt(signed=False, label="UInt32")}, name="DEVPROPKEY", pack=False, align=None), "Store": SimTypeInt(signed=False, label="DEVPROPSTORE"), "LocaleName": SimTypePointer(SimTypeChar(label="Char"), offset=0)}, name="DEVPROPCOMPKEY", pack=False, align=None), "Type": SimTypeInt(signed=False, label="UInt32"), "BufferSize": SimTypeInt(signed=False, label="UInt32"), "Buffer": SimTypePointer(SimTypeBottom(label="Void"), offset=0)}, name="DEVPROPERTY", pack=False, align=None), label="LPArray", offset=0)], SimTypeBottom(label="Void"), arg_names=["cPropertyCount", "pProperties"]),
        #
        'DevFindProperty': SimTypeFunction([SimTypePointer(SimStruct({"fmtid": SimTypeBottom(label="Guid"), "pid": SimTypeInt(signed=False, label="UInt32")}, name="DEVPROPKEY", pack=False, align=None), offset=0), SimTypeInt(signed=False, label="DEVPROPSTORE"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimStruct({"CompKey": SimStruct({"Key": SimStruct({"fmtid": SimTypeBottom(label="Guid"), "pid": SimTypeInt(signed=False, label="UInt32")}, name="DEVPROPKEY", pack=False, align=None), "Store": SimTypeInt(signed=False, label="DEVPROPSTORE"), "LocaleName": SimTypePointer(SimTypeChar(label="Char"), offset=0)}, name="DEVPROPCOMPKEY", pack=False, align=None), "Type": SimTypeInt(signed=False, label="UInt32"), "BufferSize": SimTypeInt(signed=False, label="UInt32"), "Buffer": SimTypePointer(SimTypeBottom(label="Void"), offset=0)}, name="DEVPROPERTY", pack=False, align=None), label="LPArray", offset=0)], SimTypePointer(SimStruct({"CompKey": SimStruct({"Key": SimStruct({"fmtid": SimTypeBottom(label="Guid"), "pid": SimTypeInt(signed=False, label="UInt32")}, name="DEVPROPKEY", pack=False, align=None), "Store": SimTypeInt(signed=False, label="DEVPROPSTORE"), "LocaleName": SimTypePointer(SimTypeChar(label="Char"), offset=0)}, name="DEVPROPCOMPKEY", pack=False, align=None), "Type": SimTypeInt(signed=False, label="UInt32"), "BufferSize": SimTypeInt(signed=False, label="UInt32"), "Buffer": SimTypePointer(SimTypeBottom(label="Void"), offset=0)}, name="DEVPROPERTY", pack=False, align=None), offset=0), arg_names=["pKey", "Store", "pszLocaleName", "cProperties", "pProperties"]),
    }

lib.set_prototypes(prototypes)
