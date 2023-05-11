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
lib.set_library_names("oledlg.dll")
prototypes = \
    {
        #
        'OleUIAddVerbMenuW': SimTypeFunction([SimTypeBottom(label="IOleObject"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpOleObj", "lpszShortType", "hMenu", "uPos", "uIDVerbMin", "uIDVerbMax", "bAddConvert", "idConvert", "lphMenu"]),
        #
        'OleUIAddVerbMenuA': SimTypeFunction([SimTypeBottom(label="IOleObject"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpOleObj", "lpszShortType", "hMenu", "uPos", "uIDVerbMin", "uIDVerbMax", "bAddConvert", "idConvert", "lphMenu"]),
        #
        'OleUIInsertObjectW': SimTypeFunction([SimTypePointer(SimStruct({"cbStruct": SimTypeInt(signed=False, label="UInt32"), "dwFlags": SimTypeInt(signed=False, label="UInt32"), "hWndOwner": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), "lpszCaption": SimTypePointer(SimTypeChar(label="Char"), offset=0), "lpfnHook": SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["param0", "param1", "param2", "param3"]), offset=0), "lCustData": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), "hInstance": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), "lpszTemplate": SimTypePointer(SimTypeChar(label="Char"), offset=0), "hResource": SimTypeBottom(label="HRSRC"), "clsid": SimTypeBottom(label="Guid"), "lpszFile": SimTypePointer(SimTypeChar(label="Char"), offset=0), "cchFile": SimTypeInt(signed=False, label="UInt32"), "cClsidExclude": SimTypeInt(signed=False, label="UInt32"), "lpClsidExclude": SimTypePointer(SimTypeBottom(label="Guid"), offset=0), "iid": SimTypeBottom(label="Guid"), "oleRender": SimTypeInt(signed=False, label="UInt32"), "lpFormatEtc": SimTypePointer(SimStruct({"cfFormat": SimTypeShort(signed=False, label="UInt16"), "ptd": SimTypePointer(SimStruct({"tdSize": SimTypeInt(signed=False, label="UInt32"), "tdDriverNameOffset": SimTypeShort(signed=False, label="UInt16"), "tdDeviceNameOffset": SimTypeShort(signed=False, label="UInt16"), "tdPortNameOffset": SimTypeShort(signed=False, label="UInt16"), "tdExtDevmodeOffset": SimTypeShort(signed=False, label="UInt16"), "tdData": SimTypePointer(SimTypeChar(label="Byte"), offset=0)}, name="DVTARGETDEVICE", pack=False, align=None), offset=0), "dwAspect": SimTypeInt(signed=False, label="UInt32"), "lindex": SimTypeInt(signed=True, label="Int32"), "tymed": SimTypeInt(signed=False, label="UInt32")}, name="FORMATETC", pack=False, align=None), offset=0), "lpIOleClientSite": SimTypeBottom(label="IOleClientSite"), "lpIStorage": SimTypeBottom(label="IStorage"), "ppvObj": SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), "sc": SimTypeInt(signed=True, label="Int32"), "hMetaPict": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)}, name="OLEUIINSERTOBJECTW", pack=False, align=None), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["param0"]),
        #
        'OleUIInsertObjectA': SimTypeFunction([SimTypePointer(SimStruct({"cbStruct": SimTypeInt(signed=False, label="UInt32"), "dwFlags": SimTypeInt(signed=False, label="UInt32"), "hWndOwner": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), "lpszCaption": SimTypePointer(SimTypeChar(label="Byte"), offset=0), "lpfnHook": SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["param0", "param1", "param2", "param3"]), offset=0), "lCustData": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), "hInstance": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), "lpszTemplate": SimTypePointer(SimTypeChar(label="Byte"), offset=0), "hResource": SimTypeBottom(label="HRSRC"), "clsid": SimTypeBottom(label="Guid"), "lpszFile": SimTypePointer(SimTypeChar(label="Byte"), offset=0), "cchFile": SimTypeInt(signed=False, label="UInt32"), "cClsidExclude": SimTypeInt(signed=False, label="UInt32"), "lpClsidExclude": SimTypePointer(SimTypeBottom(label="Guid"), offset=0), "iid": SimTypeBottom(label="Guid"), "oleRender": SimTypeInt(signed=False, label="UInt32"), "lpFormatEtc": SimTypePointer(SimStruct({"cfFormat": SimTypeShort(signed=False, label="UInt16"), "ptd": SimTypePointer(SimStruct({"tdSize": SimTypeInt(signed=False, label="UInt32"), "tdDriverNameOffset": SimTypeShort(signed=False, label="UInt16"), "tdDeviceNameOffset": SimTypeShort(signed=False, label="UInt16"), "tdPortNameOffset": SimTypeShort(signed=False, label="UInt16"), "tdExtDevmodeOffset": SimTypeShort(signed=False, label="UInt16"), "tdData": SimTypePointer(SimTypeChar(label="Byte"), offset=0)}, name="DVTARGETDEVICE", pack=False, align=None), offset=0), "dwAspect": SimTypeInt(signed=False, label="UInt32"), "lindex": SimTypeInt(signed=True, label="Int32"), "tymed": SimTypeInt(signed=False, label="UInt32")}, name="FORMATETC", pack=False, align=None), offset=0), "lpIOleClientSite": SimTypeBottom(label="IOleClientSite"), "lpIStorage": SimTypeBottom(label="IStorage"), "ppvObj": SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), "sc": SimTypeInt(signed=True, label="Int32"), "hMetaPict": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)}, name="OLEUIINSERTOBJECTA", pack=False, align=None), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["param0"]),
        #
        'OleUIPasteSpecialW': SimTypeFunction([SimTypePointer(SimStruct({"cbStruct": SimTypeInt(signed=False, label="UInt32"), "dwFlags": SimTypeInt(signed=False, label="UInt32"), "hWndOwner": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), "lpszCaption": SimTypePointer(SimTypeChar(label="Char"), offset=0), "lpfnHook": SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["param0", "param1", "param2", "param3"]), offset=0), "lCustData": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), "hInstance": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), "lpszTemplate": SimTypePointer(SimTypeChar(label="Char"), offset=0), "hResource": SimTypeBottom(label="HRSRC"), "lpSrcDataObj": SimTypeBottom(label="IDataObject"), "arrPasteEntries": SimTypePointer(SimStruct({"fmtetc": SimStruct({"cfFormat": SimTypeShort(signed=False, label="UInt16"), "ptd": SimTypePointer(SimStruct({"tdSize": SimTypeInt(signed=False, label="UInt32"), "tdDriverNameOffset": SimTypeShort(signed=False, label="UInt16"), "tdDeviceNameOffset": SimTypeShort(signed=False, label="UInt16"), "tdPortNameOffset": SimTypeShort(signed=False, label="UInt16"), "tdExtDevmodeOffset": SimTypeShort(signed=False, label="UInt16"), "tdData": SimTypePointer(SimTypeChar(label="Byte"), offset=0)}, name="DVTARGETDEVICE", pack=False, align=None), offset=0), "dwAspect": SimTypeInt(signed=False, label="UInt32"), "lindex": SimTypeInt(signed=True, label="Int32"), "tymed": SimTypeInt(signed=False, label="UInt32")}, name="FORMATETC", pack=False, align=None), "lpstrFormatName": SimTypePointer(SimTypeChar(label="Char"), offset=0), "lpstrResultText": SimTypePointer(SimTypeChar(label="Char"), offset=0), "dwFlags": SimTypeInt(signed=False, label="UInt32"), "dwScratchSpace": SimTypeInt(signed=False, label="UInt32")}, name="OLEUIPASTEENTRYW", pack=False, align=None), offset=0), "cPasteEntries": SimTypeInt(signed=True, label="Int32"), "arrLinkTypes": SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), "cLinkTypes": SimTypeInt(signed=True, label="Int32"), "cClsidExclude": SimTypeInt(signed=False, label="UInt32"), "lpClsidExclude": SimTypePointer(SimTypeBottom(label="Guid"), offset=0), "nSelectedIndex": SimTypeInt(signed=True, label="Int32"), "fLink": SimTypeInt(signed=True, label="Int32"), "hMetaPict": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), "sizel": SimStruct({"cx": SimTypeInt(signed=True, label="Int32"), "cy": SimTypeInt(signed=True, label="Int32")}, name="SIZE", pack=False, align=None)}, name="OLEUIPASTESPECIALW", pack=False, align=None), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["param0"]),
        #
        'OleUIPasteSpecialA': SimTypeFunction([SimTypePointer(SimStruct({"cbStruct": SimTypeInt(signed=False, label="UInt32"), "dwFlags": SimTypeInt(signed=False, label="UInt32"), "hWndOwner": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), "lpszCaption": SimTypePointer(SimTypeChar(label="Byte"), offset=0), "lpfnHook": SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["param0", "param1", "param2", "param3"]), offset=0), "lCustData": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), "hInstance": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), "lpszTemplate": SimTypePointer(SimTypeChar(label="Byte"), offset=0), "hResource": SimTypeBottom(label="HRSRC"), "lpSrcDataObj": SimTypeBottom(label="IDataObject"), "arrPasteEntries": SimTypePointer(SimStruct({"fmtetc": SimStruct({"cfFormat": SimTypeShort(signed=False, label="UInt16"), "ptd": SimTypePointer(SimStruct({"tdSize": SimTypeInt(signed=False, label="UInt32"), "tdDriverNameOffset": SimTypeShort(signed=False, label="UInt16"), "tdDeviceNameOffset": SimTypeShort(signed=False, label="UInt16"), "tdPortNameOffset": SimTypeShort(signed=False, label="UInt16"), "tdExtDevmodeOffset": SimTypeShort(signed=False, label="UInt16"), "tdData": SimTypePointer(SimTypeChar(label="Byte"), offset=0)}, name="DVTARGETDEVICE", pack=False, align=None), offset=0), "dwAspect": SimTypeInt(signed=False, label="UInt32"), "lindex": SimTypeInt(signed=True, label="Int32"), "tymed": SimTypeInt(signed=False, label="UInt32")}, name="FORMATETC", pack=False, align=None), "lpstrFormatName": SimTypePointer(SimTypeChar(label="Byte"), offset=0), "lpstrResultText": SimTypePointer(SimTypeChar(label="Byte"), offset=0), "dwFlags": SimTypeInt(signed=False, label="UInt32"), "dwScratchSpace": SimTypeInt(signed=False, label="UInt32")}, name="OLEUIPASTEENTRYA", pack=False, align=None), offset=0), "cPasteEntries": SimTypeInt(signed=True, label="Int32"), "arrLinkTypes": SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), "cLinkTypes": SimTypeInt(signed=True, label="Int32"), "cClsidExclude": SimTypeInt(signed=False, label="UInt32"), "lpClsidExclude": SimTypePointer(SimTypeBottom(label="Guid"), offset=0), "nSelectedIndex": SimTypeInt(signed=True, label="Int32"), "fLink": SimTypeInt(signed=True, label="Int32"), "hMetaPict": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), "sizel": SimStruct({"cx": SimTypeInt(signed=True, label="Int32"), "cy": SimTypeInt(signed=True, label="Int32")}, name="SIZE", pack=False, align=None)}, name="OLEUIPASTESPECIALA", pack=False, align=None), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["param0"]),
        #
        'OleUIEditLinksW': SimTypeFunction([SimTypePointer(SimStruct({"cbStruct": SimTypeInt(signed=False, label="UInt32"), "dwFlags": SimTypeInt(signed=False, label="UInt32"), "hWndOwner": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), "lpszCaption": SimTypePointer(SimTypeChar(label="Char"), offset=0), "lpfnHook": SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["param0", "param1", "param2", "param3"]), offset=0), "lCustData": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), "hInstance": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), "lpszTemplate": SimTypePointer(SimTypeChar(label="Char"), offset=0), "hResource": SimTypeBottom(label="HRSRC"), "lpOleUILinkContainer": SimTypeBottom(label="IOleUILinkContainerW")}, name="OLEUIEDITLINKSW", pack=False, align=None), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["param0"]),
        #
        'OleUIEditLinksA': SimTypeFunction([SimTypePointer(SimStruct({"cbStruct": SimTypeInt(signed=False, label="UInt32"), "dwFlags": SimTypeInt(signed=False, label="UInt32"), "hWndOwner": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), "lpszCaption": SimTypePointer(SimTypeChar(label="Byte"), offset=0), "lpfnHook": SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["param0", "param1", "param2", "param3"]), offset=0), "lCustData": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), "hInstance": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), "lpszTemplate": SimTypePointer(SimTypeChar(label="Byte"), offset=0), "hResource": SimTypeBottom(label="HRSRC"), "lpOleUILinkContainer": SimTypeBottom(label="IOleUILinkContainerA")}, name="OLEUIEDITLINKSA", pack=False, align=None), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["param0"]),
        #
        'OleUIChangeIconW': SimTypeFunction([SimTypePointer(SimStruct({"cbStruct": SimTypeInt(signed=False, label="UInt32"), "dwFlags": SimTypeInt(signed=False, label="UInt32"), "hWndOwner": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), "lpszCaption": SimTypePointer(SimTypeChar(label="Char"), offset=0), "lpfnHook": SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["param0", "param1", "param2", "param3"]), offset=0), "lCustData": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), "hInstance": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), "lpszTemplate": SimTypePointer(SimTypeChar(label="Char"), offset=0), "hResource": SimTypeBottom(label="HRSRC"), "hMetaPict": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), "clsid": SimTypeBottom(label="Guid"), "szIconExe": SimTypeFixedSizeArray(SimTypeChar(label="Char"), 260), "cchIconExe": SimTypeInt(signed=True, label="Int32")}, name="OLEUICHANGEICONW", pack=False, align=None), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["param0"]),
        #
        'OleUIChangeIconA': SimTypeFunction([SimTypePointer(SimStruct({"cbStruct": SimTypeInt(signed=False, label="UInt32"), "dwFlags": SimTypeInt(signed=False, label="UInt32"), "hWndOwner": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), "lpszCaption": SimTypePointer(SimTypeChar(label="Byte"), offset=0), "lpfnHook": SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["param0", "param1", "param2", "param3"]), offset=0), "lCustData": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), "hInstance": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), "lpszTemplate": SimTypePointer(SimTypeChar(label="Byte"), offset=0), "hResource": SimTypeBottom(label="HRSRC"), "hMetaPict": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), "clsid": SimTypeBottom(label="Guid"), "szIconExe": SimTypeFixedSizeArray(SimTypeBottom(label="CHAR"), 260), "cchIconExe": SimTypeInt(signed=True, label="Int32")}, name="OLEUICHANGEICONA", pack=False, align=None), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["param0"]),
        #
        'OleUIConvertW': SimTypeFunction([SimTypePointer(SimStruct({"cbStruct": SimTypeInt(signed=False, label="UInt32"), "dwFlags": SimTypeInt(signed=False, label="UInt32"), "hWndOwner": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), "lpszCaption": SimTypePointer(SimTypeChar(label="Char"), offset=0), "lpfnHook": SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["param0", "param1", "param2", "param3"]), offset=0), "lCustData": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), "hInstance": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), "lpszTemplate": SimTypePointer(SimTypeChar(label="Char"), offset=0), "hResource": SimTypeBottom(label="HRSRC"), "clsid": SimTypeBottom(label="Guid"), "clsidConvertDefault": SimTypeBottom(label="Guid"), "clsidActivateDefault": SimTypeBottom(label="Guid"), "clsidNew": SimTypeBottom(label="Guid"), "dvAspect": SimTypeInt(signed=False, label="UInt32"), "wFormat": SimTypeShort(signed=False, label="UInt16"), "fIsLinkedObject": SimTypeInt(signed=True, label="Int32"), "hMetaPict": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), "lpszUserType": SimTypePointer(SimTypeChar(label="Char"), offset=0), "fObjectsIconChanged": SimTypeInt(signed=True, label="Int32"), "lpszDefLabel": SimTypePointer(SimTypeChar(label="Char"), offset=0), "cClsidExclude": SimTypeInt(signed=False, label="UInt32"), "lpClsidExclude": SimTypePointer(SimTypeBottom(label="Guid"), offset=0)}, name="OLEUICONVERTW", pack=False, align=None), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["param0"]),
        #
        'OleUIConvertA': SimTypeFunction([SimTypePointer(SimStruct({"cbStruct": SimTypeInt(signed=False, label="UInt32"), "dwFlags": SimTypeInt(signed=False, label="UInt32"), "hWndOwner": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), "lpszCaption": SimTypePointer(SimTypeChar(label="Byte"), offset=0), "lpfnHook": SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["param0", "param1", "param2", "param3"]), offset=0), "lCustData": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), "hInstance": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), "lpszTemplate": SimTypePointer(SimTypeChar(label="Byte"), offset=0), "hResource": SimTypeBottom(label="HRSRC"), "clsid": SimTypeBottom(label="Guid"), "clsidConvertDefault": SimTypeBottom(label="Guid"), "clsidActivateDefault": SimTypeBottom(label="Guid"), "clsidNew": SimTypeBottom(label="Guid"), "dvAspect": SimTypeInt(signed=False, label="UInt32"), "wFormat": SimTypeShort(signed=False, label="UInt16"), "fIsLinkedObject": SimTypeInt(signed=True, label="Int32"), "hMetaPict": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), "lpszUserType": SimTypePointer(SimTypeChar(label="Byte"), offset=0), "fObjectsIconChanged": SimTypeInt(signed=True, label="Int32"), "lpszDefLabel": SimTypePointer(SimTypeChar(label="Byte"), offset=0), "cClsidExclude": SimTypeInt(signed=False, label="UInt32"), "lpClsidExclude": SimTypePointer(SimTypeBottom(label="Guid"), offset=0)}, name="OLEUICONVERTA", pack=False, align=None), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["param0"]),
        #
        'OleUICanConvertOrActivateAs': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeShort(signed=False, label="UInt16")], SimTypeInt(signed=True, label="Int32"), arg_names=["rClsid", "fIsLinkedObject", "wFormat"]),
        #
        'OleUIBusyW': SimTypeFunction([SimTypePointer(SimStruct({"cbStruct": SimTypeInt(signed=False, label="UInt32"), "dwFlags": SimTypeInt(signed=False, label="UInt32"), "hWndOwner": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), "lpszCaption": SimTypePointer(SimTypeChar(label="Char"), offset=0), "lpfnHook": SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["param0", "param1", "param2", "param3"]), offset=0), "lCustData": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), "hInstance": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), "lpszTemplate": SimTypePointer(SimTypeChar(label="Char"), offset=0), "hResource": SimTypeBottom(label="HRSRC"), "hTask": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), "lphWndDialog": SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)}, name="OLEUIBUSYW", pack=False, align=None), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["param0"]),
        #
        'OleUIBusyA': SimTypeFunction([SimTypePointer(SimStruct({"cbStruct": SimTypeInt(signed=False, label="UInt32"), "dwFlags": SimTypeInt(signed=False, label="UInt32"), "hWndOwner": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), "lpszCaption": SimTypePointer(SimTypeChar(label="Byte"), offset=0), "lpfnHook": SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["param0", "param1", "param2", "param3"]), offset=0), "lCustData": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), "hInstance": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), "lpszTemplate": SimTypePointer(SimTypeChar(label="Byte"), offset=0), "hResource": SimTypeBottom(label="HRSRC"), "hTask": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), "lphWndDialog": SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)}, name="OLEUIBUSYA", pack=False, align=None), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["param0"]),
        #
        'OleUIChangeSourceW': SimTypeFunction([SimTypePointer(SimStruct({"cbStruct": SimTypeInt(signed=False, label="UInt32"), "dwFlags": SimTypeInt(signed=False, label="UInt32"), "hWndOwner": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), "lpszCaption": SimTypePointer(SimTypeChar(label="Char"), offset=0), "lpfnHook": SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["param0", "param1", "param2", "param3"]), offset=0), "lCustData": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), "hInstance": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), "lpszTemplate": SimTypePointer(SimTypeChar(label="Char"), offset=0), "hResource": SimTypeBottom(label="HRSRC"), "lpOFN": SimTypePointer(SimTypeBottom(label="OPENFILENAMEW"), offset=0), "dwReserved1": SimTypeFixedSizeArray(SimTypeInt(signed=False, label="UInt32"), 4), "lpOleUILinkContainer": SimTypeBottom(label="IOleUILinkContainerW"), "dwLink": SimTypeInt(signed=False, label="UInt32"), "lpszDisplayName": SimTypePointer(SimTypeChar(label="Char"), offset=0), "nFileLength": SimTypeInt(signed=False, label="UInt32"), "lpszFrom": SimTypePointer(SimTypeChar(label="Char"), offset=0), "lpszTo": SimTypePointer(SimTypeChar(label="Char"), offset=0)}, name="OLEUICHANGESOURCEW", pack=False, align=None), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["param0"]),
        #
        'OleUIChangeSourceA': SimTypeFunction([SimTypePointer(SimStruct({"cbStruct": SimTypeInt(signed=False, label="UInt32"), "dwFlags": SimTypeInt(signed=False, label="UInt32"), "hWndOwner": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), "lpszCaption": SimTypePointer(SimTypeChar(label="Byte"), offset=0), "lpfnHook": SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["param0", "param1", "param2", "param3"]), offset=0), "lCustData": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), "hInstance": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), "lpszTemplate": SimTypePointer(SimTypeChar(label="Byte"), offset=0), "hResource": SimTypeBottom(label="HRSRC"), "lpOFN": SimTypePointer(SimTypeBottom(label="OPENFILENAMEA"), offset=0), "dwReserved1": SimTypeFixedSizeArray(SimTypeInt(signed=False, label="UInt32"), 4), "lpOleUILinkContainer": SimTypeBottom(label="IOleUILinkContainerA"), "dwLink": SimTypeInt(signed=False, label="UInt32"), "lpszDisplayName": SimTypePointer(SimTypeChar(label="Byte"), offset=0), "nFileLength": SimTypeInt(signed=False, label="UInt32"), "lpszFrom": SimTypePointer(SimTypeChar(label="Byte"), offset=0), "lpszTo": SimTypePointer(SimTypeChar(label="Byte"), offset=0)}, name="OLEUICHANGESOURCEA", pack=False, align=None), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["param0"]),
        #
        'OleUIObjectPropertiesW': SimTypeFunction([SimTypePointer(SimStruct({"cbStruct": SimTypeInt(signed=False, label="UInt32"), "dwFlags": SimTypeInt(signed=False, label="UInt32"), "lpPS": SimTypePointer(SimTypeBottom(label="PROPSHEETHEADERW_V2"), offset=0), "dwObject": SimTypeInt(signed=False, label="UInt32"), "lpObjInfo": SimTypeBottom(label="IOleUIObjInfoW"), "dwLink": SimTypeInt(signed=False, label="UInt32"), "lpLinkInfo": SimTypeBottom(label="IOleUILinkInfoW"), "lpGP": SimTypePointer(SimStruct({"cbStruct": SimTypeInt(signed=False, label="UInt32"), "dwFlags": SimTypeInt(signed=False, label="UInt32"), "dwReserved1": SimTypeFixedSizeArray(SimTypeInt(signed=False, label="UInt32"), 2), "lpfnHook": SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["param0", "param1", "param2", "param3"]), offset=0), "lCustData": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), "dwReserved2": SimTypeFixedSizeArray(SimTypeInt(signed=False, label="UInt32"), 3), "lpOP": SimTypePointer(SimTypeBottom(label="OLEUIOBJECTPROPSW"), offset=0)}, name="OLEUIGNRLPROPSW", pack=False, align=None), offset=0), "lpVP": SimTypePointer(SimStruct({"cbStruct": SimTypeInt(signed=False, label="UInt32"), "dwFlags": SimTypeInt(signed=False, label="UInt32"), "dwReserved1": SimTypeFixedSizeArray(SimTypeInt(signed=False, label="UInt32"), 2), "lpfnHook": SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["param0", "param1", "param2", "param3"]), offset=0), "lCustData": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), "dwReserved2": SimTypeFixedSizeArray(SimTypeInt(signed=False, label="UInt32"), 3), "lpOP": SimTypePointer(SimTypeBottom(label="OLEUIOBJECTPROPSW"), offset=0), "nScaleMin": SimTypeInt(signed=True, label="Int32"), "nScaleMax": SimTypeInt(signed=True, label="Int32")}, name="OLEUIVIEWPROPSW", pack=False, align=None), offset=0), "lpLP": SimTypePointer(SimStruct({"cbStruct": SimTypeInt(signed=False, label="UInt32"), "dwFlags": SimTypeInt(signed=False, label="UInt32"), "dwReserved1": SimTypeFixedSizeArray(SimTypeInt(signed=False, label="UInt32"), 2), "lpfnHook": SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["param0", "param1", "param2", "param3"]), offset=0), "lCustData": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), "dwReserved2": SimTypeFixedSizeArray(SimTypeInt(signed=False, label="UInt32"), 3), "lpOP": SimTypePointer(SimTypeBottom(label="OLEUIOBJECTPROPSW"), offset=0)}, name="OLEUILINKPROPSW", pack=False, align=None), offset=0)}, name="OLEUIOBJECTPROPSW", pack=False, align=None), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["param0"]),
        #
        'OleUIObjectPropertiesA': SimTypeFunction([SimTypePointer(SimStruct({"cbStruct": SimTypeInt(signed=False, label="UInt32"), "dwFlags": SimTypeInt(signed=False, label="UInt32"), "lpPS": SimTypePointer(SimTypeBottom(label="PROPSHEETHEADERA_V2"), offset=0), "dwObject": SimTypeInt(signed=False, label="UInt32"), "lpObjInfo": SimTypeBottom(label="IOleUIObjInfoA"), "dwLink": SimTypeInt(signed=False, label="UInt32"), "lpLinkInfo": SimTypeBottom(label="IOleUILinkInfoA"), "lpGP": SimTypePointer(SimStruct({"cbStruct": SimTypeInt(signed=False, label="UInt32"), "dwFlags": SimTypeInt(signed=False, label="UInt32"), "dwReserved1": SimTypeFixedSizeArray(SimTypeInt(signed=False, label="UInt32"), 2), "lpfnHook": SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["param0", "param1", "param2", "param3"]), offset=0), "lCustData": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), "dwReserved2": SimTypeFixedSizeArray(SimTypeInt(signed=False, label="UInt32"), 3), "lpOP": SimTypePointer(SimTypeBottom(label="OLEUIOBJECTPROPSA"), offset=0)}, name="OLEUIGNRLPROPSA", pack=False, align=None), offset=0), "lpVP": SimTypePointer(SimStruct({"cbStruct": SimTypeInt(signed=False, label="UInt32"), "dwFlags": SimTypeInt(signed=False, label="UInt32"), "dwReserved1": SimTypeFixedSizeArray(SimTypeInt(signed=False, label="UInt32"), 2), "lpfnHook": SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["param0", "param1", "param2", "param3"]), offset=0), "lCustData": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), "dwReserved2": SimTypeFixedSizeArray(SimTypeInt(signed=False, label="UInt32"), 3), "lpOP": SimTypePointer(SimTypeBottom(label="OLEUIOBJECTPROPSA"), offset=0), "nScaleMin": SimTypeInt(signed=True, label="Int32"), "nScaleMax": SimTypeInt(signed=True, label="Int32")}, name="OLEUIVIEWPROPSA", pack=False, align=None), offset=0), "lpLP": SimTypePointer(SimStruct({"cbStruct": SimTypeInt(signed=False, label="UInt32"), "dwFlags": SimTypeInt(signed=False, label="UInt32"), "dwReserved1": SimTypeFixedSizeArray(SimTypeInt(signed=False, label="UInt32"), 2), "lpfnHook": SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["param0", "param1", "param2", "param3"]), offset=0), "lCustData": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), "dwReserved2": SimTypeFixedSizeArray(SimTypeInt(signed=False, label="UInt32"), 3), "lpOP": SimTypePointer(SimTypeBottom(label="OLEUIOBJECTPROPSA"), offset=0)}, name="OLEUILINKPROPSA", pack=False, align=None), offset=0)}, name="OLEUIOBJECTPROPSA", pack=False, align=None), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["param0"]),
        #
        'OleUIPromptUserW': SimTypeFunction([SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["nTemplate", "hwndParent"]),
        #
        'OleUIPromptUserA': SimTypeFunction([SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["nTemplate", "hwndParent"]),
        #
        'OleUIUpdateLinksW': SimTypeFunction([SimTypeBottom(label="IOleUILinkContainerW"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["lpOleUILinkCntr", "hwndParent", "lpszTitle", "cLinks"]),
        #
        'OleUIUpdateLinksA': SimTypeFunction([SimTypeBottom(label="IOleUILinkContainerA"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["lpOleUILinkCntr", "hwndParent", "lpszTitle", "cLinks"]),
    }

lib.set_prototypes(prototypes)
