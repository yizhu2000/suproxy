--tns protocol parser 
local P=require "suproxy.tns.tnsPackets"
local K=P.getKey
local parser=require("suproxy.parser")
local _M={}

local conf={
	{key=K({code=1}),         parser=P.Connect,              eventName="ConnectEvent"},
	{key=K({callId=0x76}),    parser=P.SessionRequest,       eventName="SessionRequestEvent"},
	{key=K({callId=0x73}),    parser=P.AuthRequest,          eventName="AuthRequestEvent"},
	{key=K({dataId=1}),       parser=P.SetProtocolRequest,   eventName="SetProtocolEvent"},
	{key=K({callId=0x69}),    parser=P.Piggyback,            eventName="Piggyback1169"},
	{key=K({callId=0x6b}),    parser=P.Piggyback,            eventName="Piggyback116b"},
	{key=K({callId=0x5e}),    parser=P.SQLRequest,           eventName="SQLRequestEvent"},
	{key=K({code=2}),		  parser=P.Accept,               eventName="AcceptEvent"},
	{key=K({code=12}),        eventName="MarkerEvent"},
	{key=K({dataId=8,req=K({callId=0x76})}), parser=P.SessionResponse,   eventName="SessionResponseEvent"},
	{key=K({dataId=8,req=K({callId=0x3b})}), parser=P.VersionResponse,   eventName="VersionResponseEvent"},
	{key=K({code=12,req=K({callId=0x73})}),  eventName="AuthErrorEvent"},
}

local keyG=function(allBytes,pos,options,request)
    --if options is null use default value
	options=P.Options:new(options)
    local pktChkLen=(options:pktChk() and 2 or 0)
    local hdrChkLen=(options:hdrChk() and 2 or 0)
    local pktType=allBytes:byte(3+pktChkLen)
    local dataId,callId,key,keyStr
	if pktType==P.PacketType.DATA.code then dataId=allBytes:byte(7+pktChkLen+hdrChkLen) end
	if dataId==P.DataID.USER_OCI_FUNC.code or dataId==P.DataID.PIGGYBACK_FUNC.code then callId=allBytes:byte(8+pktChkLen+hdrChkLen) end
	return K({callId=callId,dataId=dataId,code=pktType,req=request})
end

function _M:new()
	local o= setmetatable({},{__index=self})
	local C2PParser=parser:new()
	C2PParser.keyGenerator=keyG
	C2PParser:registerMulti(conf)
	C2PParser:registerDefaultParser(P.Packet)
	o.C2PParser=C2PParser

	local S2PParser=parser:new()	
	S2PParser.keyGenerator=keyG
	S2PParser:registerMulti(conf)
	S2PParser:registerDefaultParser(P.Packet)
	o.S2PParser=S2PParser
	return o
end
return _M


