local P=require "suproxy.ldap.ldapPackets"
local parser=require("suproxy.parser")
local _M={}

local conf={
	{key=P.APPNO.BindRequest,     parser=P.BindRequest,      eventName="BindRequest"},
	{key=P.APPNO.UnbindRequest,   parser=P.UnbindRequest,    eventName="UnbindRequest"},
	{key=P.APPNO.SearchRequest,   parser=P.SearchRequest,    eventName="SearchRequest"},
	{key=P.APPNO.BindResponse,      parser=P.BindResponse,     eventName="BindResponse"},
	{key=P.APPNO.SearchResultEntry, parser=P.SearchResultEntry,eventName="SearchResultEntry"},
	{key=P.APPNO.SearchResultDone,  parser=P.SearchResultDone, eventName="SearchResultDone"},
}

local function keyG(allBytes,pos) 
	local p=P.Packet:new() p:parseHeader(allBytes,pos) return p.opCode
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

