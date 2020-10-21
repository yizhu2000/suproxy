local asn1 = require("suproxy.utils.asn1")local format = string.formatlocal ok,cjson=pcall(require,"cjson")
if not ok then cjson = require("suproxy.utils.json") end
local logger=require "suproxy.utils.compatibleLog"local bunpack = asn1.bunpacklocal fmt = string.format
require "suproxy.utils.stringUtils"
local tableUtils=require "suproxy.utils.tableUtils"local pureluapack=require"suproxy.utils.pureluapack"
local event=require "suproxy.utils.event"
local ldapPackets=require "suproxy.ldap.ldapPackets"local ResultCode=ldapPackets.ResultCode
local _M = {}
_M._PROTOCAL ='ldapv3'
local encoder,decoder=asn1.ASN1Encoder:new(),asn1.ASN1Decoder:new()
function _M:new()    
    local o= setmetatable({},{__index=self})
    o.ctx={}
    o.AuthSuccessEvent=event:new(o,"AuthSuccessEvent")
    o.AuthFailEvent=event:new(o,"AuthFailEvent")
    o.BeforeAuthEvent=event:newReturnEvent(o,"BeforeAuthEvent")	o.OnAuthEvent=event:newReturnEvent(o,"OnAuthEvent")
    o.CommandEnteredEvent=event:newReturnEvent(o,"CommandEnteredEvent")
    o.CommandFinishedEvent=event:new(o,"CommandFinishedEvent") 
    o.ContextUpdateEvent=event:new(o,"ContextUpdateEvent")	local ldapParser=require ("suproxy.ldap.parser"):new()
    o.c2pParser=ldapParser.C2PParser
    o.s2pParser=ldapParser.S2PParser
    o.c2pParser.events.SearchRequest:setHandler(o,_M.SearchRequestHandler)
    o.c2pParser.events.BindRequest:setHandler(o,_M.BindRequestHandler)
    o.c2pParser.events.UnbindRequest:setHandler(o,_M.UnbindRequestHandler)
    o.s2pParser.events.BindResponse:setHandler(o,_M.BindResponseHandler)
    o.s2pParser.events.SearchResultEntry:setHandler(o,_M.SearchResultEntryHandler)
    o.s2pParser.events.SearchResultDone:setHandler(o,_M.SearchResultDoneHandler)
    return o
end
----------------parser event handlers----------------------
function _M:SearchRequestHandler(src,p)
    local cstr=cjson.encode{baseObject=p.baseObject,scope=p.scope,filter=p.filter}
    if self.CommandEnteredEvent:hasHandler() then
        local cmd,err=self.CommandEnteredEvent:trigger(cstr,self.ctx)
        if err then p.allBytes=nil return end
        if cmd.command~=p.filter then 
            --todo: modify the filter
        end
    end
    self.command=cstr
end

function _M:BindRequestHandler(src,p)
    local cred
    if self.BeforeAuthEvent:hasHandler() then
        cred=self.BeforeAuthEvent:trigger({username=p.username,password=p.password},self.ctx)
    end	if self.OnAuthEvent:hasHandler() then		local ok,message,cred=self.OnAuthEvent:trigger({username=p.username,password=p.password},self.ctx)		if not ok then			local resp=ldapPackets.BindResponse:new({                messageId=p.messageId,                resultCode=ResultCode.invalidCredentials            }):pack()			self.channel:c2pSend(resp.allBytes)			p.allBytes=nil			return		end	end 
    if cred and (p.username~=cred.username or p.password~=cred.password) then
        p.username=cred.username
        p.password=cred.password
        p:pack()
    end	
    self.ctx.username=p.username  
    if self.ContextUpdateEvent:hasHandler() then
        self.ContextUpdateEvent:trigger(self.ctx)
    end
end

function _M:BindResponseHandler(src,p)
    if p.resultCode==ResultCode.success then
        if self.AuthSuccessEvent:hasHandler() then
            self.AuthSuccessEvent:trigger(self.ctx.username,self.ctx)
        end
    else
        if self.AuthFailEvent:hasHandler() then
            self.AuthFailEvent:trigger({username=self.ctx.username,message="fail code: "..tostring(p.resultCode)},self.ctx)
        end 
    end
end

function _M:SearchResultEntryHandler(src,p)
    self.reply=(self.reply or "")..cjson.encode({p.objectName,p.attributes}).."\r\n"
end
    
function _M:SearchResultDoneHandler(src,p) 
    if self.CommandFinishedEvent:hasHandler() then
        self.CommandFinishedEvent:trigger(self.command,self.reply,self.ctx)
    end
    self.reply=""
end
    
function _M:UnbindRequestHandler(src,p)
    ngx.exit(0)  
end

function _M:recv(readMethod)
    logger.log(logger.DEBUG,"start processRequest")   
    local lengthdata,err = readMethod(self.channel,2)    
    if(err) then 
        logger.log(logger.ERR,"err when reading length")
        return nil,err 
    end
    local length=("B"):unpack(lengthdata,2)
    local len_len=length-128
    local realLengthData=""
    if len_len>0 then
        realLengthData,err=readMethod(self.channel,len_len)
        if(err) then 
            logger.log(logger.ERR,"err when reading real length")
            return nil,err 
        end
        length=(">I"..len_len):unpack(realLengthData)
    end
    local payloadBytes,err = readMethod(self.channel,length)
    local allBytes=lengthdata..realLengthData..payloadBytes
    if(err) then 
        logger.log(logger.ERR,"err when reading packet")
        return nil,err 
    end
    return allBytes
end----------------implement processor methods---------------------
function _M.processUpRequest(self)
    local allBytes,err=self:recv(self.channel.c2pRead)	if err then return nil,err end
    local p=self.c2pParser:parse(allBytes)
    return p.allBytes
end

function _M.processDownRequest(self)
    local allBytes,err=self:recv(self.channel.p2sRead)	if err then return nil,err end
    local p=self.s2pParser:parse(allBytes)
    return p.allBytes
end

function _M:sessionInvalid(session)
    ngx.exit(0)
end

return _M;
