require "suproxy.utils.stringUtils"
require "suproxy.utils.pureluapack"
local event=require "suproxy.utils.event"
local ok,cjson=pcall(require,"cjson")
if not ok then cjson = require("suproxy.utils.json") end
local logger=require "suproxy.utils.compatibleLog"
local tdsPacket=require "suproxy.tds.tdsPackets"
local tableUtils=require "suproxy.utils.tableUtils"local _M = {}
_M._PROTOCAL ='tds'

function _M.new(self,options)	
    local o= setmetatable({},{__index=self})
	options=options or {}
	o.disableSSL=true
	if options.disableSSL~=nil then o.disableSSL=options.disableSSL end
	o.catchReply=false
	if options.catchReply~=nil then o.catchReply=options.catchReply end
	o.BeforeAuthEvent=event:newReturnEvent(o,"BeforeAuthEvent")
	o.OnAuthEvent=event:newReturnEvent(o,"OnAuthEvent")
    o.AuthSuccessEvent=event:new(o,"AuthSuccessEvent")
    o.AuthFailEvent=event:new(o,"AuthFailEvent")
    o.CommandEnteredEvent=event:newReturnEvent(o,"CommandEnteredEvent")
    o.CommandFinishedEvent=event:new(o,"CommandFinishedEvent")  
    o.ContextUpdateEvent=event:new(o,"ContextUpdateEvent")
    o.ctx={}
	local tdsParser=require ("suproxy.tds.parser"):new(o.catchReply)
    o.C2PParser=tdsParser.C2PParser
    o.S2PParser=tdsParser.S2PParser
    o.C2PParser.events.SQLBatch:addHandler(o,_M.SQLBatchHandler)
    o.C2PParser.events.Prelogin:addHandler(o,_M.PreloginHandler)
    o.C2PParser.events.Login7:addHandler(o,_M.Login7Handler)
    o.S2PParser.events.LoginResponse:addHandler(o,_M.LoginResponseHandler)
	o.S2PParser.events.SSLLoginResponse:addHandler(o,_M.LoginResponseHandler)
	o.S2PParser.events.SQLResponse:addHandler(o,_M.SQLResponseHandler)
    return o
end
----------------parser event handlers----------------------
function _M:SQLBatchHandler(src,p)
    if self.CommandEnteredEvent:hasHandler() then
        local cmd,err=self.CommandEnteredEvent:trigger(p.sql,self.ctx)
        if err then
            self.channel:c2pSend(tdsPacket.packErrorResponse(err.message,err.code))
            p.allBytes=nil
            return
        end
    end
    ngx.ctx.sql=p.sql
end

function _M:PreloginHandler(src,p)
    if p.options.Encryption and self.disableSSL then
        p.options.Encryption=2
        --self.ctx.serverVer=p.options.Version.versionNumber
        p:pack()
    end
end

function _M:Login7Handler(src,p)
    local cred
    if self.BeforeAuthEvent:hasHandler() then
        cred=self.BeforeAuthEvent:trigger({username=p.username,password=p.password},self.ctx)
    end
	if self.OnAuthEvent:hasHandler() then
		local ok,message,cred=self.OnAuthEvent:trigger({username=p.username,password=p.password},self.ctx)
		if not ok then
			self.channel:c2pSend(tdsPacket.packErrorResponse(message or "login with "..p.username.." failed",18456))
			p.allBytes=nil
			return
		end
	end
    if cred and (p.username~=cred.username or p.password~=cred.password) then
		print(p.username,cred.username,p.password,cred.password)
        p.username=cred.username
        p.password=cred.password
        p:pack()
    end
    self.ctx.username=p.username
    self.ctx.client=p.appName
    self.ctx.clientVer=p.ClientProgVer:hex()
    self.ctx.libName=p.libName
    self.ctx.tdsVer=p.TDSVersion:hex()
    if self.ContextUpdateEvent:hasHandler() then
        self.ContextUpdateEvent:trigger(self.ctx)
    end
end

function _M:LoginResponseHandler(src,p)
    if p.success then
		if self.AuthSuccessEvent:hasHandler() then
			self.AuthSuccessEvent:trigger(self.ctx.username,self.ctx)
		end
		self.ctx.serverVer=p.serverVersion.versionNumber
		self.ctx.tdsVer=p.TDSVersion:hex()
		if self.ContextUpdateEvent:hasHandler() then
			self.ContextUpdateEvent:trigger(self.ctx)
		end
	else
		if self.AuthFailEvent:hasHandler() then
			self.AuthFailEvent:trigger({username=self.ctx.username,message="["..p.errNo.."]"..p.message},self.ctx)
		end
	end
end

function _M:SQLResponseHandler(src,p)
    if self.CommandFinishedEvent:hasHandler() then
        local reply=p.tostring and p:tostring() or ""
        reply=reply
        self.CommandFinishedEvent:trigger(ngx.ctx.sql,reply,self.ctx)
    end
end

----------------implement processor methods---------------------
local function recv(self,readMethod)
    local headerBytes,err,partial=readMethod(self.channel,8)    
    if(err) then
        logger.log(logger.ERR,"err when reading header",err)
        return partial,err 
    end    
    local packet=tdsPacket.Packet:new()
    local pos=packet:parseHeader(headerBytes)
    local payloadBytes,err,allBytes
    if(packet.code==0x17) then
        local _,_,_,dataLength=string.unpack(">BBBI2",headerBytes)
        payloadBytes,err=readMethod(self.channel,dataLength-3) 
        allBytes=headerBytes..payloadBytes
    else
        local dataLength=packet.dataLength
        payloadBytes,err=readMethod(self.channel,dataLength-8) 
        allBytes=headerBytes..payloadBytes
    end
    return allBytes
end

function _M.processUpRequest(self)
    local readMethod=self.channel.c2pRead
    local allBytes,err=recv(self,readMethod)
    if err then return nil,err end
    local p=self.C2PParser:parse(allBytes)
    ngx.ctx.upPacket=p.code
    return p.allBytes
end

function _M.processDownRequest(self)
    local readMethod=self.channel.p2sRead
    local allBytes,err=recv(self,readMethod)
    if err then return nil,err end
    local p =self.S2PParser:parse(allBytes,nil,ngx.ctx.upPacket)
    return p.allBytes
end

function _M:sessionInvalid(session)
    self.channel:c2pSend(tdsPacket.packErrorResponse("you are not allowed to connect, please contact the admin"))
    ngx.exit(0)
end

return _M
