require "suproxy.utils.stringUtils"
require "suproxy.utils.pureluapack"
local event=require "suproxy.utils.event"
local logger=require "suproxy.utils.compatibleLog"
local tnsPackets=require "suproxy.tns.tnsPackets"
local tableUtils=require "suproxy.utils.tableUtils"
local crypt= require "suproxy.tns.crypt"local _M = {}
_M._PROTOCAL ='tns'

function _M.new(self,options)	
    options=options or {}
    local o= setmetatable({},{__index=self})  
    o.AuthSuccessEvent=event:new(o,"AuthSuccessEvent")
    o.AuthFailEvent=event:new(o,"AuthFailEvent")
    o.BeforeAuthEvent=event:newReturnEvent(o,"BeforeAuthEvent")
	o.OnAuthEvent=event:newReturnEvent(o,"OnAuthEvent")
    o.CommandEnteredEvent=event:newReturnEvent(o,"CommandEnteredEvent")
    o.CommandFinishedEvent=event:new(o,"CommandFinishedEvent") 
    o.ContextUpdateEvent=event:new(o,"ContextUpdateEvent")
    o.options=tnsPackets.Options:new()
    o.options.oracleVersion.major=options.oracleVersion or o.options.oracleVersion.major
    o.swapPass=options.swapPass or false
    o.ctx={}
	local tnsParser=require ("suproxy.tns.parser"):new()
    o.C2PParser=tnsParser.C2PParser
    o.C2PParser.events.ConnectEvent:setHandler(o,_M.ConnectHandler)
    o.C2PParser.events.AuthRequestEvent:setHandler(o,_M.AuthRequestHandler)
    o.C2PParser.events.SessionRequestEvent:setHandler(o,_M.SessionRequestHandler) 
    o.C2PParser.events.SetProtocolEvent:setHandler(o,_M.SetProtocolRequestHandler) 
    o.C2PParser.events.SQLRequestEvent:setHandler(o,_M.SQLRequestHandler)
    o.C2PParser.events.Piggyback1169:setHandler(o,_M.PiggbackHandler)
    o.C2PParser.events.Piggyback116b:setHandler(o,_M.PiggbackHandler)
    o.C2PParser.events.MarkerEvent:setHandler(o,_M.MarkerHandler)
    o.S2PParser=tnsParser.S2PParser
    o.S2PParser.events.SessionResponseEvent:setHandler(o,_M.SessionResponseHandler)
    o.S2PParser.events.VersionResponseEvent:setHandler(o,_M.VersionResponseHandler)
    o.S2PParser.events.SetProtocolEvent:setHandler(o,_M.SetProtocolResponseHandler) 
    o.S2PParser.events.AcceptEvent:setHandler(o,_M.AcceptHandler)
	o.S2PParser.events.AuthErrorEvent:setHandler(o,_M.AuthErrorHandler)
    return o
end

----------------parser event handlers----------------------
function _M:ConnectHandler(src,p)
    p:setTnsVersion(314)
    self.ctx.connStr=p:getConnStr()
    p:pack()
end

function _M:AcceptHandler(src,p)
    self.options.tnsVersion=p:getTnsVersion()
    self.options.headerCheckSum=p:checkHeader()
    self.options.packetCheckSum=p:checkPacket()
    self.ctx.tnsVer=p:getTnsVersion()
end

function _M:AuthRequestHandler(src,p)
    local ckey=p:getAuthKey()
    local skey=self.serverKey
    local tmpKey=self.tmpKey
    local salt=self.salt
    local pass=p:getPassword()
    local username=p:getUsername()
    if username ~= self.username then
        p:setUsername(self.username)
    end
    local passChanged=false
    if self.swapPass and self.tempPass ~= self.realPass then
        passChanged=true
        local ck
        local realpass=self.realPass
        if self.options.oracleVersion.major==11 then
            ck,pass=crypt:Decrypt11g(ckey,tmpKey,pass,self.tempPass,salt)
        elseif self.options.oracleVersion.major==10 then
            --ck,pass=crypt:Decrypt10g(ckey,tmpKey,pass,self.tempPass,salt)
        end
        if self.options.oracleVersion.major==11 or self.options.oracleVersion.major==10 then
            ckey,pass=crypt:Encrypt11g(realpass,ck,skey,salt)
            p:setAuthKey(ckey)
            p:setPassword(pass)
        end
    end
	if self.OnAuthEvent:hasHandler() then
		local ok,message=self.OnAuthEvent:trigger({username=username,password=self.tempPass},self.ctx)
		if not ok then
			--return marker1
			self.channel:c2pSend(tnsPackets.Marker1:pack())
			--return marker2
			self.channel:c2pSend(tnsPackets.Marker2:pack())
			self.responseError=true
			p.allBytes=nil
			return
		end
	end 
    if username ~= self.username or passChanged then
        p:pack()
    end
end

function _M:SessionRequestHandler(src,p) 
    self.options.program=p:getProgram()
    self.options.is64Bit=p:is64Bit()
    self.ctx.client=p:getProgram()
    self.username=p:getUsername()
    if self.BeforeAuthEvent:hasHandler() then
        local cred=self.BeforeAuthEvent:trigger({username=p:getUsername()},self.ctx)
        self.tempPass=cred.temppass
        self.realPass=cred.password
        self.username=cred.username
        self.tempUsername=p:getUsername()
    end
    self.ctx.username=self.username
    if self.ContextUpdateEvent:hasHandler() then
        self.ContextUpdateEvent:trigger(self.ctx)
    end
    p:setUsername(self.username)
    p:pack()
end

function _M:SetProtocolRequestHandler(src,p) 
    self.options.platform=p:getClientPlatform()
    self.ctx.clientPlatform=p:getClientPlatform()
end

function _M:SetProtocolResponseHandler(src,p) 
    self.options.srvPlatform=p:getClientPlatform()
    self.ctx.srvPlatform=p:getClientPlatform()
end

function _M:VersionResponseHandler(src,p)
    --todo find a better chance to trigger authSuccess
    if self.AuthSuccessEvent:hasHandler() then
        self.AuthSuccessEvent:trigger(self.ctx.username,self.ctx)
    end
    self.options.oracleVersion.major=p:getMajor()
    self.options.oracleVersion.minor=p:getMinor()
    self.options.oracleVersion.build=p:getBuild()
    self.options.oracleVersion.subbuild=p:getSub()
    self.options.oracleVersion.fix=p:getFix()
    self.ctx.serverVer=p:getVersion()
    if self.ContextUpdateEvent:hasHandler() then
        self.ContextUpdateEvent:trigger(self.ctx)
    end
end

function _M:SessionResponseHandler(src,p) 
    --if temp pass equals real pass then do nothing
    if self.tempPass==self.realPass or not self.swapPass then return end
    if self.options.oracleVersion.major==11 or self.options.oracleVersion.major==10 then
        self.serverKey=p:getAuthKey()
        self.salt=p:getSalt()
        local tmpKey=crypt:getServerKey(self.tempPass,self.realPass,self.serverKey,self.salt)
        self.tmpKey=tmpKey
        p:setAuthKey(tmpKey)
        p:pack()
    end
end

function _M:PiggbackHandler(src,p)
	if not p.__key then return end
	local entry=self.C2PParser.parserList[p.__key] 
	if entry and entry.event and entry.event:hasHandler() then 
		entry.event:trigger(p) 
	end
end

function _M:MarkerHandler(src,p) 
    --process req marker, if flag true then return error
    if self.responseError then
        self.channel:c2pSend(tnsPackets.NoPermissionError:new(self.options):pack())
        self.responseError=false
    end
    if self.sessionStop then
        self.channel:c2pSend(tnsPackets.NoPermissionError:new(self.options):pack())
        ngx.exit(0)
        return
    end
end

function _M:AuthErrorHandler(src,p)
	if self.AuthFailEvent:hasHandler() then
		self.AuthFailEvent:trigger({username=self.username},self.ctx)
	end
end

function _M:SQLRequestHandler(src,p)
    local command=p:getCommand()
    --if command=="altersession" then replace end
    if command and command:len()>0 then 
        local allBytes
        if self.CommandEnteredEvent:hasHandler() then
            local cmd,err=self.CommandEnteredEvent:trigger(command,self.ctx)
            if err then
                --set a flag indicate error happen
                self.responseError=true
                --return marker1
                self.channel:c2pSend(tnsPackets.Marker1:pack())
                --return marker2
                self.channel:c2pSend(tnsPackets.Marker2:pack())
                p.allBytes=nil
                return
            end
            if cmd and cmd~=command then
                command=cmd
                p:setCommand(cmd)
                p:pack()
            end
        end
        --if username was changed during login, alter session sql sent by client should be update to real username
        if self.tempUsername ~= self.username then
            if command:match("ALTER SESSION SET CURRENT_SCHEMA") then
                command=command:gsub("%= .*","%= "..self.username:literalize())
                p:setCommand(command)
                p:pack()
            end
        end
        
        if self.CommandFinishedEvent:hasHandler() then
            self.CommandFinishedEvent:trigger(command,"",self.ctx)
        end
    end
end

-------------implement processor methods---------------
function _M.processUpRequest(self)
    local readMethod=self.channel.c2pRead
    local allBytes,err=self:recv(readMethod)
	if err then return nil,err end
    local p=self.C2PParser:parse(allBytes,nil,nil,self.options)
    self.request=p.__key
    return p.allBytes
end

function _M.processDownRequest(self)
    local readMethod=self.channel.p2sRead
    local allBytes,err= self:recv(readMethod)
	if err then return nil,err end
    --if request is oci function call , then set options and wait for respond
	local ociCall
	if self.request then
		ociCall= self.request:match("callId") and self.request or nil
	end
	local p=self.S2PParser:parse(allBytes,nil,nil,self.options,ociCall)
    return p.allBytes
end

function _M:recv(readMethod)
    local lengthdata,err=readMethod(self.channel,2)    
    if(err) then
        logger.log(logger.ERR,"err when reading length")
        return nil,err 
    end
    local pktLen=string.unpack(">I2",lengthdata)
    local data,err=readMethod(self.channel,pktLen-2)
    if(err) then 
        logger.log(logger.ERR,"err when reading packet")
        return nil,err 
    end
    local allBytes=lengthdata..data
    return  allBytes
end

function _M:sessionInvalid(session)
    --return marker1
    self.channel:c2pSend(tnsPackets.Marker1:pack())
    --return marker2
    self.channel:c2pSend(tnsPackets.Marker2:pack())
    self.sessionStop=true
end

return _M
