local sub = string.sublocal byte = string.bytelocal format = string.formatlocal tcp = ngx.socket.tcplocal setmetatable = setmetatablelocal spawn = ngx.thread.spawnlocal wait = ngx.thread.waitlocal logger = require "suproxy.utils.compatibleLog"local ses= require "suproxy.session.session"local cjson=require "cjson"
local event=require "suproxy.utils.event"local balancer=require "suproxy.balancer.balancer"local _M={}

_M._VERSION = '0.01'


function _M:new(upstreams,processor,options)    local o={}    options =options or {}    options.c2pConnTimeout=options.c2pConnTimeout or 10000    options.c2pSendTimeout=options.c2pSendTimeout or 10000    options.c2pReadTimeout=options.c2pReadTimeout or 3600000    options.p2sConnTimeout=options.p2sConnTimeout or 10000    options.p2sSendTimeout=options.p2sSendTimeout or 10000    options.p2sReadTimeout=options.p2sReadTimeout or 3600000
    local c2pSock, err = ngx.req.socket()
    if not c2pSock then
        return nil, err
    end
    c2pSock:settimeouts(options.c2pConnTimeout , options.c2pSendTimeout , options.c2pReadTimeout)
    local standalone=false
    if(not upstreams) then
        logger.log(logger.ERR, format("[SuProxy] no upstream specified, Proxy will run in standalone mode"))
        standalone=true
    end
    local p2sSock=nil
    if(not standalone) then
        p2sSock, err = tcp()
        if not p2sSock then
            return nil, err
        end
        p2sSock:settimeouts(options.p2sConnTimeout , options.p2sSendTimeout , options.p2sReadTimeout )
    end
    --add default receive-then-forward processor
    if(not processor and not standalone) then
        processor={}
        processor.processUpRequest=function(self)
            local data, err, partial =self.channel:c2pRead(1024*10)            --real error happend or timeout            if not data and not partial and err then return nil,err end
            if(data and not err) then 
                return data 
            else 
                return partial
            end
        end
        processor.processDownRequest=function(self)
            local data, err, partial = self.channel:p2sRead(1024*10)            --real error happend or timeout            if not data and not partial and err then return nil,err end
            if(data and not err) then 
                return data 
            else 
                return partial
            end
        end
    end
    --add default echo processor if proxy in standalone mode
    if(not processor and standalone) then
        processor={}
        processor.processUpRequest=function(self)
            local data, err, partial =self.channel:c2pRead(1024*10)
            --real error happend or timeout            if not data and not partial and err then return nil,err end
            local echodata=""
            if(data and not err) then 
                echodata=data
            else      
                echodata=partial
            end
            logger.log(logger.INFO,echodata)
            local _,err=self.channel:c2pSend(echodata)
            logger.log(logger.ERR,partial)
        end
    end
    local upForwarder=function(self,data)
        if data then return self.channel:p2sSend(data) end
    end
    local downForwarder=function(self,data)
        if data then return self.channel:c2pSend(data) end
    end
    --add default upforwarder
    processor.sendUp=processor.sendUp or upForwarder
    --add default downforwarder
    processor.sendDown=processor.sendDown or downForwarder
        processor.ctx=processor.ctx or {}        local sessionInvalidHandler=function (self,session)        logger.log(logger.DEBUG,"session closed")        self:shutdown()    end    --set default session invalid handler    processor.sessionInvalid=processor.sessionInvalid or sessionInvalidHandler    --set AuthSuccessEvent handler    if processor.AuthSuccessEvent then        processor.AuthSuccessEvent:addHandler(o,function(self,source,username)             if self.session and username then self.session.uid=username end        end)    end    --update ctx info to session    if processor.ContextUpdateEvent then        processor.ContextUpdateEvent:addHandler(o,function(self,source,ctx)             if ctx and self.session then                self.session.ctx=ctx            end        end)    end    o.p2sSock=p2sSock    o.c2pSock=c2pSock    o.processor=processor    o.balancer=upstreams.getBest and upstreams or balancer:new(upstreams)    o.standalone=standalone    o.OnConnectEvent=event:new(o,"OnConnectEvent")    o.sessionMan=options.sessionMan or ses:newDoNothing()    setmetatable(o, { __index = self })    processor.channel=o    return o
end
local function _cleanup(self)
    logger.log(logger.DEBUG, format("[SuProxy] clean up executed"))
    -- make sure buffers are clean
    ngx.flush(true)
    local p2sSock = self.p2sSock
    local c2pSock = self.c2pSock
    if p2sSock ~= nil then
        if p2sSock.shutdown then
            p2sSock:shutdown("send")
        end
        if p2sSock.close ~= nil then
            local ok, err = p2sSock:setkeepalive()
            if not ok then
                --
            end
        end
    end
    
    if c2pSock ~= nil then
        if c2pSock.shutdown then
            c2pSock:shutdown("send")
        end
        if c2pSock.close ~= nil then
            local ok, err = c2pSock:close()
            if not ok then
                --
            end
        end
    end
    
end
local function _upl(self)
    -- proxy client request to server	local upstream=self.upstream
    local buf, err, partial    local session,err=ses:new(self.processor._PROTOCAL,self.sessionMan)    if err then        logger.log(logger.ERR, format("[SuProxy] start session fail: %s:%s, err:%s", upstream.ip, upstream.port, err))        return    end    self.processor.ctx.clientIP=ngx.var.remote_addr    self.processor.ctx.clientPort=ngx.var.remote_port    self.processor.ctx.srvIP=upstream.ip    self.processor.ctx.srvPort=upstream.port	self.processor.ctx.srvID=upstream.id	self.processor.ctx.srvGID=upstream.gid	self.processor.ctx.connTime=ngx.time()     session.ctx=self.processor.ctx    self.session=session    self.OnConnectEvent:trigger({clientIP=session.ctx.clientIP,clientPort=session.ctx.clientPort,srvIP=session.ctx.srvIP,srvPort=session.ctx.srvPort})
    while true do        --todo: sessionMan should notify session change        if not self.session:valid(self.session) 		then self.processor:sessionInvalid(self.session) 		else self.session.uptime=ngx.time() end        logger.log(logger.DEBUG,"client --> proxy start process")
        buf, err, partial = self.processor:processUpRequest(self.standalone)
        if err  then
            logger.log(logger.ERR, format("[SuProxy] processUpRequest fail: %s:%s, err:%s", upstream.ip, upstream.port, err))
            break
        end
        --if in standalone mode, don't forward
        if not self.standalone and buf then 
            local _, err = self.processor:sendUp(buf)
            if err then
            logger.log(logger.ERR, format("[SuProxy] forward to upstream fail: %s:%s, err:%s", upstream.ip, upstream.port, err))
                break
            end
        end
    end	self:shutdown(upstream)
end
local function _dwn(self)	local upstream=self.upstream
    -- proxy response to client
    local buf, err, partial
    while true do        logger.log(logger.DEBUG,"server --> proxy start process")
        buf, err, partial = self.processor:processDownRequest(self.standalone) 
        if err then
        logger.log(logger.ERR, format("[SuProxy] processDownRequest fail: %s:%s, err:%s", upstream.ip, upstream.port, err))
            break
        end
        if buf then
            local _, err = self.processor:sendDown(buf)
            if err then
            logger.log(logger.ERR, format("[SuProxy] forward to downstream fail: %s:%s, err:%s", upstream.ip, upstream.port, err))
                break
            end
        end
    end    self:shutdown(upstream)
endfunction _M:c2pRead(length)    local bytes,err,partial= self.c2pSock:receive(length) 	logger.logWithTitle(logger.DEBUG,"c2pRead",(bytes and bytes:hex16F() or ""))    return bytes,err,partial  endfunction _M:p2sRead(length)    local bytes,err,partial= self.p2sSock:receive(length)       logger.logWithTitle(logger.DEBUG,"p2sRead",(bytes and bytes:hex16F() or ""))    return bytes,err,partialendfunction _M:c2pSend(bytes)    logger.logWithTitle(logger.DEBUG,"c2pSend",(bytes and bytes:hex16F() or ""))    return self.c2pSock:send(bytes)endfunction _M:p2sSend(bytes)	logger.logWithTitle(logger.DEBUG,"p2sSend",(bytes and bytes:hex16F() or ""))    return self.p2sSock:send(bytes)end
function _M:run()	--this while is to ensure _cleanup will always be executed
    while true do		local upstream
        if(not self.standalone) then			while true do				upstream=self.balancer:getBest()				if not upstream then					logger.log(logger.ERR, format("[SuProxy] failed to get avaliable upstream"))					break				end
				local ok, err = self.p2sSock:connect(upstream.ip, upstream.port)
				if not ok then
					logger.log(logger.ERR, format("[SuProxy] failed to connect to proxy upstream: %s:%s, err:%s", upstream.ip, upstream.port, err))
					self.balancer:blame(upstream)
				else					logger.log(logger.INFO, format("[SuProxy] connect to proxy upstream: %s:%s", upstream.ip, upstream.port))					self.upstream=upstream					break				end			end
        end		if not self.standalone and not upstream then			break		end		--_singThreadRun(self)
        local co_upl = spawn(_upl,self)
        if(not self.standalone) then
            local co_dwn = spawn(_dwn,self) 
            wait(co_dwn)
        end
        wait(co_upl)
        break
    end
    _cleanup(self)
endfunction _M:shutdown()    if self.session then        --self.processor:sessionInvalid(self.session)		local err=self.session:kill(self.session) 		if err then			logger.log(logger.ERR, format("[SuProxy] kill session fail: %s:%s, err:%s", self.upstream.ip, self.upstream.port, err))		end    end    _cleanup(self)end

return _M
