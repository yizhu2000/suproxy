require "suproxy.utils.stringUtils"
local event=require "suproxy.utils.event"
local logger=require "suproxy.utils.compatibleLog"
local tableUtils=require "suproxy.utils.tableUtils"
local _M={}
function _M:new()
    local o=setmetatable({},{__index=self})
    o.events={}
    o.parserList={}
    o.defaultParseEvent=event:newReturnEvent(nil,"defaultParseEvent")
    return o
end

function _M:register(key,parserName,parser,eventName,e)
    assert(not self.parserList[key],string.format("unable to register parser %s, key already registered",key))
    if eventName then 
        assert(not self.events[eventName],string.format("unable to register event %s, event already registered",eventName)) 
        e=e or event:new(nil,eventName) 
        self.events[eventName]=e
    end
    self.parserList[key]={parser=parser,parserName=parserName,event=e}
end

function _M:unregister(key,eventName)
	self.parserList[key]=nil
	if eventName then
		self.events[eventName]=nil
	end
end

function _M:getParser(key)
    return self.parserList[key]
end

function _M:registerMulti(t)
    for i,v in ipairs(t) do
		local parserName
		if v.parser then parserName=v.parserName or v.parser.desc or tostring(v.parser) end
        self:register(v.key,parserName,v.parser,v.eventName,v.e)
    end
end

function _M:registerDefaultParser(parser)
	assert(parser,"default parser can not be null")
    self.defaultParser=parser
end

function _M.printPacket(packet,allBytes,key,parserName,...)
    local args={...}
	if not parserName then
		logger.logWithTitle(logger.DEBUG,string.format("packet with key %s doesn't have parser",key),(allBytes and allBytes:hex16F() or ""))
	else
		logger.logWithTitle(logger.DEBUG,string.format("packet with key %s will be parsed by parser %s ",key,parserName or "Unknown"),(allBytes and allBytes:hex16F() or ""))
	end
    for i,v in ipairs(args) do
        logger.log(logger.DEBUG,"\r\noptions"..i..":"..tableUtils.printTableF(v,{inline=true,printIndex=true}))
    end
    logger.log(logger.DEBUG,"\r\npacket:"..tableUtils.printTableF(packet,{ascii=true,excepts={"allBytes"}}))
end

--static method to  parse all kinds of packets
function _M:parse(allBytes,pos,key,...)
	pos=pos or 1
	assert(allBytes,"bytes stream can not be null")
    if not key then key=self.keyGenerator end
    if type(key)=="function" then
        key=key(allBytes,pos,...)
    end
    assert(key,"key can not be null")
    local packet={}
	packet.allBytes=allBytes
    local parser,event,newBytes,parserName
    if self.parserList[key] then
        parser=self.parserList[key].parser
		parserName=self.parserList[key].parserName
        if self.parserList[key].event then
            event=self.parserList[key].event
        end
    end
	if not parser and self.defaultParser then
		parser=self.defaultParser
		parserName="Default Parser"
	end
    event=event or self.defaultParseEvent
    local args={...}
    local ok=true 
	local ret
    if parser then
        ok,ret=xpcall(function() return parser:new(nil,unpack(args)):parse(allBytes,pos,unpack(args))end,function(err) logger.log(logger.ERR,err) logger.log(logger.ERR,debug.traceback()) end,"error when parsing ")
        if ok then packet= ret end
    end
    if logger.getLogLevel().code>=logger.DEBUG.code then
        _M.printPacket(packet,allBytes,key,parserName,...)
    end
    packet.__key=packet.__key or key
    if ok and event and event:hasHandler() then 
        xpcall(function() return event:trigger(packet,allBytes,key,unpack(args)) end,function(err) logger.log(logger.ERR,err) logger.log(logger.ERR,debug.traceback()) end,"error when exe parser handler " )
    end
    return packet
end
_M.doParse=doParse
return _M