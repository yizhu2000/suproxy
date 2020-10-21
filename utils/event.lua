local _M={}
local logger=require "suproxy.utils.compatibleLog"
local function addHandler(self,context,...)
    local handlers={...}
    if #handlers ==0 then print("no handler was added to event") return  error("no handler was added to event")  end
    for k,v in ipairs(handlers) do
        table.insert(self.chain,{context=context,handler=v})
    end
end

function _M:new(source,name)
    local o={
        source=source,
        name=name,
        chain={},
    }
    o.addHandler=addHandler
    o.trigger=function(self,...)
        logger.logWithTitle(logger.DEBUG,string.format("event %s triggered",self.name),"")
        local args={...}
        for k,v in ipairs(self.chain) do
            v.handler(v.context,self.source,unpack(args))
        end
    end
    return setmetatable(o, {__index=self})
end

function _M:newReturnEvent(source,name)
    local o=_M:new(source,name)
    o.addHandler=function(self,context,...)
        assert(#(self.chain)==0,"returnEvent cannot has more than one handler")
        addHandler(self,context,...)
    end
    o.trigger=function(self,...)
		logger.logWithTitle(logger.DEBUG,string.format("event %s triggered",self.name),"")
        local args={...}
        for k,v in ipairs(self.chain) do
            return unpack{v.handler(v.context,self.source,unpack(args))}
        end
    end
    return o
end


function _M:setHandler(context,...)
    self.chain={}
    self:addHandler(context,...)
end

function _M:hasHandler()
    return #(self.chain)>0
end

_M.unitTest={}
function _M.test()
    local src={}
    src.eventA=_M:new(src)
    src.eventB=_M:newReturnEvent(src)
    local handlers={
        handle1=function(self,source,params)
            print("1 executed"..tostring(params))
            source.name=params
        end,
        handle2=function(self,source,params)
            print("2 executed"..tostring(params))
            self.name=params
        end,
        handle3=function(self,source,params)
            print("3 executed"..tostring(params))
        end,
    }
    src.eventA:addHandler(handlers,handlers.handle1,handlers.handle2,handlers.handle3)
    local result=src.eventA:trigger("0","lala")
    assert(src.name=="0",src.name)
    assert(handlers.name=="0",handlers.name)
    src.eventB:addHandler(src,function(self,source,params) source.name=params return "2",true end)
    local result1=src.eventB:trigger("0","la")
    assert(src.name=="0",src.name)
    assert(result1=="2",result)
    ok=pcall(src.eventB.addHandler,src.eventB,nil,function()end)
    assert(not ok)
end

return _M