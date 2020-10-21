require "suproxy.utils.stringUtils"
require "suproxy.utils.pureluapack"
local _M={}
function _M:new(stype,manager)
    assert(manager,"manager can not be null")
	local now=ngx.time()
    local session={sid=string.random(4):hex(),uptime=now,ctime=now,stype=stype,uid="_SUPROXY_UNKNOWN"}
	setmetatable(session,{__index=self})
    local sessionMeta={
        __index=session,
        __newindex=function(t,k,v) 
			local now=ngx.time()
			manager:setProperty(session.sid,k,v,"uptime",now) 
			t.__data[k]=v 
			t.__data.uptime=now
		end
    }
    manager:create(session)
    local proxy={__data=session,__manager=manager}
    return setmetatable(proxy,sessionMeta),nil
end

function _M:kill()
    return self.__manager:kill(self.sid)
end

function _M:valid()
	return self.__manager:valid(self.sid)
end

function _M.newDoNothing(self)
    return {
        create=function() return end,
        setProperty=function() return 1 end,
        valid=function() return true end,
        kill=function() return true end
    }
end

return _M