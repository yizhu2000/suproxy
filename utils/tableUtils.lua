require "suproxy.utils.stringUtils"
local _M={}
local printFlag="___printted"
--format and print table in json style
function _M.printTableF(tab,options,layer,map)
    options=options or {}
    local printIndex=options.printIndex or false
    local layer=layer or 1
    local stopLayer=options.stopLayer or 0xffff
    local inline=options.inline or false
    local wrap= (not inline) and "\r\n" or ""
    local tabb= (not inline) and "\t" or ""
    local justLen=options.justLen or false
    local ascii=options.ascii or true
    local excepts=options.excepts or {}
    local map=map or {}
    local includes=options.includes
    local logStr=""
    if layer>stopLayer then return logStr end
    if type(tab)=="table" and  (not map[tostring(tab)]) then
        map[tostring(tab)]=""
        local i=1
        local isList=true
        local shortList=true
        for k, v in pairs(tab) do
            if k~=i then isList=false break end
            if type(v)=="table" then shortList=false end
            i=i+1
        end
        --no item in table
        if i==1 then isList,shortList =false,false end
        if not tab.__orderred then
            for k, v in pairs(tab) do
                local skip=false
                k=tostring(k)
                for _,e in ipairs(excepts) do
                    if k:match(e) then
                        skip=true
                        break
                    end
                end
                if includes then
                    local inWhiteList=false 
                    for _,e in ipairs(includes) do
                        if k:match(e) then
                            inWhiteList=true
                        end
                    end
                    skip=not inWhiteList
                end
                if not skip then
                    if not isList or not shortList then logStr=logStr..wrap..string.rep(tabb,layer) end
                    if not isList then logStr=logStr.."\""..k.."\":" end
                    --print(string.rep(" ",layer),k,":",tostring(v))
                    logStr=logStr.._M.printTableF(v,options,layer+1,map)
                    logStr=logStr..","
                end
            end 
        else
            for k, v in ipairs(tab) do
                local skip=false
                for _,e in ipairs(excepts) do
                    if v.key:match(e) then
                        skip=true
                        break
                    end
                end
                if includes then
                    local inWhiteList=false 
                    for _,e in ipairs(includes) do
                        if v.key:match(e) then
                            inWhiteList=true
                        end
                    end
                    skip=not inWhiteList
                end
                if  not skip then
                    if not isList or not shortList then logStr=logStr..wrap..string.rep(tabb,layer) end
                    if not isList then logStr=logStr.."\""..v.key.."\":" end
                    logStr=logStr.._M.printTableF(v.value,options,layer+1,map)
                    logStr=logStr.."," 
                end
            end 
        end
        if printIndex and getmetatable(tab) and getmetatable(tab).__index then 
            if not isList or not shortList then logStr=logStr..wrap..string.rep(tabb,layer) end
            if not isList then logStr=logStr.."\"__index\":" end
            logStr=logStr.._M.printTableF(getmetatable(tab).__index,options,layer+1,map).."," 
        end
        if #logStr >0 then logStr=logStr:sub(1,#logStr-1) end
        logStr=(isList and "[" or "{")..logStr
        if not isList or not shortList then logStr=logStr..wrap..string.rep(tabb,layer-1) end
        logStr=logStr..(isList and "]" or "}")..tostring(tab)
    elseif type(tab)=="string" then
        logStr="[Len:"..tab:len().."]"..logStr
        if not justLen then
            if #tab<40 then
                logStr=logStr.."\""..(ascii and tab:ascii(true) or tostring(tab)).."\"".."["..tab:hex().."]"
            else
                logStr=logStr..wrap..string.rep(tabb,layer-1).."\""..(ascii and tab:ascii(true) or tostring(tab)).."\""..wrap..string.rep(tabb,layer-1).."["..tab:hex().."]"
            end
        end
    elseif type(tab)=="number" then
        logStr=logStr..string.dec2hexF(tab) 
    else
        logStr=logStr..tostring(tab)
    end
	return logStr
end
--nil and table compatible concat
function _M.concat(tab,splitter)
	local rs={}
	for i=1,#tab do
		local v=tab[i]
		v = v or "nil"
		v=(type(v)=="table") and tostring(tab) or v
		rs[#rs +1]=v
	end
	return table.concat(rs,splitter)
end

--add index to table, then you can use the index to get item
function _M.addIndex(tab,key)
    local lookUps={}
    for k,v in pairs(tab) do lookUps[v[key]]=v end
    local index
    local mt
    repeat
        mt=getmetatable(tab)
        if mt then index=mt.__index tab=index end
    until not index
    setmetatable(tab,{__index=lookUps})
end

--imitate extends keyword in java
--copy parents method into subclass if not exists in subclass
--set __base as the base class
--limitation : any method add after extends method can't call sub class's override method
function _M.extends(o,parent)
	assert(o,"object can not be null")
	assert(parent,"parent can not be null")
	for k,v in pairs(parent) do
		if not o[k] then o[k]=v end
	end
    -- if not o.orderred then
        -- setmetatable(o,{__index=parent})
    -- else
        -- local index=getmetatable(o).__index
        -- setmetatable(index,{__index=parent})
    -- end
	o.__base=parent
	return o
end

--order table: item key can not be Number
_M.OrderedTable={
    new=function(self,o)
        local o=o or {}
        local k_i={}
        local meta={
            __index=self,
            __newindex=function(t,k,v) 
				assert(type(k)~="number") 
				rawset(k_i,k,#t+1)
				rawset(t,k,v) 
				rawset(t,#t+1,{key=k,value=v}) 
			end,
			__k_i=k_i
        }
        o.__orderred=true
        return setmetatable(o,meta)
    end,
    getIndex=function(self,k)
        assert(type(k)~="number") 
        local k_i=getmetatable(self).__k_i
        return k_i[k]
    end,
    getKVTable=function(self)
        local rs
        for i,v in ipairs(self) do
            rs[v.key]=v.value
        end 
        return rs
    end,
    remove=function(self,k)
        assert(type(k)~="number") 
        local k_i=getmetatable(self).__k_i
        local removeIndex=k_i[k]
        table.remove(self,removeIndex) 
        rawset(k_i,k,nil)
        rawset(self,k,nil)
        for i=removeIndex,#self do
          k_i[self[i].key]=i
        end
        return
    end
}



_M.unitTest={}
function _M.unitTest.OrderedTable()
	local t=_M.OrderedTable:new()
	t.A=1
	t.B=2
	t.C=3
	t.D=4
	t.E=5
	print(_M.printTableF(t))
	assert(t[1].key=="A",t[1].key)
	assert(t[2].key=="B",t[2].key)
	assert(t[3].key=="C",t[3].key)
	assert(#t==5,#t)
	t:remove("B")
	print(_M.printTableF(t)) 
	assert(t[1].key=="A",t[1].key)
	assert(t[2].key=="C",t[2].key)
	assert(t[3].key=="D",t[3].key)
	assert(#t==4)
end

function _M.unitTest.concat()
	local t={[1]=1,[2]="",[3]=nil,[4]="abc",[5]=4524354326}
	assert(_M.concat(t,";")=="1;;nil;abc;4524354326",_M.concat(t,";"))
end

function _M.test()
	for k,v in pairs(_M.unitTest) do
		print("------------running  "..k)
		v()
		print("------------"..k.."  finished")
	end
end

return _M