require "suproxy.utils.stringUtils"
require "suproxy.utils.pureluapack"
local _M = {}
function _M.new(self)
    local o={}
    o.cursor=0
    o.chars={}
    return setmetatable(o, {__index=self})
end
local function rshiftArray(tab,cursor,count)
    for i=#tab,cursor,-1 do
        tab[i+count]=tab[i]
    end
    return tab
end

function _M.append(self,str)
    local i=1
    while i<=#str do
        local c=string.byte(str,i)
        self.chars=rshiftArray(self.chars,self.cursor,1)
        if c>0xF0 then
            self.chars[self.cursor+1]=str:sub(i,i+3)
            i=i+4
        elseif c>0xE0 then
            --unicode
            self.chars[self.cursor+1]=str:sub(i,i+2)
            i=i+3
        elseif c>0xC0 then
            self.chars[self.cursor+1]=str:sub(i,i+1)
            i=i+2
        else
            self.chars[self.cursor+1]=str:sub(i,i)
            i=i+1
        end
        self.cursor=self.cursor+1
    end
end

function _M.removeBefore(self,count,all)
    if all then count=self.cursor end
    if not count then count=1 end
    if self.cursor<1 then return end
    if self.cursor-count<0 then count= self.cursor end
    for i=1, count, -1 do
        table.remove(self.chars,self.cursor)
    end
    self.cursor=self.cursor-count
end

function _M.clear(self)
    self.cursor=0
    self.chars={}
end

function _M.removeAfter(self,count,all)
    if all then count= #(self.chars)-self.cursor end
    if not count then count=1 end
    if self.cursor==#(self.chars) then return end
    if self.cursor+count>#(self.chars) then count= #(self.chars)-self.cursor end
    for i=1,count,1 do
        table.remove(self.chars,self.cursor)
    end
end

function _M.home(self)
    self.cursor=0
end

function _M.toEnd(self)
    self.cursor=#(self.chars)
end

function _M.moveCursor(self,step)
    if self.cursor+step>#(self.chars) then
        self.cursor=#(self.chars) return  
    elseif self.cursor+step<0 then
        self.cursor=0 return
    end
    self.cursor=self.cursor+step
end

function _M.getLength(self) 
    return #(self.chars)
end

function _M.get(self,pos) 
    if pos>#(self.chars) or pos<1 then return nil end
    return self.chars[pos]
end

function _M.toString(self)
    -- local result=""
    -- for k, v in pairs(self.chars) do
        -- result=result..v
    -- end
    -- return result
    return table.concat(self.chars)
end

function _M.test()
    local str="中华A已经Bあまり哈哈哈1234567"
    print(str:hex())
    local shellCommand=_M
    local command=shellCommand:new()
    command:append(str)
    assert(command:getLength()==19,command:getLength())
    assert(command:get(1)=="中",command:get(1))
    assert(command:get(19)=="7",command:get(19))
    assert(command.cursor==19,command.cursor)
    command:moveCursor(-100)
    command:moveCursor(100)
    command:moveCursor(-2)
    assert(command.cursor==17,command.cursor)
    command:removeAfter()
    command:removeAfter()
    command:removeAfter()
    command:removeAfter()
    command:removeAfter()
    command:removeBefore()
    assert(command.cursor==16,command.cursor)
    assert(command:toString()=="中华A已经Bあまり哈哈哈1234",command:toString():hex())
    command:clear()
    command:append("34")
    command:moveCursor(-2)
    command:append("12")
    assert(command:toString()=="1234",command:toString())
    command:home()
    assert(command.cursor==0,command.cursor)
    command:toEnd()
    assert(command.cursor==command:getLength(),command.cursor)
    print(command:toString())
end

return _M

