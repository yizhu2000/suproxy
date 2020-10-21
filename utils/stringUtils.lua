-- convert byte array to hex string with different format params
-- simplest way to call it is p:hex() where p is a bytearray
-- different param can be used to display ascii,header and mark specific bytes
-- eg.  from 1 to the end convert to hex, display ascii and pos header, mark 17th -- and 128th bytes out. every 4 bytes a column, 8 bytes a line.
-- print(p:hex(1,nil,4,8," ","    ",1,1,17,128))
-- 0000    FF FF FF FF    FF FF FF FF    ....    ....
-- 0008    C9 0F DA A2    21 68 C2 34    ....    !h.4
-- 0010    C4<- C6 62 8B    80 DC 1C D1    ..b.    ....
-- 0018    29 02 4E 08    8A 67 CC 74    ).N.    .g.t
-- 0020    02 0B BE A6    3B 13 9B 22    ....    ;.."
-- 0028    51 4A 08 79    8E 34 04 DD    QJ.y    .4..
-- 0030    EF 95 19 B3    CD 3A 43 1B    ....    .:C.
-- 0038    30 2B 0A 6D    F2 5F 14 37    0+.m    ._.7
-- 0040    4F E1 35 6D    6D 51 C2 45    O.5m    mQ.E
-- 0048    E4 85 B5 76    62 5E 7E C6    ...v    b^~.
-- 0050    F4 4C 42 E9    A6 37 ED 6B    .LB.    .7.k
-- 0058    0B FF 5C B6    F4 06 B7 ED    ..\.    ....
-- 0060    EE 38 6B FB    5A 89 9F A5    .8k.    Z...
-- 0068    AE 9F 24 11    7C 4B 1F E6    ..$.    |K..
-- 0070    49 28 66 51    EC E6 53 81    I(fQ    ..S.
-- 0078    FF FF FF FF    FF FF FF FF<-    ....    ....
function string.hex(self,pos,endpos,columnwidth,linewidth,bytespan,columnspan,ascii,header,...)
    local arg={...}
    local bytespan=bytespan or ""
    local columnspan=columnspan or "  "
    if(pos) then self=self:sub(pos,endpos) end
    local asciiStr=""
    local i=0
    local s=self:gsub("(.)",
    function (x) 
        local d=string.format("%02X",string.byte(x))
        if header and linewidth and i%linewidth==0  then
            d=string.format("%04x",i)..columnspan ..d
        end
        i=i+1 
        --mark bytes
        for j=1,#arg,1 do
            if(arg[j]==i) then d=d.."<-" end
        end
        --print ascii 
        if ascii then 
            if string.byte(x)>31 and string.byte(x)<127 then
                asciiStr=asciiStr..string.char(string.byte(x))
            else
                asciiStr=asciiStr.."."
            end
            if linewidth and i%linewidth==0  then
            elseif columnwidth and i%columnwidth==0  then
                asciiStr=asciiStr..columnspan
            end
        end
        if linewidth and (i%linewidth==0 or i==#self) then
            d=d..columnspan..asciiStr.."\n"
            asciiStr=""
        elseif columnwidth and i%columnwidth==0  then
            d=d..columnspan
        else 
            d=d..bytespan
        end
        return d
    end)
    return s
end

function string.random(byteNum) 
    local ok,rand=pcall(require,"resty.openssl.rand")
    if ok then return rand.bytes(byteNum) end
    local byteNum=byteNum or 4
    local result=""
    math.randomseed(ngx and ngx.time() or os.time())
    for i=1,byteNum,1 do
        result=result..string.pack("I1",math.random(0x7f))
    end
    return result
end

function string.split(self,splitter)
    local nFindStartIndex = 1
    local nSplitIndex = 1
    local nSplitArray = {}
    while true do
       local nFindLastIndex = string.find(self, splitter, nFindStartIndex)
       if not nFindLastIndex then
        nSplitArray[nSplitIndex] = string.sub(self, nFindStartIndex, string.len(self))
        break
       end
       nSplitArray[nSplitIndex] = string.sub(self, nFindStartIndex, nFindLastIndex - 1)
       nFindStartIndex = nFindLastIndex + string.len(splitter)
       nSplitIndex = nSplitIndex + 1
    end
    return nSplitArray
end

function string.ascii(self,noFormat)
	return self:gsub("." ,function(x)
		if (string.byte(x)<31 or string.byte(x)>127)  then
            if not noFormat and string.byte(x) ~= 0x09 and   string.byte(x) ~= 0x0a and    string.byte(x) ~= 0x0d     then
                return x
            end
            return "." 
        end
	end)
end
--same as hex(1,nil,4,8," ","    ",1,1,...)
function string.hexF(self,pos,endpos,...)
	pos=pos or 1
    return self:hex(pos,endpos,4,8," ","   ",1,1,...)
end
--same as hex(1,nil,8,16," ","    ",1,1,...)
function string.hex16F(self,pos,endpos,...)
	pos=pos or 1
    return self:hex(pos,endpos,8,16," ","   ",1,1,...)
end
--same as hex(1,nil,8,32," ","    ",1,1,...)
function string.hex32F(self,pos,endpos,...)
	pos=pos or 1
    return self:hex(pos,endpos,8,32," ","   ",1,1,...)
end
--decimal number to hex string
function string.dec2hex(input)
	assert(type(input)=="number","input must be a number")
	return string.format("0x%02X",input)
end
--decimal number to hex string and format as decimal[0x hex]
function string.dec2hexF(input)
	return tostring(input).."["..string.dec2hex(input).."]"
end

function string.literalize(str)
    local result=str:gsub("[%(%)%.%%%+%-%*%?%[%]%^%$]", function(c) return "%" .. c end)
    return result
end

function string.subPlain(str,plainPattern,repl)
    local p=plainPattern:literalize()
    local r=repl:literalize()
    return str:gsub(p,r)
end

function string.fromhex(value)
    local newValue=value:gsub("[^0-9a-fA-F]",function(x) return"" end)
    assert(#newValue%2 == 0,"value length % 2 must be 0")
    local rs=newValue:gsub("..",function(x) return string.char(tonumber(x,16))  end)
	return rs
end

function string.append(self,element,i)
   if not i then i=#self end
   if i<0 then i=0 end
   if i>#self then i=#self end
   if i==0 then return element..self,i+#element end
   if i==#self then return self..element,i+#element end
   return self:sub(1,i)..element..self:sub(i+1),i+#element
end

function string.trim(self,element)
    if #self<#element or not element then return self end
    local result=self;
    while result:sub(#result-#element+1)==element do
        result=result:sub(1,#result-#element)
    end
    while result:sub(1,#element)==element do
        result=result:sub(#element+1)
    end
    return result
end

function string.remove(self,i)
   if i<1 then i=1 end
   if i>#self then i=#self end
   return self:sub(1,i-1)..self:sub(i+1),i-1
end

function string.compare(value,value1)
    local i=1
    local result={}
    value:gsub("(.)",function(x) if x:byte()~=value1:byte(i) then table.insert(result,i) end i=i+1 end)
    return unpack(result)
end

function string.compareF(value,value1,pos,endpos)
	return "---------------------1-------------------------\r\n"
	..value:hexF(pos,endpos,value:compare(value1))
	.."\r\n----------------------2-----------------------\r\n"
	..value1:hexF(pos,endpos,value1:compare(value))
end

function string.compare16F(value,value1,pos,endpos)
	return "--------------------------------------1---------------------------------------\r\n"
	..value:hex16F(pos,endpos,value:compare(value1))
	.."\r\n--------------------------------------2---------------------------------------\r\n"
	..value1:hex16F(pos,endpos,value1:compare(value))
end

local b='ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/' -- You will need this for encoding/decoding
-- encoding
function string.base64Encode(data)
    return ((data:gsub('.', function(x) 
        local r,b='',x:byte()
        for i=8,1,-1 do r=r..(b%2^i-b%2^(i-1)>0 and '1' or '0') end
        return r;
    end)..'0000'):gsub('%d%d%d?%d?%d?%d?', function(x)
        if (#x < 6) then return '' end
        local c=0
        for i=1,6 do c=c+(x:sub(i,i)=='1' and 2^(6-i) or 0) end
        return b:sub(c+1,c+1)
    end)..({ '', '==', '=' })[#data%3+1])
end

-- decoding
function string.base64Decode(data)
    data = string.gsub(data, '[^'..b..'=]', '')
    return (data:gsub('.', function(x)
        if (x == '=') then return '' end
        local r,f='',(b:find(x)-1)
        for i=6,1,-1 do r=r..(f%2^i-f%2^(i-1)>0 and '1' or '0') end
        return r;
    end):gsub('%d%d%d?%d?%d?%d?%d?%d?', function(x)
        if (#x ~= 8) then return '' end
        local c=0
        for i=1,8 do c=c+(x:sub(i,i)=='1' and 2^(8-i) or 0) end
            return string.char(c)
    end))
end
