local bit=require("bit")require "suproxy.utils.stringUtils"local _INTLEN=4local _DEFAULT_ENDIAN="<"
local function packDouble (e,l,n)	local result    local sign = 0    if n < 0.0 then        sign = 0x80        n = -n    end    local mant, expo = math.frexp(n)    if mant ~= mant then        result = string.char( 0xFF, 0xF8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)    elseif mant == math.huge then        if sign == 0 then            result = string.char( 0x7F, 0xF0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)        else            result = string.char(0xFF, 0xF0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)        end    elseif mant == 0.0 and expo == 0 then       result = string.char(sign, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)    else        expo = expo + 0x3FE        mant = (mant * 2.0 - 1.0) * math.ldexp(0.5, 53)        local x=(expo % 0x10) * 0x10 + math.floor(mant / 0x1000000000000)        print(tostring(x))        result = string.char(                                 sign + math.floor(expo / 0x10),                                 (expo % 0x10) * 0x10 + math.floor(mant / 0x1000000000000),                                 math.floor(mant / 0x10000000000) % 0x100,                                 math.floor(mant / 0x100000000) % 0x100,                                 math.floor(mant / 0x1000000) % 0x100,                                 math.floor(mant / 0x10000) % 0x100,                                 math.floor(mant / 0x100) % 0x100,                                 mant % 0x100)    end	if e=="<" then		result=result:reverse()	end	return resultendlocal function unpackDouble (e,l,s)    local rs=s:sub(1,l)	if e=="<" then rs=rs:reverse() end    local b1, b2, b3, b4, b5, b6, b7, b8 = rs:byte(1, 8)    local sign = b1 > 0x7F    local expo = (b1 % 0x80) * 0x10 + math.floor(b2 / 0x10)    local mant = ((((((b2 % 0x10) * 0x100 + b3) * 0x100 + b4) * 0x100 + b5) * 0x100 + b6) * 0x100 + b7) * 0x100 + b8    if sign then        sign = -1    else        sign = 1    end    local n    if mant == 0 and expo == 0 then        n = sign * 0.0    elseif expo == 0x7FF then        if mant == 0 then            n = sign * huge        else            n = 0.0/0.0        end    else        n = sign * math.ldexp(1.0 + mant / 0x10000000000000, expo - 0x3FF)    end    return n,9endlocal function packNumber(e,length,k)
    if(k<0) then k=256^length+k end
    local rs=""
	local i=0
    while (k>=1) do
        local t=k%256
        if(e==">" ) then rs=string.char(t)..rs end
        if(e=="<" or e==nil or e=="=") then rs=rs..string.char(t) end
        k=bit.rshift(k,8) 
        i=i+1
    end
    if i>length then return nil end
	while i<length do
        if(e==">" ) then rs=string.char(0)..rs end
        if(e=="<" or e==nil or e=="=") then rs=rs..string.char(0) end
        i=i+1
	end
	return rs
end

local function packLengthPreStr(e,l,value)

    local strLen=string.len(value)

	return packNumber(e,l,strLen)..value
end
local function packLengthStr(e,l,value)

    local strLen=string.len(value)
    
    for i=strLen,l-1,1 do
        
        value=value..string.char(0)
    end

	return value
end
local function packZeroEndStr(e,l,value)

	return value..string.char(0)
end
local function unpackNumber(endian,length,Str)
    local rs=Str:sub(1,length)
    if(endian==">")then
        rs=rs:reverse()
    end
    local i=1
    local result=string.byte(rs,1)
    while i+1<=length do
        result=result+string.byte(rs,i+1)*(256^i)
        i=i+1
    end
    
	return math.floor(result),i+1
end
local function unpackSignedNumber(endian,length,Str)
    local result,pos=unpackNumber(endian,length,Str) 
    --minus value
    if result >= (256^length)/2 then
        result = result - 256^length
    end
    
	return result,pos
end
local function unpackLengthPreStr(e,l,value)
    
    local strLen=unpackNumber(e,l,value)
    
	return value:sub(l+1,l+strLen),l+strLen+1
end
local function unpackLengthStr(e,l,value)
    return value:sub(1,l),l+1
end
local function unpackZeroEndStr(e,l,value)
    local i=1;
    while(i<=#value and string.byte(value,i)~=0) do i=i+1 end
    return value:sub(1,i-1),i+1
end
local function getLen(t,l)    local _t={        ["B"]=1,        ["b"]=1,        ["H"]=2,        ["h"]=2,		["d"]=8,		["f"]=4,        ["s"]=1,        ["I"]=_INTLEN,        ["i"]=_INTLEN    }    if(not l  ) then l=_t[t] end    return lend
function string.pack(fmt,...)
    local arg={...}
    assert(type(fmt)=="string","bad argument #1 to 'pack' (string expected, got "..type(fmt)..")")
    local rs=""
    local i=1
    local nativeEndian=_DEFAULT_ENDIAN
    for w,e,t,l in fmt:gmatch("(([<>=]?)([bBhH1LjJTiIfdnczsxX])([%d]*))") do
        l=tonumber(l)
        if(e:len()~=0) then nativeEndian=e end
        if(t=="I" or t=="B" or t=="H") then
            l=getLen(t,l)
            assert(type(arg[i]) == "number", "bad argument #"..(i+1).." to 'pack' (number expected, got "..type(arg[i])..")")
            assert(arg[i]<=256^l-1,"bad argument #"..(i+1).." to 'pack' (unsign integer overflow)")
            rs=rs..packNumber(nativeEndian,l,arg[i])
        elseif(t=="i" or t=="b" or t=="h") then
            l=getLen(t,l)
            assert(type(arg[i]) == "number", "bad argument #"..(i+1).." to 'pack' (number expected, got "..type(arg[i])..")")
            assert(arg[i]<256^l/2 and arg[i]>=-256^l/2,"bad argument #"..(i+1).." to 'pack' (signed interger overflow)")
            rs=rs..packNumber(nativeEndian,l,arg[i])		elseif(t=="d") then            l=getLen(t,l)            assert(type(arg[i]) == "number", "bad argument #"..(i+1).." to 'pack' (number expected, got "..type(arg[i])..")")            rs=rs..packDouble(nativeEndian,l,arg[i])
        elseif(t=="s") then
            assert(type(arg[i]) == "string", "bad argument #"..(i+1).." to 'pack' (string expected, got "..type(arg[i])..")")
            l=getLen(t,l)
            rs=rs..packLengthPreStr(nativeEndian,l,arg[i])
        elseif(t=="c") then
            assert(type(arg[i]) == "string", "bad argument #"..(i+1).." to 'pack' (string expected, got "..type(arg[i])..")")
            assert(l,"missing size for format option 'c'")
            rs=rs..packLengthStr(nativeEndian,l,arg[i])
        elseif(t=="z") then
            assert(type(arg[i]) == "string", "bad argument #"..(i+1).." to 'pack' (string expected, got "..type(arg[i])..")")
            rs=rs..packZeroEndStr(nativeEndian,l,arg[i])
        else
            error("invalid format option '"..t)
        end
        i=i+1
    end

    return rs
end


function string.unpack(fmt,value,pos)

    assert(type(fmt)=="string","bad argument #1 to 'unpack' (string expected, got "..type(fmt)..")")
    assert(type(value)=="string","bad argument #2 to 'unpack' (string expected, got "..type(value)..")")
    if(pos) then  assert(pos>=1 and pos<=value:len()+1,"pos invalid") end
    local rs={}
    local i=1
    if(pos)then i=pos end
    local nativeEndian=_DEFAULT_ENDIAN
    for w,e,t,l in fmt:gmatch("(([<>=]?)([bBhH1LjJTiIfdnczsxX])([%d]*))") do
        l=tonumber(l)
        if(e:len()~=0) then nativeEndian=e end
        local segment=value:sub(i)
        local ps,index
        if(t=="I" or t=="B" or t=="H") then
            l=getLen(t,l)            assert(l>=1,"size out of limit")
            assert(segment:len()>=l,"bad argument #2 to 'unpack' (data string too short)")
            ps,index=unpackNumber(nativeEndian,l,segment)
        elseif(t=="i" or t=="b" or t=="h") then
            l=getLen(t,l)
            assert(segment:len()>=l,"bad argument #2 to 'unpack' (data string too short)")
            ps,index=unpackSignedNumber(nativeEndian,l,segment)		elseif(t=="d") then            l=getLen(t,l)            assert(segment:len()>=l,"bad argument #2 to 'unpack' (data string too short)")            ps,index=unpackDouble(nativeEndian,l,segment)
        elseif(t=="s") then
            l=getLen(t,l)
            assert(segment:len()>=l,"bad argument #2 to 'unpack' (data string too short)")
            ps,index=unpackLengthPreStr(nativeEndian,l,segment)
        elseif(t=="c") then
            ps,index=unpackLengthStr(nativeEndian,l,segment)
            assert(segment:len()>=l,"bad argument #2 to 'unpack' (data string too short)")
        elseif(t=="z") then
            ps,index=unpackZeroEndStr(nativeEndian,l,segment)
        else
            error("invalid format option '"..t)
        end
        
        table.insert(rs,ps)
        i=i+index-1            
    end
    table.insert(rs,i)
    return unpack(rs)
end
local _M={}
function _M.test()
    local k=string.pack(">I4BHs1<s2 I2 I c3 z <i1",1,2,3,"123","abc",79,79,"1","22",-128)
    print(k:hex())
    assert(k==string.char(0x00,0x00,0x00,0x01,0x02,0x00,0x03,0x03,0x31,0x32,0x33,0x03,0x00,0x61,0x62,0x63,0x4F,0x00,0x4F,0x00,0x00,0x00,0x31,0x00,0x00,0x32,0x32,0x00,0x80))
    local v1,v2,v3,v4,v5,v6,v7,v8,v9,v10,v11=string.unpack(">I4BHs1<s2 I2 I c3 z <i1",k)
    print(v1,v2,v3,v4,v5,v6,v7,string.hex(v8),v9,v10,v11)

    assert(v1==1)
    assert(v2==2)
    assert(v3==3)
    assert(v4=="123")
    assert(v5=="abc")
    assert(v6==79)
    assert(v7==79)
    assert(v8==string.char(0x31,0x00,0x00))
    assert(v9=="22")
    assert(v10==-128)

    local m=string.pack("I4Bh>s2",673845,2,-200,"123")
    print(string.hex(m))
    --add some useless byte on start to test pos params
    m=string.char(0x2,0x3,0xff,0x00)..m
    local v1,v2,v3,v4,v5=string.unpack("I4Bh>s2",m,5)
    print(v1,v2,v3,v4,v5)
    assert(v1==673845)
    assert(v2==2)
    assert(v3==-200)
    assert(v4=="123")
    
    p=string.fromhex([[
    FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1
    29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD
    EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245
    E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED
    EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE65381
    FFFFFFFF FFFFFFFF
    ]])
    q="FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF"
    assert(p:hex()==q,"fromhex err")
    print(p:hex(1,nil,4,8," ","    ",1,1,12))
    p=string.fromhex("140000002900004823000018BE000067840000012E637572766532353531392D736861323536406C69627373682E6F72672C656364682D736861322D6E697374703235362C656364682D736861322D6E697374703338342C656364682D736861322D6E697374703532312C6469666669652D68656C6C6D616E2D67726F75702D65786368616E67652D7368613235362C6469666669652D68656C6C6D616E2D67726F75702D65786368616E67652D736861312C6469666669652D68656C6C6D616E2D67726F757031382D7368613531322C6469666669652D68656C6C6D616E2D67726F757031362D7368613531322C6469666669652D68656C6C6D616E2D67726F757031342D7368613235362C6469666669652D68656C6C6D616E2D67726F757031342D736861312C6469666669652D68656C6C6D616E2D67726F7570312D73686131000000717373682D7273612C7273612D736861322D3235362C7273612D736861322D3531322C7373682D6473732C65636473612D736861322D6E697374703235362C65636473612D736861322D6E697374703338342C65636473612D736861322D6E697374703532312C7373682D656432353531390000011963686163686132302D706F6C7931333035406F70656E7373682E636F6D2C6165733132382D6374722C6165733139322D6374722C6165733235362D6374722C6165733132382D67636D406F70656E7373682E636F6D2C6165733235362D67636D406F70656E7373682E636F6D2C6165733132382D6362632C6165733139322D6362632C6165733235362D6362632C336465732D6362632C626C6F77666973682D6362632C636173743132382D6362632C617263666F75722C72696A6E6461656C3132382D6362632C72696A6E6461656C3139322D6362632C72696A6E6461656C3235362D6362632C72696A6E6461656C2D636263406C797361746F722E6C69752E73652C617263666F75723132382C617263666F75723235360000011963686163686132302D706F6C7931333035406F70656E7373682E636F6D2C6165733132382D6374722C6165733139322D6374722C6165733235362D6374722C6165733132382D67636D406F70656E7373682E636F6D2C6165733235362D67636D406F70656E7373682E636F6D2C6165733132382D6362632C6165733139322D6362632C6165733235362D6362632C336465732D6362632C626C6F77666973682D6362632C636173743132382D6362632C617263666F75722C72696A6E6461656C3132382D6362632C72696A6E6461656C3139322D6362632C72696A6E6461656C3235362D6362632C72696A6E6461656C2D636263406C797361746F722E6C69752E73652C617263666F75723132382C617263666F757232353600000178686D61632D736861322D3235362D65746D406F70656E7373682E636F6D2C686D61632D736861322D3531322D65746D406F70656E7373682E636F6D2C686D61632D736861312D65746D406F70656E7373682E636F6D2C686D61632D736861322D3235362C686D61632D736861322D3531322C686D61632D736861312C686D61632D736861312D39362C686D61632D6D64352C686D61632D6D64352D39362C686D61632D726970656D643136302C686D61632D726970656D64313630406F70656E7373682E636F6D2C756D61632D3634406F70656E7373682E636F6D2C756D61632D313238406F70656E7373682E636F6D2C686D61632D736861312D39362D65746D406F70656E7373682E636F6D2C686D61632D6D64352D65746D406F70656E7373682E636F6D2C686D61632D6D64352D39362D65746D406F70656E7373682E636F6D2C756D61632D36342D65746D406F70656E7373682E636F6D2C756D61632D3132382D65746D406F70656E7373682E636F6D2C6E6F6E6500000178686D61632D736861322D3235362D65746D406F70656E7373682E636F6D2C686D61632D736861322D3531322D65746D406F70656E7373682E636F6D2C686D61632D736861312D65746D406F70656E7373682E636F6D2C686D61632D736861322D3235362C686D61632D736861322D3531322C686D61632D736861312C686D61632D736861312D39362C686D61632D6D64352C686D61632D6D64352D39362C686D61632D726970656D643136302C686D61632D726970656D64313630406F70656E7373682E636F6D2C756D61632D3634406F70656E7373682E636F6D2C756D61632D313238406F70656E7373682E636F6D2C686D61632D736861312D39362D65746D406F70656E7373682E636F6D2C686D61632D6D64352D65746D406F70656E7373682E636F6D2C686D61632D6D64352D39362D65746D406F70656E7373682E636F6D2C756D61632D36342D65746D406F70656E7373682E636F6D2C756D61632D3132382D65746D406F70656E7373682E636F6D2C6E6F6E65000000046E6F6E65000000046E6F6E65000000000000000000000000002CA9032100000014")
    
    print(p:hex(1,nil,8,16," ","    ",1,1,12))	p=string.pack("<d",1.12)    -- EC 51 B8   1E 85 EB F1 3F	print(p:hexF())	local f=string.unpack("<d",p)	assert(f==1.12,f)	print(f)
end


return _M