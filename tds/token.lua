require "suproxy.utils.stringUtils"
require "suproxy.utils.pureluapack"
local ok,cjson=pcall(require,"cjson")
local tableUtils=require "suproxy.utils.tableUtils"
local extends=tableUtils.extends
if not ok then cjson = require("suproxy.utils.json") end
local logger=require "suproxy.utils.compatibleLog"
local unicode = require "suproxy.utils.unicode"
local datetime = require "suproxy.utils.datetime"
local sqlVersion = require "suproxy.tds.version"
local _M={}
-- TDS response token types
local TokenType =
{
  ReturnStatus	={code=0x79,desc="ReturnStatus"},
  ColMetaData	={code=0x81,desc="ColMetaData"},
  Error			={code=0xaa,desc="Error"},
  Info			={code=0xab,desc="Info"},
  LoginAck		={code=0xad,desc="LoginAck"},
  Row			={code=0xd1,desc="Row"},
  NBCRow		={code=0xd2,desc="NBCRow"},
  Order			={code=0xa9,desc="Order"},
  EnvChange		={code=0xe3,desc="EnvChange"},
  Done			={code=0xfd,desc="Done"},
  DoneProc		={code=0xfe,desc="DoneProc"},
  DoneInProc	={code=0xff,desc="DoneInProc"}
}
--build index for code
local lookUps={}
for k,v in pairs(TokenType) do lookUps[v.code]=v end
setmetatable(TokenType,{__index=lookUps})
_M.TokenType=TokenType
----------------------------row parser------------------------------
local binRow=function(bytes,pos,length)  local tmp,pos=("c"..length):unpack(bytes,pos) return tmp:hex(),pos end

local ntextRow=function(bytes,pos,length)  local result,pos= ("c"..length):unpack(bytes,pos) return unicode.utf16to8(result),pos end

local textRow=function(bytes,pos,length)  local result,pos= ("c"..length):unpack(bytes,pos) return result,pos end
--signless int
local intRow=function(bytes,pos,length)  return ("<I"..length):unpack(bytes,pos) end

local moneyRow=function(bytes, pos,length,c)
    local i1,i2,pos=string.unpack("<I4I4", bytes, pos)
    return string.format("%.4f",i2*(10^-4)),pos
end

--number with sign
local decimalRow=function(bytes, pos,length,c)
	local  sign, format_string, colbytes
	local precision=c.precision
	local scale=c.scale 
	if ( length == 0 ) then
		return  'Null',pos
	end
	sign, pos = string.unpack("<B", bytes, pos)
	-- subtract 1 from bytes length to account for sign byte
	length = length - 1

	if ( length > 0 and length <= 16 ) then
	colbytes, pos = string.unpack("<I" .. length, bytes, pos)
	else
	logger.log(logger.DEBUG,"Unhandled lengthgth (%d) for DECIMALNTYPE", length)
	return pos + length, 'Unsupported Data'
	end

	if ( sign == 0 ) then
	colbytes = colbytes * -1
	end

	colbytes = colbytes * (10^-scale)
	-- format the return information to reduce truncation by lua
	format_string = string.format("%%.%if", scale)
	colbytes = string.format(format_string,colbytes)

	return colbytes,pos
end

local floatRow= function( data, pos,len,c )
    local result
	if ( len == 0 ) then
		return pos, 'Null'
	elseif ( len == 4 ) then
		result, pos = string.unpack("<f", data, pos)
	elseif ( len == 8 ) then
		result, pos = string.unpack("<d", data, pos)
	end
	return result,pos
end

local datetimeRow=function(bytes,pos,length) 
      -- local hi, lo, result_seconds, result
      -- hi, lo, pos = string.unpack("<i4I4", bytes, pos)
	  -- result_seconds = (hi*24*60*60) + (lo/300)
	  -- local newTime=datetime.getNewDate("190001010000",result_seconds,'SECOND')
      -- result=string.format('%d-%02d-%02d %02d:%02d:%02d',newTime.year,newTime.month,newTime.day,newTime.hour,newTime.min,newTime.sec)
	  local tmp,pos= string.unpack("c"..length, bytes, pos)
	  result=tmp:hex()
      return result,pos
end

local partial=function(bytes,pos,length,c,realParser) 
	if c.lts~=0xffff then return realParser(bytes,pos,length) end
    if length==0xffffffffffffffff then  return "NULL",pos end --???
	local result={} 
	local chuckLen,pos=("<I4"):unpack(bytes,pos)
	local s,pos=realParser(bytes,pos,chuckLen) 
	while s~=""  do 
		table.insert(result,s) 
		chuckLen,pos=("<I4"):unpack(bytes,pos)
		s,pos=realParser(bytes,pos,chuckLen) 
	end 
	return table.concat(result),pos
end

local partialNTextRow=function(bytes,pos,length,c) 
    return partial(bytes,pos,length,c,ntextRow)
end
local partialTextRow=function(bytes,pos,length,c) 
    return partial(bytes,pos,length,c,textRow)
end
local partialBinRow=function(bytes,pos,length,c) 
    return partial(bytes,pos,length,c,binRow)
end
-----------------------length parser------------------------------------
local ltsLen=	function(c,bytes,pos) assert(c.lts) if c.lts==0xffff then return ("<I8"):unpack(bytes,pos) else return ("<I2"):unpack(bytes,pos) end end
local tNLen=	function(c,bytes,pos) assert(c.scale) if c.scale<=2 then return 0x03,pos elseif c.scale<=4 then return 0x04,pos else return 0x05,pos end end
local dt2NLen=	function(c,bytes,pos) assert(c.scale) if c.scale<=2 then return 0x06,pos elseif c.scale<=4 then return 0x07,pos else return 0x08,pos end end
local dtfNLen=	function(c,bytes,pos) assert(c.scale) if c.scale<=2 then return 0x08,pos elseif c.scale<=4 then return 0x09,pos else return 0x0a,pos end end
-----------------------column header parser------------------------------
local function textXHeader(data, pos ,colinfo)
	colinfo.unknown, colinfo.codepage, colinfo.flags, colinfo.charset, pos = string.unpack("<I4I2I2B", data, pos )
	colinfo.tablenamelen, pos = string.unpack("<i2", data, pos )
	colinfo.tablename, pos = string.unpack("c" .. (colinfo.tablenamelen * 2), data, pos)
	return pos, colinfo
end 

local function intN1Header(data, pos ,colinfo)
	colinfo.unknown, pos = string.unpack("<B", data, pos)
	return pos, colinfo
end

local function dateN1Header(data, pos ,colinfo)
	colinfo.scale, pos = string.unpack("<B", data, pos)
	return pos, colinfo
end
--for ssvar only
local function ssvarNum2Header(data, pos ,colinfo)
     colinfo.precision, colinfo.scale, pos = string.unpack("<BB", data, pos)
    return pos, colinfo
end

local function num3Header(data, pos ,colinfo)
    colinfo.unknown, colinfo.precision, colinfo.scale, pos = string.unpack("<BBB", data, pos)
    return pos, colinfo
end

local function SSVAR4Header(data, pos,colinfo )
    colinfo.largeTypeSize, pos = string.unpack("<I4", data, pos)
    return pos, colinfo
end
--for ssvar only
local function ssvarBin2Header(data,pos,colinfo) 
	colinfo.maxLength,pos=string.unpack("<I2", data, pos)
	return pos, colinfo
end
local function bin2Header( data, pos,colinfo )
	colinfo.lts, pos = string.unpack("<I2", data, pos)
	return pos, colinfo
end
--for ssvar only
local function ssvarNvchar7Header(data,pos,colinfo)
	 colinfo.codepage, colinfo.flags, colinfo.charset,colinfo.max, pos = string.unpack("<I2I2BI2", data, pos )
	 colinfo.lts=0
	return pos, colinfo
end
local function nvchar7Header(data,pos,colinfo)
	colinfo.lts, colinfo.codepage, colinfo.flags, colinfo.charset, pos = string.unpack("<I2I2I2B", data, pos )
	return pos, colinfo
end

local function int0Header(data,pos,colinfo) return pos,colinfo end
--https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-tds/ffb02215-af07-4b50-8545-1fd522106c68
local DataTypes ={
  NULLType            = {code=0x1f,	lenBytes=0,	    headerParser=nil,	        parser=nil,             desc="NULLTYPE"			          },
  SQLTEXT             = {code=0x23,	lenBytes=4,	    headerParser=textXHeader,	parser=binRow,          desc="SQLTEXT(Text)",		      },
  GUIDTYPE            = {code=0x24,	lenBytes=1,	    headerParser=intN1Header,	parser=binRow,          desc="GUIDTYPE(uuid)",		      },
  INTNTYPE            = {code=0x26,	lenBytes=1,	    headerParser=intN1Header,	parser=intRow,          desc="INTNTYPE",		          },
  DATENTYPE           = {code=0x28,	lenBytes=1,	    headerParser=int0Header,	parser=binRow,          desc="DATENTYPE",		          },
  TIMENTYPE           = {code=0x29,	lenBytes=1,		headerParser=dateN1Header,	parser=binRow,          desc="TIMENTYPE",		          },
  DATETIME2NTYPE      = {code=0x2a,	lenBytes=1,		headerParser=dateN1Header,	parser=datetimeRow,     desc="DATETIME2NTYPE",	          },
  DATETIMEOFFSETNTYPE = {code=0x2b,	lenBytes=1,		headerParser=dateN1Header,	parser=binRow,          desc="DATETIMEOFFSETNTYPE",		  },
  CHARTYPE            = {code=0x2f,	lenBytes=1,	    headerParser=int0Header,	parser=textRow,         desc="CHARTYPE(Char)",		      },
  INT1TYPE            = {code=0x30,	length=1,		headerParser=int0Header,	parser=intRow,       	desc="INT1TYPE(TinyInt)",	      },
  BITTYPE             = {code=0x32,	length=1,		headerParser=int0Header,	parser=intRow,       	desc="BITTYPE(Bit)",	          },
  INT2TYPE            = {code=0x34,	length=2,		headerParser=int0Header,	parser=intRow,       	desc="INT2TYPE(SmallInt)",        },
  INT4TYPE            = {code=0x38,	length=4,		headerParser=int0Header,	parser=intRow,       	desc="INT4TYPE(Int)",		      },
  DATETIM4TYPE        = {code=0x3a,	length=4,   	headerParser=int0Header,	parser=datetimeRow,     desc="DATETIM4TYPE(SmallDateTime)"},
  FLT4TYPE            = {code=0x3b,	length=4,   	headerParser=int0Header,	parser=binRow,          desc="FLT4TYPE(Real)",	          },
  MONEYTYPE           = {code=0x3c,	length=8,   	headerParser=int0Header,	parser=moneyRow,        desc="MONEYTYPE(Money)",	      },
  DATETIMETYPE        = {code=0x3d,	length=8,   	headerParser=int0Header,	parser=datetimeRow,     desc="DATETIMETYPE",	          },
  FLT8TYPE            = {code=0x3e,	length=8,   	headerParser=int0Header,	parser=binRow,          desc="FLT8TYPE(Float)",	          },
  SSVARIANTTYPE       = {code=0x62,	lenBytes=4,	    headerParser=SSVAR4Header,	--[[parser init later]]	desc="SSVARIANTTYPE(Sql_Variant)" },
  NTEXTTYPE           = {code=0x63,	lenBytes=4,	    headerParser=textHeade,	    parser=binRow,          desc="NTEXTTYPE",		          },
  BITNTYPE            = {code=0x68,	lenBytes=1,	    headerParser=intN1Header,	parser=intRow,       	desc="BITNTYPE",		          },
  DECIMALNTYPE        = {code=0x6A,	lenBytes=1,	    headerParser=num3Header,	parser=decimalRow,      desc="DECIMALNTYPE",	          },
  NUMERICNTYPE        = {code=0x6C,	lenBytes=1,	    headerParser=num3Header,	parser=decimalRow,      desc="NUMERICNTYPE",	          },
  FLTNTYPE            = {code=0x6D,	lenBytes=1,	    headerParser=intN1Header,	parser=floatRow,        desc="FLTNTYPE",		          },
  MONEYNTYPE          = {code=0x6E,	lenBytes=1,	    headerParser=intN1Header,	parser=moneyRow,        desc="MONEYNTYPE",		          },
  DATETIMNTYPE        = {code=0x6F,	lenBytes=1,	    headerParser=intN1Header,	parser=binRow,          desc="DATETIMNTYPE",	          },
  MONEY4TYPE          = {code=0x7a,	length=4,   	headerParser=intN1Header,	parser=binRow,          desc="MONEY4TYPE(SmallMony)",     },
  INT8TYPE		      = {code=0x7f,	length=8,		headerParser=int0Header,    parser=intRow,       	desc="INT8TYPE(BigInt)",		  },
  BIGVARBINARYTYPE    = {code=0xA5,	length=ltsLen,	headerParser=bin2Header,    parser=partialBinRow,   desc="BIGVARBINARYTYPE",          },
  BIGVARCHARTYPE      = {code=0xA7,	length=ltsLen,	headerParser=nvchar7Header, parser=partialTextRow,  desc="BIGVARCHARTYPE",	          },
  BIGBINARYTYPE       = {code=0xAD,	lenBytes=2,	    headerParser=bin2Header,	parser=binRow,          desc="BIGBINARYTYPE",	          },
  BIGCHARTYPE         = {code=0xAF,	lenBytes=2,     headerParser=nvchar7Header, parser=partialTextRow,  desc="BIGCHARTYPE",	              },
  NVARCHARTYPE        = {code=0xE7,	length=ltsLen,	headerParser=nvchar7Header, parser=partialNTextRow,  desc="NVARCHARTYPE",	          },
  SQLNCHAR            = {code=0xEF,	lenBytes=2,	    headerParser=nvchar7Header, parser=ntextRow,        desc="SQLNCHAR",		          }
}
--build index for code
local lookUps={}
for k,v in pairs(DataTypes) do lookUps[v.code]=v end
setmetatable(DataTypes,{__index=lookUps})
--https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-tds/2435e85d-9e61-492c-acb2-627ffccb5b92
local ssvarRow=function(bytes,pos,length,c)
	local prop={}
	local baseType,propLen,pos=("BB"):unpack(bytes,pos)
	local headerParser=DataTypes[baseType].headerParser
	--for BIGVARBINARYTYPE, BIGBINARYTYPE,NUMERICNTYPE, DECIMALNTYPE,BIGVARCHARTYPE, BIGCHARTYPE, NVARCHARTYPE, NCHARTYPE cannot use standard Parser
	if baseType==DataTypes.BIGVARBINARYTYPE.code or baseType==DataTypes.BIGBINARYTYPE.code then
		headerParser=ssvarBin2Header
	elseif baseType==DataTypes.NUMERICNTYPE.code or baseType==DataTypes.DECIMALNTYPE.code then
		headerParser=ssvarNum2Header
	elseif baseType==DataTypes.BIGVARCHARTYPE.code or baseType==DataTypes.BIGCHARTYPE.code or baseType==DataTypes.NVARCHARTYPE.code or baseType==DataTypes.NCHARTYPE.code  then
		headerParser=ssvarNvchar7Header
	end
	pos,prop=headerParser(bytes,pos,prop)
	return DataTypes[baseType].parser(bytes,pos,length-propLen-2,prop)
end
DataTypes.SSVARIANTTYPE.parser=ssvarRow

local tokenRegister={}
local registerParser=function(token,type)
	assert(token,"token can not be null")
	local t=type or token.type
	assert(t,"type can not be null")
	tokenRegister[t]=token
end

_M.doParse=function(type,bytes,pos)
	local token
	if tokenRegister[type] then
		token=tokenRegister[type]:new()
	else
		token=_M.Token:new()
	end
	local pos,err=token:parse(bytes,pos)
	return token,pos,err
end

_M.Token={
    parse=function(self,bytes,pos)
		local err
        self.type,pos=("B"):unpack(bytes,pos)
		if TokenType[self.type] then 
			print(TokenType[self.type].desc.." is parsing") 
		else
			print(string.format("%02X",self.type).." is parsing") 
		end
		pos,err=self:parseLength(bytes,pos)
		print(self.length)
		if err then return nil,err end
		pos,err=self:parseData(bytes,pos)
		
		if err then return nil,err end
		if TokenType[self.type] then 
			print(TokenType[self.type].desc.." finished") 
		else
			print(string.format("%02X",self.type).." finished") 
		end
        return pos
    end ,
	parseData=function(self,bytes,pos)
		--for those packet we don't care just skip it
		if (not self.length) and (not self.count)  then logger.log(logger.ERR,self.type..string.format("(%02X)",self.type).." token can not be parsed") return nil end
		return pos+self.length
	end,
	--https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-tds/427e90df-a728-4899-aaff-f42a0c9bbd1a
	parseLength=function(self,bytes,pos)
		--0 length token 0001 0000
		if bit.band(self.type,0x30)==0x10 then
			self.length=0
		--fixed length token 0011 0000
		elseif bit.band(self.type,0x30)==0x30 then
			if bit.band(self.type,0x0c)==0x00 then self.length=1 end
			if bit.band(self.type,0x0c)==0x04 then self.length=2 end
			if bit.band(self.type,0x0c)==0x08 then self.length=4 end
			if bit.band(self.type,0x0c)==0x0c then self.length=8 end
			if self.type==TokenType.Done.code then self.length=12 end
		--variable length tokens 0010 0000
        elseif bit.band(self.type,0x30)==0x20 then
            self.length,pos=("<I2"):unpack(bytes,pos)
		--count type, length not available 0000 0000
        elseif bit.band(self.type,0x30)==0x00 then
			self.count,pos=("<I2"):unpack(bytes,pos)
			if self.count==0 then self.length=0 end
		end
		return pos
	end,
	pack=function(self)
		error("not implemented")
	end,
	tostring=function (self)
		return ""
	end,
    new=function(self,param) 
        return setmetatable(param or {}, {__index=self})
    end
}

_M.ColumnMetaDataToken = {
	type=TokenType.ColMetaData.code,
	parseData=function(self,bytes,pos)
		for i=1,self.count,1 do
			local column={}
			column.userType,column.flags,column.colType,pos=("<I4I2B"):unpack(bytes,pos)
			print(column.colType)
			if DataTypes[column.colType].headerParser then
				pos=DataTypes[column.colType].headerParser(bytes,pos,column)
			else
				local err="unknown column type "..string.dec2hexF(column.colType)
				print(err)
				return nil,err
			end
			column.nameLen, pos = string.unpack("<B",bytes,pos)
			local tmp
			tmp, pos = string.unpack("c" .. (column.nameLen * 2), bytes, pos )
			column.name = unicode.utf16to8(tmp)
			self.colList[i]=column
		end
		return pos
	end,
	tostring=function(self)
		local nameList={};
		for i,v in ipairs (self.colList) do
			nameList[i]=v.name
		end
		return table.concat(nameList,"\t")
	end,
	new=function(self) 
		local o={colList={}}
        return setmetatable(o, {__index=self})
    end
} 
extends(_M.ColumnMetaDataToken,_M.Token)
registerParser(_M.ColumnMetaDataToken)

--https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-tds/490e563d-cc6e-4c86-bb95-ef0186b98032
-- TokenType:0xad
-- Length:The total length, in bytes, of the following fields: Interface, TDSVersion, Progname, and ProgVersion.
-- Interface:The type of interface with which the server will accept client requests:
	-- 0: SQL_DFLT (server confirms that whatever is sent by the client is acceptable. If the client requested SQL_DFLT, SQL_TSQL will be used).
	-- 1: SQL_TSQL (TSQL is accepted).
-- TDSVersion:The TDS version being used by the server.<60>
-- ProgName:The name of the server.
-- MajorVer:The major version number (0-255).
-- MinorVer:The minor version number (0-255).
-- BuildNumHi:The high byte of the build number (0-255).
-- BuildNumLow:The low byte of the build number (0-255).
_M.LoginAckToken = {
	type=TokenType.LoginAck.code,
	parseData=function(self,bytes,pos)
		self.interface,pos=("B"):unpack(bytes,pos)
		self.TDSVersion,pos=(">c4"):unpack(bytes,pos)
		local progNameLen,pos=("B"):unpack(bytes,pos)
		self.progName,pos=unicode.utf16to8(("c"..progNameLen*2):unpack(bytes,pos)),pos+progNameLen*2
		local major, minor, build ,pos= (">BBI2"):unpack(bytes,pos)
		local version = sqlVersion:new()
		version:SetVersion( major, minor, build, nil, "SSNetLib" )
		self.serverVersion=version
		return pos,nil
	end,
	new=function(self) 
        return setmetatable({}, {__index=self})
    end
} 
extends(_M.LoginAckToken,_M.Token)
registerParser(_M.LoginAckToken)

_M.RowToken = {
	parse=function(self,bytes,pos,columnList)
		self.type,pos=("B"):unpack(bytes,pos)
		local maskbit=1
		local nullBytes={}
		if self.type==TokenType.NBCRow.code then
			local maskCount=math.ceil(#columnList/8)
			for i=1,maskCount do
				nullBytes[#nullBytes+1],pos=("B"):unpack(bytes,pos)
				print(string.dec2hex(nullBytes[#nullBytes]))
			end
		end
		if #nullBytes==0 then nullBytes[1]=0 end
		for i,v in ipairs(columnList) do
			local length,value
			-- O O O O X O O X -> 1 0 0 1 0 0 0 0
			if bit.band(nullBytes[math.ceil(i/8)],bit.lshift(maskbit,(i%8)==0 and 7 or (i%8)-1))==0 then
				print(i)
				local dtype=DataTypes[v.colType]
				if dtype then
					print(cjson.encode({desc=dtype.desc,code=string.dec2hexF(dtype.code)}))
					print(bytes:hexF(pos,pos+15))
					length=dtype.length
					if not length then
						local lenBytes=dtype.lenBytes or 1
						length,pos=("I"..lenBytes):unpack(bytes,pos)
					elseif type(length)=="function" then
						length,pos=length(v,bytes,pos)
					end
					print(length)
					value,pos=dtype.parser(bytes,pos,length,v)
				else
					length,pos=("B"):unpack(bytes,pos)
					value,pos=("c"..length):unpack(bytes,pos)
				end
			else
				value="NULL"
			end
			self.rowData[i]=value
		end
		return pos
	end,
	tostring=function(self)
		return table.concat(self.rowData,"\t")
	end,
	new=function(self,param) 
        return setmetatable(param or {rowData={}}, {__index=self})
    end
} 
extends(_M.RowToken,_M.Token)
registerParser(_M.RowToken,TokenType.Row.code)
registerParser(_M.RowToken,TokenType.NBCRow.code)


--https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-tds/3c06f110-98bd-4d5b-b836-b1ba66452cb7
_M.DoneToken = extends({type=TokenType.Done.code},_M.Token)
registerParser(_M.DoneToken)

--https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-tds/9805e9fa-1f8b-4cf8-8f78-8d2602228635
-- TokenType:0xaa
-- Length:The total length of the ERROR data stream, in bytes.
-- Number:The error number.
-- State:The error state, used as a modifier to the error number.
-- Class:The class (severity) of the error. A class of less than 10 indicates an informational message.
-- MsgText:The message text length and message text using US_VARCHAR format.
-- ServerName:The server name length and server name using B_VARCHAR format.
-- ProcName:The stored procedure name length and the stored procedure name using B_VARCHAR format.
-- LineNumber:The line number in the SQL batch or stored procedure that caused the error. Line numbers begin at 1. If the line number is not applicable to the message, the value of LineNumber is 0.
_M.ErrorToken = {
	type=TokenType.Error.code,
	parseData=function(self,bytes,pos)
		self.number,pos=("<I4"):unpack(bytes,pos)
		self.state,pos=("B"):unpack(bytes,pos)
		self.class,pos=("B"):unpack(bytes,pos)
		local msgLen,pos=("<I2"):unpack(bytes,pos)
		self.message,pos=unicode.utf16to8(("c"..msgLen*2):unpack(bytes,pos)),pos+msgLen*2
		local serverNameLen,pos=("B"):unpack(bytes,pos)
		self.serverName,pos=unicode.utf16to8(("c"..serverNameLen*2):unpack(bytes,pos)),pos+serverNameLen*2
		local procNameLen,pos=("B"):unpack(bytes,pos)
		self.procName,pos=unicode.utf16to8(("c"..procNameLen*2):unpack(bytes,pos)),pos+procNameLen*2
		self.lineNo,pos=("<I4"):unpack(bytes,pos)
		return pos,nil
	end,
	pack=function(self)
		local buf={
			("<I4BB"):pack(self.number,self.state,self.class),
			("<I2"):pack(self.message:len()),
			unicode.utf8to16(self.message),
			("B"):pack(self.serverName:len()),
			unicode.utf8to16(self.serverName),
			("B"):pack(self.procName:len()),
			unicode.utf8to16(self.procName),
			("<I4"):pack(self.lineNo)
		}
		local tmp=table.concat(buf)
		return ("B"):pack(self.type)..("<I2"):pack(#tmp)..tmp
	end,
	tostring=function(self)
		return cjson.encode(self)
	end
}
extends(_M.ErrorToken,_M.Token)
registerParser(_M.ErrorToken)
return _M
