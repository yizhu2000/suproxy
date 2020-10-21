--tns protocol parser and encoder
require "suproxy.utils.stringUtils"
require "suproxy.utils.pureluapack"
local ok,cjson=pcall(require,"cjson")
cjson = ok and cjson or require("suproxy.utils.json")
local tableHelper=require "suproxy.utils.tableUtils"
local extends=tableHelper.extends
local orderTable=tableHelper.OrderedTable
local event=require "suproxy.utils.event"
local logger=require "suproxy.utils.compatibleLog"
local parserUtil=require ("suproxy.parser")
local _M={}
----------------------build parser---------------------------
local function getKey(params)
    local key=params.callId and "callId"..params.callId or params.dataId and "dataId"..params.dataId or "code"..params.code
	key=key .. (params.req and "req"..params.req or "")
    return key
end
_M.getKey=getKey

_M.Options= {
    tnsVersion=314,
    headerCheckSum=true,
    packetCheckSum=true,
    hdrChk=function(self) return self.tnsVersion<=314 or self.headerCheckSum end,
    pktChk=function(self) return self.tnsVersion<=314 or self.packetCheckSum end,
    clientEndian=">",
    serverEndian="<",
    program="sqlplus.exe",
    is64Bit=true,
    platform="IBMPC/WIN_NT64-9.1.0",
    oracleVersion={
        major=11,
        minor=2,
        build=0,
        subbuild=0,
        fix=0
    },
    new=function(self,o) 
        return setmetatable(o or {},{__index=self}) 
    end
}
local packetType={
	CONNECT={code=1,desc="CONNECT"},    ACCEPT={code=2,desc="ACCEPT"},          ACK={code=3,desc="ACK"},
	REFUSE={code=4,desc="REFUSE"},      REDIRECT={code=5,desc="REDIRECT"},      DATA={code=6,desc="DATA"},
	NULL={code=7,desc="NULL DATA"},     ABORT={code=9,desc="ABORT"},            RESEND={code=11,desc="RESEND"},
	MARKER={code=12,desc="MARKER"},     ATTENTION={code=13,desc="ATTENTION"},   CONTROL={code=14,desc="CONTROL"},
	MAX={code=19,desc="MAX"}
}
--build index for code
tableHelper.addIndex(packetType,"code")
packetType.getDesc=function(self,code) 
    local rs=""
    if not code then return rs end
    if self[code] then rs= self[code].desc end
    return rs.."("..string.dec2hexF(code)..")"
end
_M.PacketType=packetType

local dataId={
	SET_PROTOCOL		={code=1	, desc="SET_PROTOCOL"},
	SET_DATATYPES		={code=2	, desc="SET_DATATYPES"},
	USER_OCI_FUNC		={code=3	, desc="USER_OCI_FUNC"},
	RETURN_STATUS		={code=4	, desc="RETURN_STATUS"},
	ACCESS_USR_ADDR		={code=5	, desc="ACCESS_USR_ADDR"},
	ROW_TRANSF_HEADER	={code=6	, desc="ROW_TRANSF_HEADER"},
	ROW_TRANSF_DATA		={code=7	, desc="ROW_TRANSF_DATA"},
	RETURN_OPI_PARAM 	={code=8	, desc="RETURN_OPI_PARAM"},
	FUNCCOMPLETE		={code=9	, desc="FUNCCOMPLETE"},
	NERROR_RET_DEF		={code=10	, desc="NERROR_RET_DEF"},
	IOVEC_4FAST_UPI		={code=11	, desc="IOVEC_4FAST_UPI"},
	LONG_4FAST_UPI		={code=12	, desc="LONG_4FAST_UPI"},
	INVOKE_USER_CB		={code=13	, desc="INVOKE_USER_CB"},
	LOB_FILE_DF			={code=14	, desc="LOB_FILE_DF"},
	WARNING				={code=15	, desc="WARNING"},
	DESCRIBE_INFO		={code=16	, desc="DESCRIBE_INFO"},
	PIGGYBACK_FUNC		={code=17	, desc="PIGGYBACK_FUNC"},
	SIG_4UCS			={code=18	, desc="SIG_4UCS"},
	FLUSH_BIND_DATA		={code=19	, desc="FLUSH_BIND_DATA"},
	OCI_RESPOND			={code=23	, desc="OCI_RESPOND"},
	SNS					={code=0xde	, desc="SNS"},
	XTRN_PROCSERV_R1	={code=32	, desc="XTRN_PROCSERV_R1"},
	XTRN_PROCSERV_R2	={code=68	, desc="XTRN_PROCSERV_R2"}
}
--build index for code
tableHelper.addIndex(dataId,"code")
dataId.getDesc=packetType.getDesc
_M.DataID=dataId

local callId={
    [1]="Logon to Oracle",
	[2]="Open Cursor",
	[3]="Parse a Row",
	[4]="Execute a Row",
	[5]="Fetch a Row",
	[8]="Close Cursor",
	[9]="Logoff of Oracle",
	[10]="Describe a select list column",
	[11]="Define where the column goes",
	[12]="Auto commit on",
	[13]="Auto commit off",
	[14]="Commit",
	[15]="Rollback",
	[16]="Set fatal error options",
	[17]="Resume current operation",
	[18]="Get Oracle version-date string",
	[19]="Until we get rid of OASQL",
	[20]="Cancel the current operation",
	[21]="Get error message",
	[22]="Exit Oracle command",
	[23]="Special function",
	[24]="Abort",
	[25]="Dequeue by RowID",
	[26]="Fetch a long column value",
	[27]="Create Access Module",
	[28]="Save Access Module Statement",
	[29]="Save Access Module",
	[30]="Parse Access Module Statement",
	[31]="How many items?",
	[32]="Initialize Oracle",
	[33]="Change User ID",
	[34]="Bind by reference positional",
	[35]="Get n'th Bind Variable",
	[36]="Get n'th Into Variable",
	[37]="Bind by reference",
	[38]="Bind by reference numeric",
	[39]="Parse and Execute",
	[40]="Parse for syntax (only)",
	[41]="Parse for syntax and SQL Dictionary lookup",
	[42]="Continue serving after EOF",
	[43]="Array describe",
	[44]="Init sys pars command table",
	[45]="Finalize sys pars command table",
	[46]="Put sys par in command table",
	[47]="Get sys pars from command table",
	[48]="Start Oracle (V6)",
	[49]="Shutdown Oracle (V6)",
	[50]="Run Independent Process (V6)",
	[51]="Test RAM (V6)",
	[52]="Archive operation (V6)",
	[53]="Media Recovery - start (V6)",
	[54]="Media Recovery - record tablespace to recover (V6)",
	[55]="Media Recovery - get starting log seq # (V6)",
	[56]="Media Recovery - recover using offline log (V6)",
	[57]="Media Recovery - cancel media recovery (V6)",
	[58]="Logon to Oracle (V6)",
	[59]="Get Oracle version-date string in new format",
	[60]="Initialize Oracle",
	[61]="Reserved for MAC; close all cursors",
	[62]="Bundled execution call",
	[65]="For direct loader: functions",
	[66]="For direct loader: buffer transfer",
	[67]="Distrib. trans. mgr. RPC",
	[68]="Describe indexes for distributed query",
	[69]="Session operations",
	[70]="Execute using synchronized system commit numbers",
	[71]="Fast UPI calls to OPIAL7",
	[72]="Long Fetch (V7)",
	[73]="Call OPIEXE from OPIALL: no two-task access",
	[74]="Parse Call (V7) to deal with various flavours",
	[76]="RPC call from PL/SQL",
	[77]="Do a KGL operation",
	[78]="Execute and Fetch",
	[79]="X/Open XA operation",
	[80]="New KGL operation call",
	[81]="2nd Half of Logon",
	[82]="1st Half of Logon",
	[83]="Do Streaming Operation",
	[84]="Open Session (71 interface)",
	[85]="X/Open XA operations (71 interface)",
	[86]="Debugging operations",
	[87]="Special debugging operations",
	[88]="XA Start",
	[89]="XA Switch and Commit",
	[90]="Direct copy from db buffers to client address",
	[91]="OKOD Call (In Oracle <= 7 this used to be Connect",
	[93]="RPI Callback with ctxdef",
	[94]="Bundled execution call (V7)",
	[95]="Do Streaming Operation without begintxn",
	[96]="LOB and FILE related calls",
	[97]="File Create call",
	[98]="Describe query (V8) call",
	[99]="Connect (non-blocking attach host)",
	[100]="Open a recursive cursor",
	[101]="Bundled KPR Execution",
	[102]="Bundled PL/SQL execution",
	[103]="Transaction start, attach, detach",
	[104]="Transaction commit, rollback, recover",
	[105]="Cursor close all",
	[106]="Failover into piggyback",
	[107]="Session switching piggyback (V8)",
	[108]="Do Dummy Defines",
	[109]="Init sys pars (V8)",
	[110]="Finalize sys pars (V8)",
	[111]="Put sys par in par space (V8)",
	[112]="Terminate sys pars (V8)",
	[114]="Init Untrusted Callbacks",
	[115]="Generic authentication call",
	[116]="FailOver Get Instance call",
	[117]="Oracle Transaction service Commit remote sites",
	[118]="Get the session key",
	[119]="Describe any (V8)",
	[120]="Cancel All",
	[121]="AQ Enqueue",
	[122]="AQ Dequeue",
	[123]="Object transfer",
	[124]="RFS Call",
	[125]="Kernel programmatic notification",
	[126]="Listen",
	[127]="Oracle Transaction service Commit remote sites (V >= 8.1.3)",
	[128]="Dir Path Prepare",
	[129]="Dir Path Load Stream",
	[130]="Dir Path Misc. Ops",
	[131]="Memory Stats",
	[132]="AQ Properties Status",
	[134]="Remote Fetch Archive Log FAL",
	[135]="Client ID propagation",
	[136]="DR Server CNX Process",
	[138]="SPFILE parameter put",
	[139]="KPFC exchange",
	[140]="Object Transfer (V8.2)",
	[141]="Push Transaction",
	[142]="Pop Transaction",
	[143]="KFN Operation",
	[144]="Dir Path Unload Stream",
	[145]="AQ batch enqueue dequeue",
	[146]="File Transfer",
	[147]="Ping",
	[148]="TSM",
	[150]="Begin TSM",
	[151]="End TSM",
	[152]="Set schema",
	[153]="Fetch from suspended result set",
	[154]="Key/Value pair",
	[155]="XS Create session Operation",
	[156]="XS Session Roundtrip Operation",
	[157]="XS Piggyback Operation",
	[158]="KSRPC Execution",
	[159]="Streams combined capture apply",
	[160]="AQ replay information",
	[161]="SSCR",
	[162]="Session Get",
	[163]="Session RLS",
	[165]="Workload replay data",
	[166]="Replay statistic data",
	[167]="Query Cache Stats",
	[168]="Query Cache IDs",
	[169]="RPC Test Stream",
	[170]="Replay PL/SQL RPC",
	[171]="XStream Out",
	[172]="Golden Gate RPC"
}
callId.getDesc=function(self,code) 
    local rs=""
    if not code then return rs end
    if self[code] then rs= self[code] end
    return rs.."("..string.dec2hexF(code)..")"
end
_M.CallID=callId


local function parseFemagic(is64Bit,bytes,pos) return ("c"..(is64Bit and 8 or 1)):unpack(bytes,pos) end
local function packFemagic(is64Bit) return (is64Bit and string.char(0xfe,0xff,0xff,0xff,0xff,0xff,0xff,0xff) or string.char(1)) end
_M.Packet={
	desc="BasePacket",
	getLength=function(self) return self._length end,
	getType=function(self) return self._code end,
	getDataFlag=function(self) return self._dataFlag end,
    parseHeader=function(self,headerBytes,pos)
        self._length,pos=(">I2"):unpack(headerBytes,pos)
		if self.options:pktChk() then self._packetCheckSum,pos=(">I2"):unpack(headerBytes,pos) end
		self._code,pos=("B"):unpack(headerBytes,pos)
		self._reserved,pos=("B"):unpack(headerBytes,pos)
		if self.options:hdrChk() then self._headerCheckSum,pos=(">I2"):unpack(headerBytes,pos) end
		if self._code==packetType.DATA.code then self._dataFlag,pos=(">I2"):unpack(headerBytes,pos) end
        return pos
    end,
    packHeader=function(self,payloadLen)
        local rs={
			(">I2"):pack(payloadLen+4
				+(self.options:pktChk() and 2 or 0)
				+(self.options:hdrChk() and 2 or 0)
				+(self._code==packetType.DATA.code and 2 or 0)),
			self.options:pktChk() and (">I2"):pack(self._packetCheckSum) or "",
			("B"):pack(self._code),
			("B"):pack(self._reserved),
			self.options:hdrChk() and (">I2"):pack(self._headerCheckSum) or "",
			self._code==packetType.DATA.code and (">I2"):pack(self._dataFlag) or "",
		}
		return table.concat(rs)
    end,

    pack=function(self)
        local payloadBytes=self:packPayload()
        local headerBytes=self:packHeader(#payloadBytes)
        local result=headerBytes..payloadBytes
        logger.logWithTitle(logger.DEBUG,"packing",result:hex16F())
        self.allBytes=result
        return result
    end,

    parse=function(self,allBytes,pos)
        pos=self:parseHeader(allBytes)
        self:parsePayload(allBytes,pos)
        --for piggy back packet, the real packet may change the bytes
        self.allBytes=self.allBytes or allBytes
        return self
    end,
    
    parsePayload=function(self,allBytes,pos)
    end,
    
    new=function(self,o,options) 
        local options=_M.Options:new(options)
        local o=o or {}
        o.options=options
        return orderTable.new(self,o)
    end

}

_M.Connect={
	_code=packetType.CONNECT.code, 
	getType=function(self) return self._code end,
	desc="Connect",
	checkHeader=function(self) return bit.band(self._serviceOption,0x0800)>0 end,
	checkPacket=function(self) return bit.band(self._serviceOption,0x1000)>0 end,
	fullDuplex=function(self) return bit.band(self._serviceOption,0x0400)>0 end,
	halfDuplex=function(self) return bit.band(self._serviceOption,0x0200)>0 end,
	getTnsVersion=function(self) return self._tnsVersion end,
	setTnsVersion=function(self,version) self._tnsVersion=version end,
	bigEndian=function(self) return self._valueOf1==1 end,
	getConnStr=function(self) return self._connStr end,
	setConnStr=function(self,connStr) self._connStr=connStr end,
	parsePayload=function(self,bytes,pos)
		self._tnsVersion,pos=(">I2"):unpack(bytes,pos)
		self._compatibleVersion,pos=(">I2"):unpack(bytes,pos)
		self._serviceOption,pos=(">I2"):unpack(bytes,pos)
		--header checksum
		self._sessionDataUnit,pos=(">I2"):unpack(bytes,pos)
		self._maxTranmitDataUnit,pos=(">I2"):unpack(bytes,pos)
		self._netOptions,pos=(">I2"):unpack(bytes,pos)
		self._line,pos=(">I2"):unpack(bytes,pos)
		self._valueOf1,pos=(">I2"):unpack(bytes,pos)
		local connectDataLength,pos=(">I2"):unpack(bytes,pos)
        self._connectDataOffset,pos=(">I2"):unpack(bytes,pos)
		self._maxRecvConnData,pos=(">I4"):unpack(bytes,pos)
		self._flag1,pos=("B"):unpack(bytes,pos)
		self._flag2,pos=("B"):unpack(bytes,pos)
		self._idontcare,pos=("c"..self._connectDataOffset+1-pos):unpack(bytes,pos)
        self._connStr=("c"..connectDataLength):unpack(bytes,self._connectDataOffset+1)
		return self
	end,
	packPayload=function(self)
		local result={
			(">I2"):pack(self._tnsVersion),
			(">I2"):pack(self._compatibleVersion),
			(">I2"):pack(self._serviceOption),
			(">I2"):pack(self._sessionDataUnit),
			(">I2"):pack(self._maxTranmitDataUnit),
			(">I2"):pack(self._netOptions),
			(">I2"):pack(self._line),
			(">I2"):pack(self._valueOf1),
			(">I2"):pack(self._connStr:len()),
			(">I2"):pack(self._connectDataOffset),
			(">I4"):pack(self._maxRecvConnData),
			("B"):pack(self._flag1),
			("B"):pack(self._flag2),
			self._idontcare,
			self._connStr,
		}
		return table.concat(result)
	end
}
extends(_M.Connect,_M.Packet)

_M.Accept={
	_code=packetType.ACCEPT.code 
	,getType=function(self) return self._code end,
	desc="Accept",
	checkHeader=function(self) return bit.band(self._serviceOption,0x0800)>0 end,
	checkPacket=function(self) return bit.band(self._serviceOption,0x1000)>0 end,
	fullDuplex=function(self) return bit.band(self._serviceOption,0x0400)>0 end,
	halfDuplex=function(self) return bit.band(self._serviceOption,0x0200)>0 end,
	getTnsVersion=function(self) return self._tnsVersion end,
	setTnsVersion=function(self,version) self._tnsVersion=version end,
	bigEndian=function(self) return self._valueOf1==1 end,
	parsePayload=function(self,bytes,pos)
		self._tnsVersion,pos=(">I2"):unpack(bytes,pos)
		self._serviceOption,pos=(">I2"):unpack(bytes,pos)
		--header checksum
		self._sessionDataUnit,pos=(">I2"):unpack(bytes,pos)
		self._maxTranmitDataUnit,pos=(">I2"):unpack(bytes,pos)
		self._valueOf1,pos=(">I2"):unpack(bytes,pos)
		local dataLength,dataOff,pos=(">I2I2"):unpack(bytes,pos)
		self._flag1,pos=("B"):unpack(bytes,pos)
		self._flag2,pos=("B"):unpack(bytes,pos)
	end
}
extends(_M.Accept,_M.Packet)

local parseKVPEntry = function( data, pos )
    -- In some case this is the 3*totoal length
    local value_len
    value_len, pos = string.unpack("<I4", data, pos)
    if value_len == 0 then return pos, "" end
    -- Look at the first byte after the total length. If the value is
    -- broken up into multiple chunks, this will be indicated by this
    -- byte being 0xFE. Otherwise this is the length of the only chunk.
    local chunked = string.unpack("B", data, pos) == 0xFE
    if chunked then
      pos = pos + 1
    end
    -- Loop through the chunks until we read the whole value
    local chunks = {}
    repeat
      local chunk
      chunk, pos = string.unpack("s1", data, pos)
      table.insert(chunks, chunk)
    until #chunk == 0 or not chunked -- last chunk is zero-length
    return pos, table.concat(chunks)
end
  
local parseKVP = function( data, pos )
    local key, value, flags
    pos, key   = parseKVPEntry( data, pos )
    pos, value = parseKVPEntry( data, pos )
    flags, pos = string.unpack("<I4", data, pos )
    return pos, key, value, flags
end

local packArrayItem=function(value,result,tri)
 -- this length seems vary along with client version
    local MAX_CHUNK_LENGTH = tri and 0x40 or 127
    if #value > MAX_CHUNK_LENGTH then
      -- First, write the multiple-chunk indicator
      table.insert(result, string.char(0xfe))
      -- Loop through the string value, chunk by chunk
      local pos = 1
      repeat
        local nextpos = pos + MAX_CHUNK_LENGTH
        table.insert(result, string.pack("s1", value:sub(pos, nextpos - 1)))
        pos = nextpos
      until pos > #value
      -- Finish with an empty chunk
      table.insert(result, "\0")
    else
      table.insert(result, string.pack("s1", value))
    end
end

local packKVPEntry= function( value,tri )
    value = value or ""
    local sb4len = string.pack("<I4", (tri and 3 or 1)*#value)
    if #value == 0 then return sb4len end
    local result = {sb4len}
    packArrayItem(value,result,tri)
    return table.concat(result)
end
 
local packKVP = function( key, value, flags ,tri)
	return packKVPEntry( key ,tri) ..
	packKVPEntry( value ,tri) ..
	string.pack( "<I4", ( flags or 0 ) )
end
_M.SessionRequest={
	_code= packetType.DATA.code 
	,getType=function(self) return self._code end,
	_dataId=dataId.USER_OCI_FUNC.code, 
	 getDataId=function(self) return self._dataId end,
	_callId=0x76, 
	 getCallId=function(self) return self._callId end,
	desc="SessionRequest",
	getUsername=function(self) return self._username end,
	setUsername=function(self,username) self._username=username end,
	getProgram=function(self) return self._params["AUTH_PROGRAM_NM"].v end,
	getMachine=function(self) return self._params["AUTH_MACHINE"].v end,
	getSid=function(self) return self._params["AUTH_SID"].v end,
    getPid=function(self) return self._params["AUTH_PID"].v end,
    is64Bit=function(self) return self._is64Bit end,
	parsePayload=function(self,bytes,pos)
		self._dataId,pos=("B"):unpack(bytes,pos)
		assert(self._dataId == self:getDataId(),self._dataId)
		self._callId,pos=("B"):unpack(bytes,pos)
		assert(self._callId == self:getCallId(),self._callId )
		self._seq,pos=("B"):unpack(bytes,pos)
		local userNamePos,countPos
        --test client 32bit or 64bit
        self._is64Bit=bytes:byte(pos)==0xfe and true or false 
        if(self._is64Bit) then
            if(bytes:byte(2+9+2+1+44)==0xff)then countPos=2+9+2+1+24 userNamePos=2+9+2+1+48 else countPos=2+9+2+1+24 userNamePos=2+9+2+1+44 end
        else
            if(bytes:byte(2+9+2+1+16)==0x01)then countPos=2+9+2+1+10 userNamePos=2+9+2+1+20 else countPos=2+9+2+1+10 userNamePos=2+9+2+1+16 end
        end
		
		self._unknown,pos=bytes:sub(pos,userNamePos-1),userNamePos
		local paramCount=string.unpack("B",bytes,countPos)
		self._username,pos=string.unpack("s1",bytes,pos)
		local params = orderTable:new()
		for i=1, paramCount do
			local item,k={}
			pos, k, item.v, item.flag = parseKVP( bytes, pos )
			params[k] = item
		end
		self._params=params
		return self,nil
	end,
	packPayload=function(self)
		local rs={
			("BBB"):pack(self._dataId,self._callId,self._seq),
			self._unknown,
			("s1"):pack(self._username),
		}
		for i,item in ipairs(self._params) do
			rs[#rs+1]=packKVP(item.key,item.value.v,item.value.flag,self._is64Bit)
		end
		return table.concat(rs)
	end
	
}
extends(_M.SessionRequest,_M.Packet)

_M.SessionResponse={
	_code=packetType.DATA.code ,
	_dataId=dataId.RETURN_OPI_PARAM.code, 
	 getDataId=function(self) return self._dataId end,
	desc="SessionResponse",
	getAuthKey=function(self) return self._params["AUTH_SESSKEY"].v:fromhex() end,
	setAuthKey=function(self,key)  self._params["AUTH_SESSKEY"].v=key:hex() end,
	getSalt=function(self) return self._params["AUTH_VFR_DATA"].v:fromhex() end,
	getDbid=function(self) return self._params["AUTH_GLOBALLY_UNIQUE_DBID"..string.char(0)].v:fromhex() end,
	parsePayload=function(self,bytes,pos)
		self._dataId,pos=("B"):unpack(bytes,pos)
		assert(self._dataId == self:getDataId(),self._dataId)
		local kvps = {}
		local c,pos =("<I2"):unpack(bytes, pos)
		self._params=orderTable:new()
		for i=1, c do
			local item,k={}
			pos, k, item.v, item.flag = parseKVP( bytes, pos )
			self._params[k] = item
		end
		self._unknown=bytes:sub(pos)
		return self,nil
	end,
	packPayload=function(self)
		local rs={
			("B<I2"):pack(self._dataId  ,#(self._params))
		}
		for i,item in ipairs(self._params) do
			rs[#rs+1]=packKVP(item.key,item.value.v,item.value.flag)
		end
		rs[#rs+1]=self._unknown
		return table.concat(rs)
	end
}
extends(_M.SessionResponse,_M.Packet)

_M.AuthRequest={
    _code=packetType.DATA.code,
	getType=function(self) return self._code end,
	_dataId=dataId.USER_OCI_FUNC.code, 
	 getDataId=function(self) return self._dataId end,
	_callId=0x73, 
	 getCallId=function(self) return self._callId end,
	desc="AuthRequest",
	getUsername=function(self) return self._username end,
	setUsername=function(self,username) self._username=username end,
	getAuthKey=function(self) return self._params["AUTH_SESSKEY"].v:fromhex() end,
	setAuthKey=function(self,key) self._params["AUTH_SESSKEY"].v=key:hex() end,
	getPassword=function(self)return self._params["AUTH_PASSWORD"].v:fromhex() end,
	setPassword=function(self,pass) self._params["AUTH_PASSWORD"].v=pass:hex() end,
	getProgram=function(self) return self._params["AUTH_PROGRAM_NM"].v end,
	getMachine=function(self) return self._params["AUTH_MACHINEK"].v end,
	getSid=function(self) return self._params["AUTH_SID"].v end,
	parsePayload=function(self,bytes,pos)
		self._dataId,pos=("B"):unpack(bytes,pos)
		assert(self._dataId == self:getDataId(),self._dataId)
		self._callId,pos=("B"):unpack(bytes,pos)
		assert(self._callId == self:getCallId(),self._callId )
		self._seq,pos=("B"):unpack(bytes,pos)
		local userNamePos,countPos
        --test client 32bit or 64bit
        self._is64Bit=bytes:byte(pos)==0xfe and true or false 
        if(self._is64Bit) then
            if(bytes:byte(2+9+2+1+44)==0xff)then countPos=2+9+2+1+24 userNamePos=2+9+2+1+48 else countPos=2+9+2+1+24 userNamePos=2+9+2+1+44 end
        else
            if(bytes:byte(2+9+2+1+16)==0x01)then countPos=2+9+2+1+10 userNamePos=2+9+2+1+20 else countPos=2+9+2+1+10 userNamePos=2+9+2+1+16 end
        end
		self._unknown,pos=bytes:sub(pos,userNamePos-1),userNamePos
		local paramCount=string.unpack("B",bytes,countPos)
		self._username,pos=string.unpack("s1",bytes,pos)
		local params = orderTable:new()
		for i=1, paramCount do
			local item,k={}
			pos, k, item.v, item.flag = parseKVP( bytes, pos )
			params[k] = item
		end
		self._params=params
		return self,nil
	end,
	packPayload=function(self)
		local rs={
			("BBB"):pack(self._dataId,self._callId,self._seq),
			self._unknown,
			("s1"):pack(self._username),
		}
		for i,item in ipairs(self._params) do
			rs[#rs+1]=packKVP(item.key,item.value.v,item.value.flag,self._is64Bit)
		end
		return table.concat(rs)
	end
	
}
extends(_M.AuthRequest,_M.Packet)

_M.SetProtocolRequest={
	_code=packetType.DATA.code,
	getType=function(self) return self._code end,
	_dataId=dataId.SET_PROTOCOL.code, 
	getDataId=function(self) return self._dataId end,
	desc="SetProtocolRequest",
    getClientPlatform=function(self) return self._clientPlatform end,
	parsePayload=function(self,bytes,pos)
		self._dataId,pos=("B"):unpack(bytes,pos)
		assert(self._dataId == self:getDataId(),self._dataId)
		local acceptedVersion,pos=("z"):unpack(bytes,pos)
		self._acceptedVersion={acceptedVersion:byte(1,#acceptedVersion)}
		self._clientPlatform,pos=("z"):unpack(bytes,pos)
		return self,nil
	end
}
extends(_M.SetProtocolRequest,_M.Packet)

_M.Piggyback={
	_code=packetType.DATA.code,
	 getType=function(self) return self._code end,
	_dataId=dataId.PIGGYBACK_FUNC.code, 
	 getDataId=function(self) return self._dataId end, 
	 getCallId=function(self) return self._callId end,
	desc="Piggyback",
	parsePayload=function(self,bytes,pos)  
		self._piggyDataId,pos=("B"):unpack(bytes,pos)
		assert(self._piggyDataId == self:getDataId(),self._dataId)
		self._piggyCallId,pos=("B"):unpack(bytes,pos)
        self._piggySeq,pos=("B"):unpack(bytes,pos)
        local cHeaderPos
        if self._piggyCallId==0x69 then
            if(self.options.is64Bit) then
                if self.options.oracleVersion.major<=11 then
                    cHeaderPos=2+9+2+1+16
                else 
                    cHeaderPos=2+9+2+1+20
                end
            else
                if self.options.oracleVersion.major<=11 then
                    cHeaderPos=2+9+2+1+9
                else
                    cHeaderPos=2+9+2+1+13
                end
            end
        elseif self._piggyCallId==0x6b then
            cHeaderPos=13+12+1
        end
        self._piggyHeader,pos=("c"..cHeaderPos-pos):unpack(bytes,pos)
        self._realDataId,self._realCallId=bytes:byte(pos,pos+1)
        local key=getKey({callId=self._realCallId,dataId=self._realDataId,code=self._code})
        local entry=require("suproxy.tns.parser"):new().C2PParser:getParser(key)
        self.__key=key
        if entry then
            local ret=entry.parser:new(nil,self.options):parsePayload(bytes,pos)
            extends(self,ret)
            extends(self,entry.parser) 
        end
		return self
	end,
    packPayload=function(self)
        local rs={
			("BBB"):pack(self._piggyDataId,self._piggyCallId,self._piggySeq),
			self._piggyHeader,
		}
        local key=getKey({callId=self._realCallId,dataId=self._realDataId,code=self._code})
        local entry=require("suproxy.tns.parser"):new().C2PParser:getParser(key)
        if entry then
            rawset(self,"_dataId",self._realDataId)
            rawset(self,"_callId",self._realCallId)
            local ret=entry.parser:new(nil,self.options).packPayload(self)
            rs[#rs+1]=ret
        end
		return table.concat(rs)
    end
}
extends(_M.Piggyback,_M.Packet)


_M.VersionResponse={
	desc="VersionResponse",
	_code=packetType.DATA.code ,
	_dataId=dataId.RETURN_OPI_PARAM.code, 
	getDataId=function(self) return self._dataId end,
    getBanner=function(self) return self._banner end,
    getVersion=function(self) return self._major..'.'..self._minor..'.'..self._build..'.'..self._sub..'.'..self._fix end, 
    getMajor=function(self) return self._major end,
    getMinor=function(self) return self._minor end,
    getBuild=function(self) return self._build end,
    getSub=function(self) return self._sub end,
    getFix=function(self) return self._fix end,
	parsePayload=function(self,bytes,pos)
        local versionString,pos=string.unpack("s1",bytes,14)
        self._banner=versionString
        local minor
        self._fix,self._sub,minor,self._major,pos=("BBBB"):unpack(bytes,pos)
        self._minor=minor/16
        self._build=minor%16
		return self,nil
	end
}
extends(_M.VersionResponse,_M.Packet)

_M.SQLRequest={
	_code=packetType.DATA.code,
	getType=function(self) return self._code end,
	_dataId=dataId.USER_OCI_FUNC.code, 
	getDataId=function(self) return self._dataId end,
    _callId=0x5e, 
	getCallId=function(self) return self._callId end,
	desc="SQLRequest",
    getCommand=function(self) return self._command end,
    setCommand=function(self,command) self._command=command,self._sql end,
    getSqlTotalLen=function(self) 
        local sqlLen=("<I"..self._sqlTotalLen:len()):unpack(self._sqlTotalLen) 
        if self.options.is64Bit then return math.floor(sqlLen/3) else return sqlLen end
    end,
    getSqlTotalLenBytes=function(self)
        local l= (self.options.platform=="Java_TTC-8.2.0" and 1 or 2)
        local sqlLen=#(self._command)
        if self.options.is64Bit then sqlLen=3*sqlLen end
        return ("I"..l):pack(sqlLen)
    end,
	parsePayload=function(self,bytes,pos)
		self._dataId,pos=("B"):unpack(bytes,pos)
		assert(self._dataId == self:getDataId(),self._dataId)
		self._callId,pos=("B"):unpack(bytes,pos)
		assert(self._callId == self:getCallId(),self._callId )
        self._seq,pos=("B"):unpack(bytes,pos)
        local unknowLen=8 local sqlLen=2 local unknowLen2=2 local fixUnknownLen=152
        if self.options.platform=="Java_TTC-8.2.0" then unknowLen=5 sqlLen=1 unknowLen2=1 end
        self._unknown,pos=("c"..unknowLen):unpack(bytes,pos)
        self._feMagic,pos=parseFemagic(self.options.is64Bit,bytes,pos)
        self._sqlTotalLen,pos=("c"..sqlLen):unpack(bytes,pos)
        self._unknown2,pos=("c"..unknowLen2):unpack(bytes,pos)
        if self.options.platform=="Java_TTC-8.2.0" then fixUnknownLen=41 
		elseif self.options.oracleVersion.major==10 then fixUnknownLen=40 
		elseif not self.options.is64Bit then fixUnknownLen=54 end
        self._fixUnknown,pos=("c"..fixUnknownLen):unpack(bytes,pos)
		local len_len=1
        --client 19_6
		if bytes:byte(pos)==0 then
			pos=pos+20
			self.v19_6=true
			len_len=4
		end
		local commandLen=bytes:byte(pos)
        local command=""
        if(commandLen==0xfe) then
            local i=pos+1
            while(("I"..len_len):unpack(bytes,i)~=0) do
                local c
                c,i=string.unpack("s"..len_len,bytes,i)
                command=command..c
            end
            pos=i
        else
            command,pos=string.unpack("s1",bytes,pos)
        end
        self._command=command
        self._idontcare=bytes:sub(pos)
		return self
	end,
    packPayload=function(self)
        local rs={
			("BBB"):pack(self._dataId,self._callId,self._seq),
			self._unknown,
            self._feMagic,
            self:getSqlTotalLenBytes(),
            self._unknown2,
            self._fixUnknown
		}
        packArrayItem(self._command,rs)
        rs[#rs+1]=self._idontcare
		return table.concat(rs)
    end
}
extends(_M.SQLRequest,_M.Packet)

_M.Marker1={
    pack=function(self)
        return string.char(0x00,0x0b,0x00,0x00,0x0c,0x00,0x00,0x00,0x01,0x00,0x01)
    end
}
_M.Marker2={
    pack=function(self)
        return string.char(0x00,0x0b,0x00,0x00,0x0c,0x00,0x00,0x00,0x01,0x00,0x02)
    end
}

_M.NoPermissionError={
    pack=function(self)
        local rs
                --11g
        if(self.options.tnsVersion==314 and self.options.oracleVersion.major==11) then
            rs=string.char(           
0x00, 0x75, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00,
0x00, 0x00, 0x04, 0x05, 0x00, 0x00, 0x00, 0x05,
0x00, 0x00, 0x00, 0x00, 0x00, 0x07, 0x04, 0x00,
0x00, 0x00, 0x00, 0x02, 0x00, 0x0e, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03,
0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x28, 0x4f, 0x52, 0x41,
0x2d, 0x30, 0x30, 0x39, 0x34, 0x32, 0x3a, 0x20,
0x74, 0x61, 0x62, 0x6c, 0x65, 0x20, 0x6f, 0x72,
0x20, 0x76, 0x69, 0x65, 0x77, 0x20, 0x64, 0x6f,
0x65, 0x73, 0x20, 0x6e, 0x6f, 0x74, 0x20, 0x65,
0x78, 0x69, 0x73, 0x74, 0x0a)
        end
        --12c
        if(self.options.tnsVersion==314 and self.options.oracleVersion.major==12) then
            rs=string.char(
0x00, 0xb4, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00,
0x00, 0x00, 0x17, 0x02, 0x04, 0x00, 0x04, 0x33,
0x35, 0x38, 0x34, 0x04, 0x01, 0x00, 0x00, 0x00,
0x04, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x07,
0x04, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
0x00, 0x27, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x40, 0xbb, 0x3d, 0x24, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07,
0x04, 0x00, 0x00, 0x18, 0x4f, 0x52, 0x41, 0x2d,
0x30, 0x31, 0x30, 0x33, 0x31, 0x3a, 0x20, 0xe6,
0x9d, 0x83, 0xe9, 0x99, 0x90, 0xe4, 0xb8, 0x8d,
0xe8, 0xb6, 0xb3, 0x0a)
        end
        
        if(self.options.tnsVersion==312) then
            rs=string.char(
0x00, 0xb4, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00,
0x00, 0x00, 0x17, 0x02, 0x04, 0x00, 0x04, 0x32,
0x37, 0x30, 0x30, 0x04, 0x05, 0x00, 0x00, 0x00,
0x56, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x07,
0x04, 0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x0e,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x58, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x60, 0xe6, 0xe9, 0x0f, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07,
0x04, 0x00, 0x00, 0x18, 0x4f, 0x52, 0x41, 0x2d,
0x30, 0x31, 0x30, 0x33, 0x31, 0x3a, 0x20, 0xe6,
0x9d, 0x83, 0xe9, 0x99, 0x90, 0xe4, 0xb8, 0x8d,
0xe8, 0xb6, 0xb3, 0x0a)
        end
        
        return rs
    end
}
extends(_M.NoPermissionError,_M.Packet)

_M.LoginError={
    pack=function(self)
        local rs=string.char(           
0x00, 0x80, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00,
0x00, 0x00, 0x04, 0x01, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0xf9, 0x03, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x33, 0x4f, 0x52, 0x41,
0x2d, 0x30, 0x31, 0x30, 0x31, 0x37, 0x3a, 0x20,
0x69, 0x6e, 0x76, 0x61, 0x6c, 0x69, 0x64, 0x20,
0x75, 0x73, 0x65, 0x72, 0x6e, 0x61, 0x6d, 0x65,
0x2f, 0x70, 0x61, 0x73, 0x73, 0x77, 0x6f, 0x72,
0x64, 0x3b, 0x20, 0x6c, 0x6f, 0x67, 0x6f, 0x6e,
0x20, 0x64, 0x65, 0x6e, 0x69, 0x65, 0x64, 0x0a)
        return rs
    end
}
extends(_M.NoPermissionError,_M.Packet)


--print(tableHelper.printTableF(_M.parser))
--------------------------------unit test starts here----------------------------
_M.unitTest={}
function _M.unitTest.connectTest()
	local bytes=string.fromhex("011e000001000000013e012c0c412000ffffc60e0000010000d4004a00001400414150000000000000000000000000000000000000000000000000002000002000000000000000000001284445534352495054494f4e3d28434f4e4e4543545f444154413d28534552564943455f4e414d453d4f52434c29284349443d2850524f4752414d3d433a5c50726f6772616d3f46696c65735c5072656d69756d536f66745c4e6176696361743f5072656d69756d3f31355c6e6176696361742e6578652928484f53543d4445534b544f502d504e4f30364c432928555345523d79697a687529292928414444524553533d2850524f544f434f4c3d7463702928484f53543d3139322e3136382e312e3138322928504f52543d31353231292929")	
	local packet=require("suproxy.tns.parser"):new().C2PParser:parse(bytes)
	assert(packet:getTnsVersion()==318,packet:getTnsVersion())
	assert(packet:checkHeader(),tostring(packet:checkHeader()))
	assert(not packet:checkPacket(),tostring(packet:checkPacket()))
	assert(packet:fullDuplex(),tostring(packet:fullDuplex()))
	assert(not packet:halfDuplex(),tostring(packet:halfDuplex()))
	assert(packet._sessionDataUnit==8192,packet._sessionDataUnit)
	assert(packet._maxTranmitDataUnit==65535,packet._maxTranmitDataUnit)
	assert(not packet:bigEndian(),tostring(packet:bigEndian()))
	assert(packet._flag1==0x41)
	assert(packet._flag2==0x41)
	local cstr="(DESCRIPTION=(CONNECT_DATA=(SERVICE_NAME=ORCL)(CID=(PROGRAM=C:\\Program?Files\\PremiumSoft\\Navicat?Premium?15\\navicat.exe)(HOST=DESKTOP-PNO06LC)(USER=yizhu)))(ADDRESS=(PROTOCOL=tcp)(HOST=192.168.1.182)(PORT=1521)))"
	assert(packet._connStr==cstr,packet._connStr:hexF(nil,nil,packet._connStr:compare(cstr)))
	packet:setTnsVersion(200)
	packet._connStr="abcd"
	packet._flag1,packet._flag2=0x42,0x43
	local oldbytes=bytes
    packet:pack()
	local bytes=packet.allBytes
	print(bytes:hexF(nil,nil,bytes:compare(oldbytes)))
	print(oldbytes:hexF())
	local packet=require("suproxy.tns.parser"):new().C2PParser:parse(bytes)
	assert(packet:getTnsVersion()==200,packet:getTnsVersion())
	assert(packet:checkHeader(),tostring(packet:checkHeader()))
	assert(not packet:checkPacket(),tostring(packet:checkPacket()))
	assert(packet:fullDuplex(),tostring(packet:fullDuplex()))
	assert(not packet:halfDuplex(),tostring(packet:halfDuplex()))
	assert(packet._sessionDataUnit==8192,packet._sessionDataUnit)
	assert(packet._maxTranmitDataUnit==65535,packet._maxTranmitDataUnit)
	assert(not packet:bigEndian(),tostring(packet:bigEndian()))
	assert(packet._flag1==0x42)
	assert(packet._flag2==0x43)
	assert(packet._connStr=="abcd",packet._connStr)
end

function _M.unitTest.acceptTest()
	local bytes=string.fromhex("0020000002000000013a0c4120007fff01000000002041410000000000000000")	
	local packet=require("suproxy.tns.parser"):new().S2PParser:parse(bytes)
	assert(packet:getTnsVersion()==314,packet:getTnsVersion())
	assert(packet:checkHeader(),tostring(packet:checkHeader()))
	assert(not packet:checkPacket(),tostring(packet:checkPacket()))
	assert(packet:fullDuplex(),tostring(packet:fullDuplex()))
	assert(not packet:halfDuplex(),tostring(packet:halfDuplex()))
	assert(packet._sessionDataUnit==8192,packet._sessionDataUnit)
	assert(packet._maxTranmitDataUnit==32767,packet._maxTranmitDataUnit)
	assert(not packet:bigEndian(),tostring(packet:bigEndian()))
	assert(packet._flag1==0x41,packet._flag1)
	assert(packet._flag2==0x41,packet._flag2)
end

function _M.unitTest.sessionResponseTest()
	local bytes=string.fromhex("014000000600000000000803000c0000000c415554485f534553534b45596000000060363230393941433739463638363639433744303046304643313836313233303741363731413333364134303833453445454131443843453236454233433937374642323443373432413335343836323232374330424341453443303730373931000000000d0000000d415554485f5646525f4441544114000000143730333633364239324445304233443039454537251b00001a0000001a415554485f474c4f42414c4c595f554e495155455f44424944002000000020334444413639304446433035344533413336463039463946364537443033373100000000040100000002000000000000000000000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000")	
	local packet=require("suproxy.tns.parser"):new().S2PParser:parse(bytes,nil,nil,nil,"callId"..0x76)
	assert(packet:getAuthKey()==string.fromhex("62099AC79F68669C7D00F0FC18612307A671A336A4083E4EEA1D8CE26EB3C977FB24C742A354862227C0BCAE4C070791"),packet:getAuthKey():hex())
	assert(packet:getSalt()==string.fromhex("703636B92DE0B3D09EE7"),packet:getSalt():hex())
	assert(packet:getDbid()==string.fromhex("3DDA690DFC054E3A36F09F9F6E7D0371"),packet:getDbid():hex())
	packet:setAuthKey(("62099AC79F68669C7D00F0FC18612307A671A336A4083E4EEA1D8CE26EB3C977FB24C742A354862227C0BCAE4C070792"):fromhex())
	local oldbytes=bytes
	packet:pack()
    bytes=packet.allBytes
	print(bytes:compare16F(oldbytes))
	local packet=_M.SessionResponse:new():parse(bytes)
	assert(packet:getAuthKey()==string.fromhex("62099AC79F68669C7D00F0FC18612307A671A336A4083E4EEA1D8CE26EB3C977FB24C742A354862227C0BCAE4C070792"),packet:getAuthKey():hex())
	assert(packet:getSalt()==string.fromhex("703636B92DE0B3D09EE7"),packet:getSalt():hex())
	assert(packet:getDbid()==string.fromhex("3DDA690DFC054E3A36F09F9F6E7D0371"),packet:getDbid():hex())
end

function _M.unitTest.authRequestTest()
	local bytes=string.fromhex("039b0000060000000000037303feffffffffffffff1200000001010000feffffffffffffff12000000fefffffffffffffffeffffffffffffff0673797374656d240000000c415554485f534553534b455920010000fe40304642333646363937324634444130443941393933444230423635353833363336414543354434343239393239354345383637323432363337413041353442332034353035383936453841313044354138414530443338423839394637424236310001000000270000000d415554485f50415353574f5244c00000004039444332353843373736324341313342413537343246444246373833454535453237323441394442373446313332454136314245354433343531443533424535000000001800000008415554485f525454120000000633353832313900000000270000000d415554485f434c4e545f4d454d0c000000043430393600000000270000000d415554485f5445524d494e414c2d0000000f4445534b544f502d504e4f30364c43000000002d0000000f415554485f50524f4752414d5f4e4d210000000b6e6176696361742e65786500000000240000000c415554485f4d414348494e454b00000019574f524b47524f55505c4445534b544f502d504e4f30364c43000000001800000008415554485f504944210000000b32313637323a3231313230000000001800000008415554485f5349440f0000000579697a687500000000420000001653455353494f4e5f434c49454e545f43484152534554090000000338373100000000450000001753455353494f4e5f434c49454e545f4c49425f54595045030000000134000000004e0000001a53455353494f4e5f434c49454e545f4452495645525f4e414d450000000000000000420000001653455353494f4e5f434c49454e545f56455253494f4e1b0000000931383636343735353200000000420000001653455353494f4e5f434c49454e545f4c4f4241545452030000000131000000001800000008415554485f41434c0c0000000438303030000000003600000012415554485f414c5445525f53455353494f4e6f00000025414c5445522053455353494f4e205345542054494d455f5a4f4e453d272b30383a30302700010000004500000017415554485f4c4f474943414c5f53455353494f4e5f494460000000203541304638343533363535353437423541323532334341303232424636373932000000003000000010415554485f4641494c4f5645525f49440000000000000000")
	local packet=require("suproxy.tns.parser"):new().C2PParser:parse(bytes)
	assert(packet:getUsername()=="system",packet:getUsername())
	assert(packet:getAuthKey()==string.fromhex("0FB36F6972F4DA0D9A993DB0B65583636AEC5D44299295CE867242637A0A54B34505896E8A10D5A8AE0D38B899F7BB61"),packet:getAuthKey():hex())
	assert(packet:getPassword()==string.fromhex("9DC258C7762CA13BA5742FDBF783EE5E2724A9DB74F132EA61BE5D3451D53BE5"),packet:getPassword():hex())
	packet:setUsername("111111")
	packet:setAuthKey(string.fromhex("0FB36F6972F4DA0D9A993DB0B65583636AEC5D44299295CE867242637A0A54B34505896E8A10D5A8AE0D38B899F7BB62"))
	packet:setPassword(string.fromhex("9DC258C7762CA13BA5742FDBF783EE5E2724A9DB74F132EA61BE5D3451D53BE6"))
	local oldbytes=bytes
	packet:pack()
    bytes=packet.allBytes
	print(bytes:compare16F(oldbytes,1,0x100))
	local packet=_M.AuthRequest:new():parse(bytes)
	assert(packet:getLength()==0x39b)
	assert(packet:getUsername()=="111111",packet:getUsername())
	assert(packet:getPassword()==string.fromhex("9DC258C7762CA13BA5742FDBF783EE5E2724A9DB74F132EA61BE5D3451D53BE6"))
	assert(packet:getAuthKey()==string.fromhex("0FB36F6972F4DA0D9A993DB0B65583636AEC5D44299295CE867242637A0A54B34505896E8A10D5A8AE0D38B899F7BB62"),packet:getAuthKey():hex())	
end
function _M.unitTest.sessionRequestTest()
	local bytes=string.fromhex("00f40000060000000000037602feffffffffffffff1800000001000000feffffffffffffff0500000000000000fefffffffffffffffeffffffffffffff0863232373636f7474270000000d415554485f5445524d494e414c0f000000055a48555949000000002d0000000f415554485f50524f4752414d5f4e4d210000000b6e6176696361742e65786500000000240000000c415554485f4d414348494e45180000000841445c5a48555949000000001800000008415554485f504944210000000b31333730343a3138343434000000001800000008415554485f534944270000000d41646d696e6973747261746f7200000000")
	local packet=require("suproxy.tns.parser"):new().C2PParser:parse(bytes)
	assert(packet:getUsername()=="c##scott",packet:getUsername())
	packet:setUsername("1111111")
	local oldbytes=bytes
    packet:pack()
	bytes=packet.allBytes
	print(bytes:compareF(oldbytes,1,0x59))
	print(bytes:compare16F(oldbytes,1,0x59))
	local packet=require("suproxy.tns.parser"):new().C2PParser:parse(bytes)
	assert(packet:getLength()==0xf3)
	assert(packet:getUsername()=="1111111",packet:getUsername())
end
function _M.unitTest.setProtocolRequestTest()
	local bytes=string.fromhex("00270000060000000000010605040302010049424d50432f57494e5f4e5436342d392e312e3000")	
	local packet=require("suproxy.tns.parser"):new().C2PParser:parse(bytes)
	assert(#packet._acceptedVersion==6,tableHelper.printTableF(packet._acceptedVersion))
	assert(packet._clientPlatform=="IBMPC/WIN_NT64-9.1.0",packet._clientPlatform)
end
function _M.unitTest.SQLRequestTest()
	local bytes=string.fromhex("01560000060000000000035e117180000000000000feffffffffffffff78000000feffffffffffffff0d000000fefffffffffffffffeffffffffffffff0000000001000000160000000000000000000000000000000000000000000000feffffffffffffff0000000000000000fefffffffffffffffefffffffffffffffeffffffffffffff0100000000000000fefffffffffffffffeffffffffffffff000000000000000000000000000000000000000000000000000000002853454c454354204445434f4445282741272c2741272c2731272c273227292046524f4d204455414c010000000100000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000102030000160000000000000000000000000000000000000000000000000000000000000000000000")
	local packet=require("suproxy.tns.parser"):new().C2PParser:parse(bytes)
	local oldbytes=bytes
    assert(packet:getCommand()=="SELECT DECODE('A','A','1','2') FROM DUAL",packet:getCommand())
    packet:setCommand("11")
    packet:pack()
	bytes=packet.allBytes
    packet=require("suproxy.tns.parser"):new().C2PParser:parse(bytes)
    assert(packet:getCommand()=="11",packet:getCommand())
    assert(packet:getSqlTotalLen()==2,packet:getSqlTotalLen())
	print(bytes:compare16F(oldbytes,1))

end

function _M.unitTest.PiggybackTest()
	local bytes=string.fromhex("01240000060000000000116908feffffffffffffff010000000000000001000000035e092100040000000000feffffffffffffff5d000000feffffffffffffff0d000000fefffffffffffffffeffffffffffffff0000000001000000000000000000000000000000000000000000000000000000feffffffffffffff0000000000000000fefffffffffffffffefffffffffffffffeffffffffffffff0000000000000000fefffffffffffffffeffffffffffffff000000000000000000000000000000000000000000000000000000001f424547494e2044424d535f4f55545055542e44495341424c453b20454e443b01000000010000000000000000000000000000000000000000000000080000000000000000000000000000000000000000000000")
    local opt=_M.Options:new()
    opt.oracleVersion.major=12
	local packet=require("suproxy.tns.parser"):new().C2PParser:parse(bytes,nil,nil,opt)
	local oldbytes=bytes 
    assert(packet._realCallId==0x5e,packet._realCallId)
    assert(packet._realDataId==0x03,packet._realDataId)
    assert(packet:getCommand()=="BEGIN DBMS_OUTPUT.DISABLE; END;",packet:getCommand())
    packet:setCommand("11")
    print(packet.desc)
	packet:pack()
    bytes=packet.allBytes
    packet=require("suproxy.tns.parser"):new().C2PParser:parse(bytes)
    assert(packet:getCommand()=="11",packet:getCommand())
    assert(packet:getSqlTotalLen()==2,packet:getSqlTotalLen())
	print(bytes:compare16F(oldbytes,1))
    bytes=string.fromhex("003c0000060000000000116b0444000000a0f4000001000000033b05feffffffffffffffdc05000001000000fefffffffffffffffeffffffffffffff")
    local packet=require("suproxy.tns.parser"):new().C2PParser:parse(bytes)
    assert(packet._realCallId==0x3b,packet._realCallId)
    assert(packet._realDataId==0x03,packet._realDataId)
end

function _M.unitTest.versionTest()
	local bytes=string.fromhex("006e0000060000000000084c004c4f7261636c652044617461626173652031326320456e74657270726973652045646974696f6e2052656c656173652031322e322e302e312e30202d2036346269742050726f64756374696f6e0001200c17020400043237303009010000000300")	
	local packet=require("suproxy.tns.parser"):new().S2PParser:parse(bytes,nil,nil,nil,"callId"..0x3b)
	assert(packet:getBanner()=="Oracle Database 12c Enterprise Edition Release 12.2.0.1.0 - 64bit Production",packet:getBanner())
	assert(packet:getVersion()=="12.2.0.1.0",packet:getVersion())
end

function _M.test()
	for k,v in pairs(_M.unitTest) do
		print("------------running  "..k)
		v()
		print("------------"..k.."  finished")
	end
end


return _M
