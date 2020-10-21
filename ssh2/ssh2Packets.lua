--ssh2.0 protocol parser and encoder--Packet parser follows rfc rfc4251,4252,4253require "suproxy.utils.stringUtils"require "suproxy.utils.pureluapack"local tableUtils=require "suproxy.utils.tableUtils"local ok,cjson=pcall(require,"cjson")cjson = ok and cjson or require("suproxy.utils.json")local extends=tableUtils.extendslocal orderTable=tableUtils.OrderedTablelocal asn1 = require "suproxy.utils.asn1"local event=require "suproxy.utils.event"local logger=require "suproxy.utils.compatibleLog"local _M={}--Packet type defines, only the type that have been implemented are listed_M.PktType={	KeyXInit=0x14,		DHKeyXInit=0x1e,	DHKeyXReply=0x1f,	AuthReq=0x32,		AuthFail=0x33,		ChannelData=0x5e,	Disconnect=0x01,	NewKeys=0x15,		AuthSuccess=0x34,}--Tool for mpint format padding (rfc4251 section 5)local function paddingInt(n)    if(n:byte(1)>=128)then        return string.char(0)..n    end    return nend
local function packSSHData(data,padding)
    local paddingLength=16-(#data+5)%16
    if paddingLength<4 then paddingLength=paddingLength+16 end
    local padding=padding or string.random(paddingLength)
    return string.pack(">I4B",#data+1+#padding,#padding)..data..padding
end--Base Packet implements header parser and pack -- uint32    packet_length-- byte      padding_length-- byte[n1]  payload; n1 = packet_length - padding_length - 1-- byte[n2]  random padding; n2 = padding_length-- byte[m]   mac (Message Authentication Code - MAC); m = mac_length_M.Base={    parse=function(self,allBytes)        local pos        self.dataLength,self.paddingLength,self.code,pos=string.unpack(">I4BB",allBytes)        self.allBytes=allBytes        self:parsePayload(allBytes,pos)        return self    end,    parsePayload=function(self,allbytes,pos) return  self end,    pack=function(self)        self.allBytes=packSSHData(string.char(self.code)..self:packPayload())		logger.logWithTitle(logger.DEBUG,"packing",self.allBytes:hex16F())        return self    end,    packPayload=function(self) return "" end,    new=function(self,o)         local o=o or {}        return orderTable.new(self,o)    end}--Key Exchange Init Packet-- byte         SSH_MSG_KEXINIT 0x14-- byte[16]     cookie (random bytes)-- name-list    kex_algorithms-- name-list    server_host_key_algorithms-- name-list    encryption_algorithms_client_to_server-- name-list    encryption_algorithms_server_to_client-- name-list    mac_algorithms_client_to_server-- name-list    mac_algorithms_server_to_client-- name-list    compression_algorithms_client_to_server-- name-list    compression_algorithms_server_to_client-- name-list    languages_client_to_server-- name-list    languages_server_to_client-- boolean      first_kex_packet_follows-- uint32       0 (reserved for future extension)_M.KeyXInit={    code=_M.PktType.KeyXInit,    parsePayload=function(self,allBytes,pos)        self.cookie,self.kex_alg,        self.key_alg,self.enc_alg_c2s,        self.enc_alg_s2c,self.mac_alg_c2s,        self.mac_alg_s2c,self.comp_alg_c2s,        self.comp_alg_s2c,self.lan_c2s,        self.lan_s2c,self.kex_follows,        self.reserved=string.unpack(">c16s4s4s4s4s4s4s4s4s4s4BI4",allBytes,pos)         self.payloadBytes=allBytes:sub(6,5+self.dataLength-self.paddingLength-1)        return self    end,    packPayload=function(self)        local rs=string.pack(">c16s4s4s4s4s4s4s4s4s4s4BI4",self.cookie,        self.kex_alg,self.key_alg,        self.enc_alg_c2s,self.enc_alg_s2c,        self.mac_alg_c2s,self.mac_alg_s2c,        self.comp_alg_c2s,self.comp_alg_s2c,        self.lan_c2s,self.lan_s2c,self.kex_follows,self.reserved        )        self.payloadBytes=string.char(self.code)..rs        return rs    end}extends(_M.KeyXInit,_M.Base)


-- byte      SSH_MSG_KEXDH_INIT 0x1e
-- mpint     e
_M.DHKeyXInit={
    code=_M.PktType.DHKeyXInit,
    parsePayload=function(self,payload,pos)
        self.e=string.unpack(">s4",payload,pos) 
        return self
    end,
    packPayload=function(self)
        return string.pack(">s4",paddingInt(self.e))
    end
}extends(_M.DHKeyXInit,_M.Base)

-- byte      SSH_MSG_KEXDH_REPLY 0x1f
-- string    server public host key and certificates (K_S)
-- mpint     f
-- string    signature of H
_M.DHKeyXReply={
    code=_M.PktType.DHKeyXReply,
    parsePayload=function(self,payload,pos)        local hh
        self.K_S,
        self.f,
        hh=string.unpack(">s4s4s4",payload,pos) 
        self.key_alg,
        self.signH=string.unpack(">s4s4",hh)
        return self
    end,
    packPayload=function(self)
        return string.pack(">s4s4s4",self.K_S,paddingInt(self.f),string.pack(">s4s4",self.key_alg,self.signH))
    end
}extends(_M.DHKeyXReply,_M.Base)
--process user authenticate, request format in rfc4252 section 8
-- byte      SSH_MSG_USERAUTH_REQUEST 0x32
-- string    user name
-- string    service name
-- string    method
-- below are optional, if method is "none" ,following field woundn't appear
-- boolean   FALSE
-- string    plaintext password in ISO-10646 UTF-8 encoding [RFC3629]
_M.AuthReq={
    code=_M.PktType.AuthReq,
    parsePayload=function(self,payload,pos)
        local passStartPos
        self.username,
        self.serviceName,
        self.method,passStartPos=string.unpack(">s4s4s4",payload,pos)
        if self.method=="password" then
            self.password=string.unpack(">s1",payload,passStartPos+4)
        end
        return self
    end,
    packPayload=function(self)
        local req=string.pack(">s4s4s4",self.username,self.serviceName,self.method)
        if self.method=="password" then
            req=req..string.pack(">s4s1","",self.password)
        end
        return req
    end
}extends(_M.AuthReq,_M.Base)
--SSH_MSG_USERAUTH_FAILURE   0x33
_M.AuthFail={    code=_M.PktType.AuthFail,    parsePayload=function(self,payload,pos)        self.methods,pos=string.unpack(">s4",payload,pos)        if pos < #payload then self.partialSuccess=string.unpack(">I4",payload,pos)>0 end        return self    end,    packPayload=function(self)        return string.pack(">s4I4",self.methods,self.partialSuccess and 0 or 1)    end}extends(_M.AuthFail,_M.Base)
-- byte      SSH_MSG_CHANNEL_DATA 0x5e
-- uint32    recipient channel
-- string    data
_M.ChannelData={
    code=_M.PktType.ChannelData,
    parsePayload=function(self,payload,pos)
        self.channel,self.data=string.unpack(">I4s4",payload,pos) 
        return self
    end,
    packPayload=function(self)
        return string.pack(">I4s4",self.channel,self.data)
    end
}extends(_M.ChannelData,_M.Base)
-- byte      SSH_MSG_DISCONNECT 0x01
-- uint32    reason code
-- string    description in ISO-10646 UTF-8 encoding [RFC3629]
-- string    language tag [RFC3066]
_M.Disconnect={
    code=_M.PktType.Disconnect,    --todo: lang not parsed yet
    parsePayload=function(self,payload,pos)
        self.reasonCode,self.message=string.unpack(">I4s4",payload,pos) 
        return self
    end,
    packPayload=function(self)
        return string.pack(">I4s4",self.reasonCode,self.message)
    end
}extends(_M.Disconnect,_M.Base)
return _M