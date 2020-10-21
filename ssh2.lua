local sub = string.sublocal byte = string.byterequire "suproxy.utils.stringUtils"require "suproxy.utils.pureluapack"local asn1 = require "suproxy.utils.asn1"local pkey=require "resty.openssl.pkey"local cipher=require ("resty.openssl.cipher")local bn = require "resty.openssl.bn"local cipherConf= require"suproxy.ssh2.ssh2CipherConf"local ssh2Packet=require "suproxy.ssh2.ssh2Packets"local event=require "suproxy.utils.event"local logger=require "suproxy.utils.compatibleLog"local tableHelper=require "suproxy.utils.tableUtils"local _M = {}
_M._PROTOCAL ='ssh2'

function _M.new(self)
    local o=setmetatable({}, {__index=self})
    o.c2p_stage="INIT"
    o.p2s_stage="INIT"
    o.proxy_id_str="SSH-2.0-GateWay1.0"
    o.p2c_seq=0
    o.c2p_seq=0
    o.s2p_seq=0
    o.p2s_seq=0
    o.C2PDataEvent=event:new(o,"C2PDataEvent")
    o.S2PDataEvent=event:new(o,"S2PDataEvent")    o.AuthSuccessEvent=event:new(o,"AuthSuccessEvent")    o.AuthFailEvent=event:new(o,"AuthFailEvent")    o.BeforeAuthEvent=event:newReturnEvent(o,"BeforeAuthEvent")	o.OnAuthEvent=event:newReturnEvent(o,"OnAuthEvent")    o.ContextUpdateEvent=event:new(o,"ContextUpdateEvent")	local parser=require("suproxy.ssh2.parser"):new()    o.C2PParser=parser.C2PParser    o.C2PParser.events.KeyXInitEvent:addHandler(o,self.C2PKeyXInitHandler)    o.C2PParser.events.AuthReqEvent:addHandler(o,self.handleAuthRequest)    o.C2PParser.events.DHKeyXInitEvent:addHandler(o,self.handleDHKexInit)    o.C2PParser.events.NewKeysEvent:addHandler(o,self.C2PNewKeysHandler)    o.C2PParser.events.ChannelDataEvent:addHandler(o,self.C2PChannelDataHandler)    o.S2PParser=parser.S2PParser    o.S2PParser.events.KeyXInitEvent:addHandler(o,self.S2PKeyXInitHandler)    o.S2PParser.events.DHKeyXReplyEvent:addHandler(o,self.handleDHKeyXReply)    o.S2PParser.events.AuthSuccessEvent:addHandler(o,self.handleAuthSuccess)     o.S2PParser.events.AuthFailEvent:addHandler(o,self.handleAuthFail)    o.S2PParser.events.NewKeysEvent:addHandler(o,self.S2PNewKeysHandler)    o.S2PParser.events.ChannelDataEvent:addHandler(o,self.S2PChannelDataHandler)
    return o
end
--tool for mpint format padding (rfc4251 section 5)local function paddingInt(n)
    if(n:byte(1)>=128)then
        return string.char(0)..n
    end
    return n
end

--tool for get e from pkcs#1 format privkeylocal rsa_pubkey_modulus_e=function(cer)
    --replace -----BEGIN RSA PRIVATE KEY-----
    cer=cer:gsub("%-%-%-%-%-.-%-%-%-%-%-",""):gsub("\r?\n?","")
    cer=ngx.decode_base64(cer)
    local decoder = asn1.ASN1Decoder:new()
    --asn1 decoder integer is limited to 16 bit, m and e would be too long, so overwrite this just return a char string
    decoder:registerTagDecoders({
        [string.char(0x02)]=function(self, encStr, elen, pos)
        local value,pos=string.unpack("c" .. elen,encStr, pos)
        return pos,value
    end})
    local _,seq = decoder:decode(cer,1)
    return seq[1],seq[2]
end

--todo: dynamicly load cert
--load key from config
-- int32     Host key length
-- string    Host key type
-- string(mpint)    RSA public exponent (e):
-- string(mpint)    RSA modulus (N):local function pack_KEX_Host_Key()
    local N,e=rsa_pubkey_modulus_e(cipherConf.pubkey)
    --type
    return string.pack(">s4s4s4","ssh-rsa",e,N)
end

-- HASH(K || H || "A|B|C|D|E" || session_id)local function getKey(h,k,letter,sessionId,shaAlg)    local key=string.pack(">s4c"..#h.."c1c"..#sessionId,paddingInt(k),h,letter,sessionId)    local d,err=require("resty.openssl.digest").new(shaAlg)    return d:final(key)
end

-- string    V_C, the client's identification string (CR and LFexcluded)
-- string    V_S, the server's identification string (CR and LFexcluded)
-- string    I_C, the payload of the client's SSH_MSG_KEXINIT
-- string    I_S, the payload of the server's SSH_MSG_KEXINIT
-- string    K_S, the host key
-- mpint     e, exchange value sent by the client
-- mpint     f, exchange value sent by the server
-- mpint     K, the shared secretlocal function getHostKey(V_C,V_S,I_C,I_S,K_S,e,f,K,shaAlg)
    local h=string.pack(">s4s4s4s4s4s4s4s4",V_C,V_S,I_C,I_S,K_S,
            paddingInt(e),
            paddingInt(f),
            paddingInt(K)
            )    local d,err=require("resty.openssl.digest").new(shaAlg)    return d:final(h)
    --return ngx[shaAlg.."_bin"](h)
endlocal function negotiate(algStr,myAlgConf)    for i,v in ipairs(myAlgConf) do        if algStr:match(v.name:literalize()) then            return v        end    endend
----------------parser event handlers----------------------function _M:handleAuthRequest(source,packet,up)    self.ctx.username=packet.username    local serviceName=packet.serviceName    local method=packet.method    local ok,cred	--There might be multi auth req packet in auth process	if method=="none" and self.BeforeAuthEvent:hasHandler() then		cred=self.BeforeAuthEvent:trigger({username=packet.username},self.ctx)		if cred and packet.username~=cred.username  then			self.ctx.username=cred.username			packet.username=cred.username			self.cred=cred			packet:pack()		end	end    if method~="none" and self.OnAuthEvent:hasHandler() then        ok=self.OnAuthEvent:trigger({username=packet.username,password=packet.password},self.ctx)		if not ok then			self:sendDown(ssh2Packet.AuthFail:new({methods="password"}):pack().allBytes)			packet.allBytes=nil			return		end		if self.cred and (packet.username~=self.cred.username or packet.password~=self.cred.password) then			packet.username=self.cred.username			packet.password=self.cred.password 			packet:pack()		end    endendfunction _M:handleDHKexInit(source,packet,up)    --get e from client and calc key    local bytes_e=packet.e    local e=bn.from_binary(bytes_e)    local y=cipherConf.y    local p=self.c2p_dh_alg.p    local k=bn.mod_exp(e,y,p)    local f=bn.mod_exp(2,y,p)    local bytes_f=f:to_binary()    local bytes_k=k:to_binary()    local k_s=pack_KEX_Host_Key()    local h=getHostKey(self.client_id_str,self.proxy_id_str,self.client_init,self.p2c_init,k_s,bytes_e,bytes_f,bytes_k,self.c2p_dh_alg.shaAlg)    self.p2c_session_id=h    self.new_c2p_IV=getKey(h,bytes_k,"A",self.p2c_session_id,self.c2p_dh_alg.shaAlg)    self.new_p2c_IV=getKey(h,bytes_k,"B",self.p2c_session_id,self.c2p_dh_alg.shaAlg)    --note the "B" character in below sentence is A greek character  --self.new_p2c_IV=getKey(h,bytes_k,"Β",self.p2c_session_id)    self.new_c2p_enc_key=getKey(h,bytes_k,"C",self.p2c_session_id,self.c2p_dh_alg.shaAlg)    self.new_p2c_enc_key=getKey(h,bytes_k,"D",self.p2c_session_id,self.c2p_dh_alg.shaAlg)    self.new_c2p_int_key=getKey(h,bytes_k,"E",self.p2c_session_id,self.c2p_dh_alg.shaAlg)    self.new_p2c_int_key=getKey(h,bytes_k,"F",self.p2c_session_id,self.c2p_dh_alg.shaAlg)    local pk, err = pkey.new(cipherConf.privkey)    local digest, err = require("resty.openssl.digest").new("SHA1")    digest:update(h)    local s,err=pk:sign(digest)    local result=ssh2Packet.DHKeyXReply:new({f=bytes_f,signH=s,K_S=k_s,key_alg="ssh-rsa"}):pack().allBytes    self:sendDown(result)    self:sendDown(ssh2Packet.Base:new({code=0x15}):pack().allBytes)    packet.allBytes=nilendfunction _M:C2PKeyXInitHandler(source,packet,up)    local kex_alg=negotiate(packet.kex_alg,cipherConf.DHAlg)    self.c2p_dh_alg=kex_alg    self.c2p_enc_alg=negotiate(packet.enc_alg_c2s,cipherConf.EncAlg)    self.p2c_enc_alg=negotiate(packet.enc_alg_s2c,cipherConf.EncAlg)    self.client_init=packet.payloadBytes    packet.allBytes=nilendfunction _M:S2PKeyXInitHandler(source,packet,up)    local kex_alg=negotiate(packet.kex_alg,cipherConf.DHAlg)    self.p2s_dh_alg=kex_alg    self.p2s_enc_alg=negotiate(packet.enc_alg_c2s,cipherConf.EncAlg)    self.s2p_enc_alg=negotiate(packet.enc_alg_s2c,cipherConf.EncAlg)    self.server_init=packet.payloadBytes    local e=bn.mod_exp(2,cipherConf.x,self.p2s_dh_alg.p)    self.p2s_e=e:to_binary()    local dataToSend=ssh2Packet.DHKeyXInit:new({e=self.p2s_e}):pack().allBytes    self:sendUp(dataToSend)    packet.allBytes=nilendfunction _M:handleDHKeyXReply(source,packet,up)    local key=packet.K_S    local bytes_f=packet.f    local f=bn.from_binary(bytes_f)    local k=bn.mod_exp(f,cipherConf.x,self.p2s_dh_alg.p)    local bytes_k=k:to_binary()    local h=getHostKey(self.proxy_id_str,self.server_id_str,    self.p2s_init,self.server_init,key,    self.p2s_e,bytes_f,bytes_k,self.p2s_dh_alg.shaAlg    )    --calc keys    self.p2s_session_id=h    self.new_p2s_IV=getKey(h,bytes_k,"A",self.p2s_session_id,self.p2s_dh_alg.shaAlg)    self.new_s2p_IV=getKey(h,bytes_k,"B",self.p2s_session_id,self.p2s_dh_alg.shaAlg)    self.new_p2s_enc_key=getKey(h,bytes_k,"C",self.p2s_session_id,self.p2s_dh_alg.shaAlg)    self.new_s2p_enc_key=getKey(h,bytes_k,"D",self.p2s_session_id,self.p2s_dh_alg.shaAlg)    self.new_p2s_int_key=getKey(h,bytes_k,"E",self.p2s_session_id,self.p2s_dh_alg.shaAlg)    self.new_s2p_int_key=getKey(h,bytes_k,"F",self.p2s_session_id,self.p2s_dh_alg.shaAlg)    --send new key    self:sendUp(ssh2Packet.Base:new({code=0x15}):pack().allBytes)    packet.allBytes=nilendfunction _M:C2PNewKeysHandler(source,packet)    --Client -- > Proxy New Key take new key into use, this package    --is encrypted and hashed with the old key according to rfc    self.c2p_stage="OK"    self.p2c_hmac=require("resty.openssl.hmac").new(self.new_p2c_int_key:sub(1,20),"sha1")    self.c2p_hmac=require("resty.openssl.hmac").new(self.new_c2p_int_key:sub(1,20),"sha1")    self.c2p_cipher=cipher.new(self.c2p_enc_alg.cipherStr)    self.c2p_cipher:init(self.new_c2p_enc_key:sub(1,16),self.new_c2p_IV:sub(1,16),{no_padding=true,is_encrypt = false})    self.p2c_cipher=cipher.new(self.p2c_enc_alg.cipherStr)    self.p2c_cipher:init(self.new_p2c_enc_key:sub(1,16),self.new_p2c_IV:sub(1,16),{no_padding=true,is_encrypt = true})    --wait for proxy server channel to establish    while(not standalone and self.p2s_stage~="OK") do        ngx.sleep(3)    end    packet.allBytes=nil    endfunction _M:S2PNewKeysHandler(source,packet)    self.p2s_stage="OK"    self.p2s_hmac=require("resty.openssl.hmac").new(self.new_p2s_int_key:sub(1,20),"sha1")    self.s2p_hmac=require("resty.openssl.hmac").new(self.new_s2p_int_key:sub(1,20),"sha1")    self.p2s_cipher=cipher.new(self.p2s_enc_alg.cipherStr)    self.p2s_cipher:init(self.new_p2s_enc_key:sub(1,16),self.new_p2s_IV:sub(1,16),{no_padding=true,is_encrypt = true})    self.s2p_cipher=cipher.new(self.s2p_enc_alg.cipherStr)    self.s2p_cipher:init(self.new_s2p_enc_key:sub(1,16),self.new_s2p_IV:sub(1,16),{no_padding=true,is_encrypt = false})    while(self.c2p_stage~="OK") do        ngx.sleep(3)    end    packet.allBytes=nil       endfunction _M:C2PChannelDataHandler(source,packet)    self.C2PDataEvent:trigger(packet,self.ctx)end
function _M:S2PChannelDataHandler(source,packet)     self.S2PDataEvent:trigger(packet,self.ctx)endfunction _M:handleAuthSuccess (source,packet,up)    --login succeeded, proporate login success event with username parameter    self.AuthSuccessEvent:trigger(self.ctx.username,self.ctx)
    self.ContextUpdateEvent:trigger(self.ctx)endfunction _M:handleAuthFail(source,packet,up)    --login fail, proporate login failure event with username parameter    self.AuthFailEvent:trigger({username=self.ctx.username,message="auth methods "..packet.methods.." supported"},self.ctx)endlocal function readVersionData(self,readMethod)    local sshHeader,err=readMethod(self.channel,4)    if(err) then        logger.log(logger.ERR,"err when reading header",err)        return nil,err    end    if sshHeader:sub(1,3)~="SSH"  then        return nil    end    --Version Exchange    local sshVersion,err=readMethod(self.channel,"*l")    if(err) then        logger.log(logger.ERR,"err when reading versiondata")        return nil,err    end    local versionData=sshHeader..sshVersion:gsub("\r?\n?","")    return versionDataend--read from channel and parselocal function recv(self,readMethod,src_cipher,up)    local sshHeader,err=readMethod(self.channel,16)        if(err) then        ngx.log(ngx.ERR,"err when reading header",err)        return nil,err     end    local headerData    if src_cipher then          headerData=src_cipher:update(sshHeader)    else        headerData=sshHeader    end    local dataLength,paddingLength=string.unpack(">I4B",headerData)    local tmp=readMethod(self.channel,dataLength-12)    local allbytes    if src_cipher then        if #tmp > 0 then			allbytes,err=headerData..src_cipher:update(tmp)        else            allbytes=headerData        end    else        allbytes=headerData..tmp    end    --todo check mac    if src_cipher then        local macData,err=readMethod(self.channel,20)            if(err) then            ngx.log(ngx.ERR,"err when reading mac",err)            return nil,err         end    end    local code=allbytes:byte(6)    local parser= up and self.C2PParser or self.S2PParser    return parser:parse(allbytes,nil,nil,options)end----------------implement processor methods---------------------function _M:processUpRequest(standalone)    self.c2p_seq=self.c2p_seq+1    local readMethod=self.channel.c2pRead    logger.log(logger.DEBUG,"process up start")           if (self.c2p_stage=="INIT") then        self:sendDown(self.proxy_id_str.."\r\n")        local versionData,err=readVersionData(self,readMethod)        if err then return nil,err end        self.client_id_str=versionData        self.c2p_stage="XKEYINIT"        self.ctx.client=versionData        local cookie=string.random(16)        local p2cKexPacket=ssh2Packet.KeyXInit:new({cookie=cookie,            kex_alg=cipherConf.DHAlg:getList(),            key_alg="ssh-rsa",            enc_alg_c2s=cipherConf.EncAlg:getList(),            enc_alg_s2c=cipherConf.EncAlg:getList(),            mac_alg_c2s="hmac-sha1",            mac_alg_s2c="hmac-sha1",            comp_alg_c2s="none",            comp_alg_s2c="none",            lan_c2s="",lan_s2c="",            kex_follows=0,        reserved=0}):pack()        self.p2c_init=p2cKexPacket.payloadBytes        self:sendDown(p2cKexPacket.allBytes)        return    end    if(self.c2p_stage=="XKEYINIT" or self.c2p_stage=="OK") then        local packet,err=recv(self,readMethod,self.c2p_cipher,true)        --if malformat packet have been received then dump it        if err then return nil,err end        return packet.allBytes    endendfunction _M:processDownRequest()
    logger.log(logger.DEBUG,"process down start")
    self.s2p_seq=self.s2p_seq+1
    local readMethod=self.channel.p2sRead
    if(self.p2s_stage=="INIT" ) then        self:sendUp(self.proxy_id_str.."\r\n")
        local versionData,err=readVersionData(self,readMethod)        if err then return nil,err end
        self.server_id_str=versionData
        self.p2s_stage ="XKEYINIT"        self.ctx.server=versionData        local cookie=string.random(16)        local p2sKexPacket=ssh2Packet.KeyXInit:new({cookie=cookie,            kex_alg=cipherConf.DHAlg:getList(),            key_alg="ssh-rsa",            enc_alg_c2s=cipherConf.EncAlg:getList(),            enc_alg_s2c=cipherConf.EncAlg:getList(),            mac_alg_c2s="hmac-sha1",            mac_alg_s2c="hmac-sha1",            comp_alg_c2s="none",            comp_alg_s2c="none",            lan_c2s="",lan_s2c="",            kex_follows=0,        reserved=0}):pack()        self.p2s_init=p2sKexPacket.payloadBytes        self:sendUp(p2sKexPacket.allBytes)
        return
    end

    if(self.p2s_stage=="XKEYINIT" or self.p2s_stage=="OK") then
        local packet,err=recv(self,readMethod,self.s2p_cipher,false)        --if malformat packet have been received, dump it        if err then return nil,err end
        return packet.allBytes
        
    end
endlocal function send(self,sshdata,cipher,hmac,seq,method,up)    if not sshdata or sshdata=="" then return end    local result,mac=sshdata    if cipher then        mac=hmac:final( string.pack(">I4",seq)..result)        hmac:reset()        result=cipher:update(result)..mac    end    if(result) then return method(self.channel,result) endend
function _M.sendUp(self,sshdata)
    local method=self.channel.p2sSend
    local _,err=send(self,sshdata,self.p2s_cipher,self.p2s_hmac,self.p2s_seq,method,true)
    if self.p2s_stage~="INIT"  then
         self.p2s_seq=self.p2s_seq+1
    end
end

function _M.sendDown(self,sshdata)
    local method=self.channel.c2pSend
    local _,err=send(self,sshdata,self.p2c_cipher,self.p2c_hmac,self.p2c_seq,method)   
    if self.c2p_stage~="INIT"  then
        self.p2c_seq=self.p2c_seq+1
    end
endfunction _M:sessionInvalid(session)    local disconn=ssh2Packet.Disconnect:new({reasonCode=1,message="you are not allowed to connect, please contact the admin"}):pack().allBytes    self:sendDown(disconn)     self.channel:shutdown()end

return _M
