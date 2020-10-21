local sub = string.sub
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
    o.S2PDataEvent=event:new(o,"S2PDataEvent")
    return o
end
--tool for mpint format padding (rfc4251 section 5)
    if(n:byte(1)>=128)then
        return string.char(0)..n
    end
    return n
end

--tool for get e from pkcs#1 format privkey
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
-- string(mpint)    RSA modulus (N):
    local N,e=rsa_pubkey_modulus_e(cipherConf.pubkey)
    --type
    return string.pack(">s4s4s4","ssh-rsa",e,N)
end

-- HASH(K || H || "A|B|C|D|E" || session_id)
end

-- string    V_C, the client's identification string (CR and LFexcluded)
-- string    V_S, the server's identification string (CR and LFexcluded)
-- string    I_C, the payload of the client's SSH_MSG_KEXINIT
-- string    I_S, the payload of the server's SSH_MSG_KEXINIT
-- string    K_S, the host key
-- mpint     e, exchange value sent by the client
-- mpint     f, exchange value sent by the server
-- mpint     K, the shared secret
    local h=string.pack(">s4s4s4s4s4s4s4s4",V_C,V_S,I_C,I_S,K_S,
            paddingInt(e),
            paddingInt(f),
            paddingInt(K)
            )
    --return ngx[shaAlg.."_bin"](h)
end

function _M:S2PChannelDataHandler(source,packet)
    self.ContextUpdateEvent:trigger(self.ctx)
    logger.log(logger.DEBUG,"process down start")
    self.s2p_seq=self.s2p_seq+1
    local readMethod=self.channel.p2sRead
    if(self.p2s_stage=="INIT" ) then
        local versionData,err=readVersionData(self,readMethod)
        self.server_id_str=versionData
        self.p2s_stage ="XKEYINIT"
        return
    end

    if(self.p2s_stage=="XKEYINIT" or self.p2s_stage=="OK") then
        local packet,err=recv(self,readMethod,self.s2p_cipher,false)
        return packet.allBytes
        
    end
end
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
end

return _M