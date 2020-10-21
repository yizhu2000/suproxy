local asn1 = require("suproxy.utils.asn1")
local format = string.format
local ok,cjson=pcall(require,"cjson")
if not ok then cjson = require("suproxy.utils.json") end
local logger=require "suproxy.utils.compatibleLog"
local bunpack = asn1.bunpack
local fmt = string.format
require "suproxy.utils.stringUtils"
require "suproxy.utils.pureluapack"
local event=require "suproxy.utils.event"
local tableUtils=require "suproxy.utils.tableUtils"
local extends=tableUtils.extends
local encoder,decoder=asn1.ASN1Encoder:new(),asn1.ASN1Decoder:new()
local orderTable=tableUtils.OrderedTable
local _M={}

local APPNO = {
	BindRequest=0,      BindResponse=1,     UnbindRequest=2,    SearchRequest = 3,
	SearchResultEntry=4,SearchResultDone=5, ModifyRequest=6,    ModifyResponse = 7 ,
	AddRequest=8,       AddResponse=9,      DelRequest=10,      DelResponse	= 11 ,
    ModifyDNRequest=12, ModifyDNResponse=13,CompareRequest=14,  CompareResponse =15,
    AbandonRequest =16, ExtendedRequest=23, ExtendedResponse=24,IntermediateResponse =25
}
_M.APPNO=APPNO

local ResultCode = {
    success = 0,                        operationsError =1,             protocolError =2,           timeLimitExceeded =3,                
    sizeLimitExceeded =4,               compareFalse =5,                compareTrue =6,             authMethodNotSupported =7,                
    strongerAuthRequired =8,            --[[ 9 reserved --]]            referral =10,               adminLimitExceeded =11,
    unavailableCriticalExtension =12,   confidentialityRequired =13,    saslBindInProgress =14,     noSuchAttribute =16,            
    undefinedAttributeType =17,         inappropriateMatching =18,      constraintViolation =19,    attributeOrValueExists =20,        
    invalidAttributeSyntax =21,         noSuchObject =32,               aliasProblem =33,           invalidDNSyntax =34,            
    --[[ 35 reserved for  isLeaf --]]   aliasDereferencingProblem =36,  --[[ 37-47 unused --]]      inappropriateAuthentication =48,    
    invalidCredentials =49,             insufficientAccessRights =50,   busy =51,                   unavailable =52,    
    unwillingToPerform =53,             loopDetect =54,                 --[[ 55-63 unused --]]      namingViolation =64,    
    objectClassViolation =65,           notAllowedOnNonLeaf =66,        notAllowedOnRDN =67,        entryAlreadyExists =68,        
    objectClassModsProhibited =69,      --[[ 70 reserved for CLDAP --]] affectsMultipleDSAs =71,    --[[ 72-79 unused --]]        
    other= 80
}
_M.ResultCode=ResultCode
local function encodeLDAPOp(encoder, appno, isConstructed, data)
    local asn1_type = asn1.BERtoInt(asn1.BERCLASS.Application, isConstructed, appno)
	return encoder:encode( data,asn1_type)
end
--TODO???: filter type 4 and 9 not processed, switch must be used to replace if 
local function decodeFilter(packet,pos)

    local newpos=pos
        
    local filter="("
        
        --get filter type
    local newpos, tmp = bunpack(packet, "B", newpos)
        
    local field,condition
        
    local ftype = asn1.intToBER(tmp).number
        
    local newpos,flen=decoder.decodeLength(packet,newpos);
        
    local elenlen=newpos-pos-1
	
	logger.log(logger.DEBUG,"element:-----------------\n"..string.hex(packet,pos,pos+flen+elenlen,4,8,nil,nil,1,1))	
	
	logger.log(logger.DEBUG,"filter type:"..ftype)
	
	logger.log(logger.DEBUG,"filter length:"..flen)
	
	logger.log(logger.DEBUG,"data:-----------------\n"..string.hex(packet,newpos,newpos+flen-1,4,8,nil,nil,1,1))
	
	--0 and 1 or 2 not
	if ftype<3 then
		if ftype==0 then
			filter=filter.."&"
		end
		if ftype==1 then
			filter=filter.."||"
		end
		if ftype==2 then
			filter=filter.."!"
		end
        local lp=newpos
		while(newpos-lp<flen) do
			logger.log(logger.DEBUG,"pos:"..newpos)
            local subf
			newpos,subf=decodeFilter(packet,newpos)
			filter=filter..subf
		end
		
		logger.log(logger.DEBUG,"filter012:"..filter)
	end
	
	--equal match
	if ftype==3 then
	
		newpos, field=decoder:decode(packet,newpos);
		
		logger.log(logger.DEBUG,"field:"..field)
		
		filter=filter..field
		
		filter=filter.."="
		
		newpos, condition=decoder:decode(packet,newpos)
		
		logger.log(logger.DEBUG,"condition:"..condition)
		
		filter=filter..condition
		
		logger.log(logger.DEBUG,"pos:"..newpos..";filter3:"..filter)
	end
	
	--greater or equal 
	if ftype==5 then
	
		newpos, field=decoder:decode(packet,newpos);
		
		logger.log(logger.DEBUG,"field:"..field)
		
		filter=filter..field
		
		filter=filter..">="
		
		newpos, condition=decoder:decode(packet,newpos)
		
		logger.log(logger.DEBUG,"condition:"..condition)
		
		filter=filter..condition
		
		logger.log(logger.DEBUG,"filter5:"..filter)
	end
	
	--less or equal 
	if ftype==6 then
	
		newpos, field=decoder:decode(packet,newpos);
		
		logger.log(logger.DEBUG,"field:"..field)
		
		filter=filter..field
		
		filter=filter.."<="
		
		newpos, condition=decoder:decode(packet,newpos)
		
		logger.log(logger.DEBUG,"condition:"..condition)
		
		filter=filter..condition
		
		logger.log(logger.DEBUG,"filter6:"..filter)
	end
	
	
	--present
	if ftype==7 then
		newpos,tmp=bunpack(packet, "c" .. flen, newpos)
		filter=filter..tmp.."=*"
		logger.log(logger.DEBUG,"filter7:"..filter)
	end
	
	filter=filter..")"
	return newpos,filter
end


--parse and pack common header from or to bytes
--common headers include :length messageId,opCode
_M.Packet={
    desc="base",
    parseHeader=function(self,allBytes,pos)
        local _,pos = ("B"):unpack(allBytes,pos)
        pos,self.length= decoder.decodeLength(allBytes, pos)
        pos,self.messageId = decoder:decode(allBytes, pos)    
        local pos,tmp = bunpack(allBytes, "B", pos)
        local pos,l= decoder.decodeLength(allBytes, pos)
        self.opCode = asn1.intToBER(tmp).number
        return pos
    end,
    
    parse=function(self,allBytes,pos)
        local pos=self.parseHeader(self,allBytes,pos)
        self.parsePayload(self,allBytes,pos)
        self.allBytes=allBytes
        return self
    end,
    
    parsePayload=function(self,allBytes,pos)
    end,
    
    pack=function(self)
        local payloadBytes=self:packPayload()
        local allBytes=encoder:encodeSeq(encoder:encode(self.messageId) .. encodeLDAPOp(encoder, self.opCode,true,payloadBytes))
		logger.logWithTitle(logger.DEBUG,"packing",allBytes:hex16F())
        self.allBytes=allBytes
        return self
    end,
    
    new=function(self,o) 
        local o=o or {}
        return orderTable.new(self,o)
    end
}

_M.BindRequest={
    opCode= APPNO.BindRequest,
    desc="BindRequest",
    parsePayload=function(self,payload,pos)
        pos,self.version = decoder:decode(payload,pos)
        logger.log(logger.DEBUG,"version:"..self.version )
        pos,self.username = decoder:decode(payload,pos)
        logger.log(logger.DEBUG,"username:"..self.username )
        pos,self.password = decoder:decode(payload,pos)
        if self.username==""	then
            logger.log(logger.DEBUG,"anonymous login")	   
        elseif	self.password=="" then  
            logger.log(logger.DEBUG,"unauthorized login")  
        end
        return self
    end,
    
    packPayload=function(self)
        local payloadBytes=encoder:encode(self.version)..encoder:encode(self.username)..encoder:encode(self.password,"simplePass")
        return payloadBytes
    end
}
extends(_M.BindRequest,_M.Packet)

_M.BindResponse={
    opCode= APPNO.BindResponse,
    desc="BindResponse",
    parsePayload=function(self,payload,pos)
        pos,self.resultCode=decoder:decode(payload,pos)
        return self
    end,
    packPayload=function(self)
        local payloadBytes=encoder:encode(self.resultCode,"enumerated") .. encoder:encode('') .. encoder:encode('')
        return payloadBytes
    end
}
extends(_M.BindResponse,_M.Packet)

--UnbindRequest
_M.UnbindRequest=extends({opCode=APPNO.UnbindRequest,desc="UnbindRequest"},_M.Packet)

_M.SearchRequest={
    opCode=APPNO.SearchRequest,
    desc="SearchRequest",
    parsePayload=function(self,payload,pos)
    	logger.log(logger.DEBUG,"searchRequest:")

        pos,self.baseObject = decoder:decode(payload,pos)
        
        logger.log(logger.DEBUG,"baseObject:"..self.baseObject )
        
        pos,self.scope = decoder:decode(payload,pos)
        
        logger.log(logger.DEBUG,"scope:"..self.scope )
        
        pos,self.derefAlias = decoder:decode(payload,pos)
        
        logger.log(logger.DEBUG,"derefAlias:"..self.derefAlias )
        
        pos,self.sizeLimit = decoder:decode(payload,pos)
        
        logger.log(logger.DEBUG,"sizeLimit:"..self.sizeLimit )
         
        pos,self.timeLimit = decoder:decode(payload,pos)
        
        logger.log(logger.DEBUG,"timeLimit:"..self.timeLimit )
        
        pos,self.typesOnly = decoder:decode(payload,pos)
        
        logger.log(logger.DEBUG,"typesOnly:"..(self.typesOnly and "true" or "false"))

        pos,self.filter=decodeFilter(payload,pos)
        
        logger.log(logger.DEBUG,"self.filter:"..self.filter)
        
        pos,self.attributes=decoder:decode(payload,pos)
        
        logger.log(logger.DEBUG,"self.attributes:\n"..cjson.encode(self.attributes))

        logger.log(logger.DEBUG,"searchRequest finish")
        return self
    end
}
extends(_M.SearchRequest,_M.Packet)

_M.SearchResultEntry={
    opCode= APPNO.SearchResultEntry,
    desc="SearchResponseEntry",
    parsePayload=function(self,payload,pos)
        pos,self.objectName=decoder:decode(payload,pos)
        local pos,attr=decoder:decode(payload,pos)
        print(tableUtils.printTableF(attr))
        self.attributes={}
        for i,v in ipairs(attr) do
            local t=v[1]
            table.remove(v,1)
            table.insert(self.attributes,{attrType=t,values=v})
        end
        return self
    end,
    packPayload=function(self)
        local resultObjectName = encoder:encode(self.objectName)
        local tmp=""
        for i,v in ipairs(self.attributes) do
            local attrValues=""
            for _,val in ipairs(v.values) do
                attrValues=attrValues..encoder:encode(val)
            end
            tmp=tmp..encoder:encodeSeq(encoder:encode(v.attrType)..encoder:encodeSet(attrValues))
        end
        local resultAttributes = encoder:encodeSeq(tmp)
		local payloadBytes =  resultObjectName..resultAttributes
        return payloadBytes
    end,
}
extends(_M.SearchResultEntry,_M.Packet)

_M.SearchResultDone={
    opCode= APPNO.SearchResultDone,
    desc="SearchResponseDone",
    parsePayload=function(self,payload,pos)
        pos,self.resultCode=decoder:decode(payload,pos)
        return self
    end,
    packPayload=function(self)
        local payloadBytes=encoder:encode(self.resultCode,"enumerated") .. encoder:encode('') .. encoder:encode('')
        return payloadBytes
    end
}
extends(_M.SearchResultDone,_M.Packet)

---------------------test starts here -----------------------
_M.unitTest={}
function _M.unitTest.testBindRequest()
    local bytes=string.fromhex("30840000003402010a60840000002b020103041e636e3d61646d696e2c64633d7777772c64633d746573742c64633d636f6d800661413132332e")
    local p=require("suproxy.ldap.parser"):new().C2PParser:parse(bytes)
    assert(p.version==3,p.version)
    assert(p.username=="cn=admin,dc=www,dc=test,dc=com",p.username)
    assert(p.password=="aA123.",p.password)
    p.username="cn=admin,dc=www,dc=test,dc=cn"
    p.password="Aa123."
    p:pack(encoder)
    bytes=p.allBytes
    local p=require("suproxy.ldap.parser"):new().C2PParser:parse(bytes)
    assert(p.username=="cn=admin,dc=www,dc=test,dc=cn",p.username)
    assert(p.password=="Aa123.",p.password)
end

function _M.unitTest.testSearchRequest()
    local bytes=string.fromhex("30840000008302010c638400000046041564633d7777772c64633d746573742c64633d636f6d0a01010a010002010002013c010100870b6f626a656374636c61737330840000000d040b6f626a656374636c617373a0840000002e3084000000280416312e322e3834302e3131333535362e312e342e3331390101ff040b3084000000050201640400")
    local p=require("suproxy.ldap.parser"):new().C2PParser:parse(bytes)
    assert(p.baseObject=="dc=www,dc=test,dc=com",p.baseObject)
    assert(p.scope==1,p.scope)
    assert(p.derefAlias==0,p.derefAlias)
    assert(p.timeLimit==60,p.timeLimit)
    assert(p.sizeLimit==0,p.sizeLimit)
    assert(p.typesOnly==false,p.typesOnly)
    assert(p.filter=="(objectclass=*)",p.filter)
end


function _M.unitTest.testSearchResultEntry()
    local bytes=string.fromhex("306502016a6460041564633d7777772c64633d746573742c64633d636f6d3047302c040b6f626a656374436c617373311d0403746f70040864634f626a656374040c6f7267616e697a6174696f6e300a04016f31050403646576300b0402646331050403777777")
    local p=require("suproxy.ldap.parser"):new().S2PParser:parse(bytes)
    assert(p.objectName=="dc=www,dc=test,dc=com",p.objectName)
    assert(#(p.attributes)==3,#(p.attributes))
    p:pack()
    bytes=p.allBytes
    local p=require("suproxy.ldap.parser"):new().S2PParser:parse(bytes)
    assert(p.objectName=="dc=www,dc=test,dc=com",p.objectName)
    assert(#(p.attributes)==3,#(p.attributes))
end

function _M.test()
	for k,v in pairs(_M.unitTest) do
		print("------------running  "..k)
		v()
		print("------------"..k.."  finished")
	end
end

return _M