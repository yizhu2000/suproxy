require "suproxy.utils.pureluapack"local setmetatable = setmetatablelocal tonumber = tonumberlocal reverse = string.reverselocal ipairs = ipairslocal concat = table.concatlocal insert = table.insertlocal pairs = pairslocal math = mathlocal type = typelocal char = string.charlocal bit = bit

local bunpack=function(encStr,pattern,pos)
    local data,pos=string.unpack(pattern,encStr,pos)
    return pos,data
endlocal _M={bunpack=bunpack}
_M.BERCLASS = {
  Universal = 0,
  Application = 64,
  ContextSpecific = 128,
  Private = 192
}


_M.ASN1Decoder = {
  new = function(self,o)
    o = o or {}
    setmetatable(o, self)
    self.__index = self
    o:registerBaseDecoders()
    return o
  end,

  setStopOnError = function(self, val)
    self.stoponerror = val
  end,
  
  registerBaseDecoders = function(self)
    self.decoder = {}
	--ENUMERATED
    self.decoder[string.char(0x0a)] = function(self, encStr, elen, pos)
      return self.decodeInt(encStr, elen, pos)
    end
	--BIND SIMPLE PASS ?? context tag may conflict
	self.decoder[string.char(0x80)] = function(self, encStr, elen, pos)
      return bunpack(encStr, "c" .. elen, pos)
    end
	
    self.decoder[string.char(0x8a)] = function(self, encStr, elen, pos)
      return bunpack(encStr, "c" .. elen, pos)
    end
	-- Construncted Printable String
    self.decoder[string.char(0x31)] = function(self, encStr, elen, pos)
      return pos, nil
    end

    -- Boolean
    self.decoder[string.char(0x01)] = function(self, encStr, elen, pos)
     local pos,val = bunpack(encStr, "B", pos)
      return pos, val ~=0
    end

    -- Integer
    self.decoder[string.char(0x02)] = function(self, encStr, elen, pos)
      return self.decodeInt(encStr, elen, pos)
    end

    -- Octet String
    self.decoder[string.char(0x04)] = function(self, encStr, elen, pos)
      return bunpack(encStr, "c" .. elen, pos)
    end

    -- Null
    self.decoder[string.char(0x05)] = function(self, encStr, elen, pos)
      return pos, false
    end

    -- Object Identifier
    self.decoder[string.char(0x06)] = function(self, encStr, elen, pos)
      return self:decodeOID(encStr, elen, pos)
    end

    -- Sequence
    self.decoder[string.char(0x30)] = function(self, encStr, elen, pos)
      return self:decodeSeq(encStr, elen, pos)
    end
  end,

 --- Table for registering additional tag decoders.
  --
  -- Each index is a tag number as a hex string. Values are ASN1 decoder
  -- functions.
  -- @name tagDecoders
  -- @class table
  -- @see asn1.decoder

  --- Template for an ASN1 decoder function.
  -- @name asn1.decoder
  -- @class function
  -- @param self The ASN1Decoder object
  -- @param encStr Encoded string
  -- @param elen Length of the object in bytes
  -- @param pos Current position in the string
  -- @return The decoded object
  -- @return The position after decoding

  --- Allows for registration of additional tag decoders
  -- @name ASN1Decoder.registerTagDecoders
  -- @param tagDecoders table containing decoding functions
  -- @see tagDecoders                                                  
  registerTagDecoders = function(self, tagDecoders)
    self:registerBaseDecoders()

    for k, v in pairs(tagDecoders) do
      self.decoder[k] = v
    end
  end,

  --- Decodes the ASN.1's built-in simple types
  -- @name ASN1Decoder.decode
  -- @param encStr Encoded string.
  -- @param pos Current position in the string.
  -- @return The decoded value(s).
  -- @return The position after decoding                                       
  decode = function(self, encStr, pos)
    --print("decoder start:-----------------\n")
    local etype, elen, elenlen
    local newpos = pos

    newpos, etype = bunpack(encStr, "c1", newpos)
	
    newpos, elen = self.decodeLength(encStr, newpos)
	elenlen=newpos-pos-1
	--print("element:-----------------\n"..string.hex(encStr,pos,pos+elen+elenlen,4,8,nil,nil,1,1))	
	--print("etype:"..string.format("%02X",string.byte(etype)))	
	--print("elen:"..elen)
	--print("data:-----------------\n"..string.hex(encStr,newpos,newpos+elen-1,4,8,nil,nil,1,1))		
    if self.decoder[etype] then
      return self.decoder[etype](self, encStr, elen, newpos,nil,nil,1,1)
    else
      return newpos, nil
    end
  end,
                                        
  ---
  -- Decodes length part of encoded value according to ASN.1 basic encoding
  -- rules.
  -- @name ASN1Decoder.decodeLength
  -- @param encStr Encoded string.
  -- @param pos Current position in the string.
  -- @return The length of the following value.
  -- @return The position after decoding.                                        
  decodeLength = function(encStr, pos)
    local newpos, elen = bunpack(encStr, "B", pos)
    if elen > 128 then
      elen = elen - 128
     local elenCalc = 0
     local elenNext

      for i = 1, elen do
        elenCalc = elenCalc * 256
        newpos, elenNext = bunpack(encStr, "B", newpos)
        elenCalc = elenCalc + elenNext
      end

      elen = elenCalc
    end

    return newpos, elen
  end,

   ---
  -- Decodes a sequence according to ASN.1 basic encoding rules.
  -- @name ASN1Decoder.decodeSeq
  -- @param encStr Encoded string.
  -- @param len Length of sequence in bytes.
  -- @param pos Current position in the string.
  -- @return The decoded sequence as a table.
  -- @return The position after decoding.    
                                       
  decodeSeq = function(self, encStr, len, pos)
    local seq = {}
    local sPos = 1
    local sStr

    pos, sStr = bunpack(encStr, "c" .. len, pos)

    while (sPos < len) do
     local newSeq

      sPos, newSeq = self:decode(sStr, sPos)
      if not newSeq and self.stoponerror then
        break
      end

      insert(seq, newSeq)
    end

    return pos, seq
  end,
  -- Decode one component of an OID from a byte string. 7 bits of the component
  -- are stored in each octet, most significant first, with the eighth bit set in
  -- all octets but the last. These encoding rules come from
  -- http://luca.ntop.org/Teaching/Appunti/asn1.html, section 5.9 OBJECT
  -- IDENTIFIER.               
  decode_oid_component = function(encStr, pos)
    local octet
    local n = 0

    repeat
      pos, octet = bunpack(encStr, "B", pos)
      n = n * 128 + bit.band(0x7F, octet)
    until octet < 128

    return pos, n
  end,

  --- Decodes an OID from a sequence of bytes.
  -- @name ASN1Decoder.decodeOID
  -- @param encStr Encoded string.
  -- @param len Length of sequence in bytes.
  -- @param pos Current position in the string.
  -- @return The OID as an array.
  -- @return The position after decoding.                                      
  decodeOID = function(self, encStr, len, pos)
    local last
    local oid = {}
    local octet

    last = pos + len - 1
    if pos <= last then
      oid._snmp = "06"
      pos, octet = bunpack(encStr, "B", pos)
      oid[2] = math.fmod(octet, 40)
      octet = octet - oid[2]
      oid[1] = octet/40
    end

    while pos <= last do
     local c
      pos, c = self.decode_oid_component(encStr, pos)
      oid[#oid + 1] = c
    end

    return pos, oid
  end,

  ---
  -- Decodes an Integer according to ASN.1 basic encoding rules.
  -- @name ASN1Decoder.decodeInt
  -- @param encStr Encoded string.
  -- @param len Length of integer in bytes.
  -- @param pos Current position in the string.
  -- @return The decoded integer.
  -- @return The position after decoding.                                        
  decodeInt = function(encStr, len, pos)
    if len > 16 then
      --pos, value = bunpack(encStr, ">c" .. len, pos)
      print(string.format("Unable to decode %d-byte integer at %d", len, pos))
      return nil, pos                               
    end
    
    local pos, value = bunpack(encStr, ">i" .. len, pos)
    
    return pos, value
  end
}

_M.ASN1Encoder = {
  new = function(self)
    local o = {}
    setmetatable(o, self)
    self.__index = self
    o:registerBaseEncoders()
    return o
  end,

 
  ---
  -- Encodes an ASN1 sequence
  -- @name ASN1Encoder.encodeSeq
  -- @param seqData A string of sequence data
  -- @return ASN.1 BER-encoded sequence    
                                    
  encodeSeq = function(self, seqData)
     -- 0x30  = 00110000 =  00          1                   10000
    -- hex       binary    Universal   Constructed value   Data Type = SEQUENCE (16)
    return char(0x30).. self.encodeLength(#seqData)..seqData
  end,
  
  encodeSet = function(self, seqData)
    return char(0x31).. self.encodeLength(#seqData).. seqData
  end,
  ---
  -- Encodes a given value according to ASN.1 basic encoding rules for SNMP
  -- packet creation.
  -- @name ASN1Encoder.encode
  -- @param val Value to be encoded.  -- @param vtype [Optional] type of the val, if not pass, will infer from   -- lua pack, if type is not registered, use type itself as type code of  -- ber data, and val is encode as string
  -- @return Encoded value.                           
  encode = function(self, val,vtype)
    local vtype = vtype or type(val)
    if self.encoder[vtype] then
      return self.encoder[vtype](self,val)
    else        if vtype then            local len            if val == nil or #tostring(val) == 0 then                return char(tonumber(vtype), 0)            end            len = self.encodeLength(#val)            return char(tonumber(vtype)).. len.. tostring(val)        end
    end
    return ''
  end,

  --- Table for registering additional tag encoders.
  --
  -- Each index is a lua type as a string. Values are ASN1 encoder
  -- functions.
  -- @name tagEncoders
  -- @class table
  -- @see asn1.encoder

  --- Template for an ASN1 encoder function.
  -- @name asn1.encoder
  -- @param self The ASN1Encoder object
  -- @param val The value to encode
  -- @return The encoded object
  -- @class function

  --- Allows for registration of additional tag encoders
  -- @name ASN1Decoder.registerTagEncoders
  -- @param tagEncoders table containing encoding functions
  -- @see tagEncoders                     
  registerTagEncoders = function(self, tagEncoders)
    self:registerBaseEncoders()

    for k, v in pairs(tagEncoders) do
      self.encoder[k] = v
    end
  end,

 
  --- Registers the base ASN.1 Simple types encoders
  --
  -- * boolean
  -- * integer (Lua number)
  -- * string
  -- * null (Lua nil)
  -- @name ASN1Encoder.registerBaseEncoders                                           
  registerBaseEncoders = function(self)
    self.encoder = {}
    -- Boolean encoder
    self.encoder["boolean"] = function(self, val)
      if val then
        return char(0x01,0x01,0xFF)
      else
        return char(0x01,0x01,0x00)
      end
    end

   self.encoder["table"] = function(self, val)

     local encVal = ""
      for _, v in ipairs(val) do
        encVal = encVal .. self.encode(v) -- todo: buffer?
      end

     local tableType = char(0x30)
      if val["_snmp"] then
        tableType = tonumber(val["_snmp"])
      end

      return tableType..self.encodeLength(#encVal).. encVal
    end
    -- Integer encoder
    self.encoder["number"] = function(self, val)
      local ival = self.encodeInt(val)
      local len = self.encodeLength(#ival)
      return char(0x02).. len.. ival
    end

    -- Octet String encoder
    self.encoder["string"] = function(self, val)
      local len = self.encodeLength(#val)
      return char(0x04).. len.. val
    end

    -- Null encoder
    self.encoder["nil"] = function(self, val)
      return char(0x05,0x00)
    end        -- ENUMERATED    self.encoder["enumerated"]=  function(self, val)      local ival = self.encodeInt(val)      local len = self.encodeLength(#ival)      return char(0x0a).. len.. ival    end        --simple password string    self.encoder["simplePass"] = function(self, val)      local len = self.encodeLength(#val)      return char(0x80)..len..val    end
  end,

  -- Encode one component of an OID as a byte string. 7 bits of the component are
  -- stored in each octet, most significant first, with the eighth bit set in all
  -- octets but the last. These encoding rules come from
  -- http://luca.ntop.org/Teaching/Appunti/asn1.html, section 5.9 OBJECT
  -- IDENTIFIER.             
  encode_oid_component = function(n)
    local parts = {}

    parts[1] = char(n % 128)
    while n >= 128 do
      n = bit.rshift(n, 7)
      parts[#parts + 1] = char(n % 128 + 0x80)
    end

    return reverse(concat(parts))
  end,

  ---
  -- Encodes an Integer according to ASN.1 basic encoding rules.
  -- @name ASN1Encoder.encodeInt
  -- @param val Value to be encoded.
  -- @return Encoded integer.                           
  encodeInt = function(val)
    local lsb = 0

    if val > 0 then
     local valStr = ""

      while (val > 0) do
        lsb = math.fmod(val, 256)
        valStr = valStr .. string.pack("B", lsb)
        val = math.floor(val/256)
      end

      if lsb > 127 then
        valStr = valStr .. "\0"
      end

      return reverse(valStr)

    elseif val < 0 then
     local i = 1
     local tcval = val + 256

      while tcval <= 127 do
        tcval = tcval + (math.pow(256, i) * 255)
        i = i+1
      end

     local valStr = ""

      while (tcval > 0) do
        lsb = math.fmod(tcval, 256)
        valStr = valStr ..  string.pack("B", lsb)
        tcval = math.floor(tcval/256)
      end

      return reverse(valStr)

    else -- val == 0
      return char(0)
    end
  end,

  ---
  -- Encodes the length part of a ASN.1 encoding triplet using the "primitive,
  -- definite-length" method.
  -- @name ASN1Encoder.encodeLength
  -- @param len Length to be encoded.
  -- @return Encoded length value.                                  
  encodeLength = function(len)
    if len < 128 then
      return char(len)

    else
     local parts = {}

      while len > 0 do
        parts[#parts + 1] = char(len % 256)
        len = bit.rshift(len, 8)
      end

      return char(#parts + 0x80) .. reverse(concat(parts))
    end
  end
}

  --- Converts a BER encoded type to a numeric value
--
-- This allows it to be used in the encoding function
--
-- @param class number - see <code>BERCLASS<code>
-- @param constructed boolean (true if constructed, false if primitive)
-- @param number numeric
-- @return number to be used with <code>encode</code>
                                               
function _M.BERtoInt(class, constructed, number)
 local asn1_type = class + number

  if constructed == true then
    asn1_type = asn1_type + 32
  end

  return asn1_type
end

---
-- Converts an integer to a BER encoded type table
--
-- @param i number containing the value to decode
-- @return table with the following entries:
-- * <code>class</code>
-- * <code>constructed</code>
-- * <code>primitive</code>
-- * <code>number</code>                       
function _M.intToBER(i)
 local ber = {}

  if bit.band(i, _M.BERCLASS.Application) == _M.BERCLASS.Application then
    ber.class = _M.BERCLASS.Application
  elseif bit.band(i, _M.BERCLASS.ContextSpecific) == _M.BERCLASS.ContextSpecific then
    ber.class = _M.BERCLASS.ContextSpecific
  elseif bit.band(i, _M.BERCLASS.Private) == _M.BERCLASS.Private then
    ber.class = _M.BERCLASS.Private
  else
    ber.class = _M.BERCLASS.Universal
  end

  if bit.band(i, 32) == 32 then
    ber.constructed = true
    ber.number = i - ber.class - 32

  else
    ber.primitive = true
    ber.number = i - ber.class
  end

  return ber
end


return _M
