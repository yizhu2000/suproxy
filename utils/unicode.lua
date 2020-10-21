-- Localize a few functions for a tiny speed boost, since these will be looped
-- over every char of a string
require "suproxy.utils.stringUtils"
require "suproxy.utils.pureluapack"
local byte = string.byte
local char = string.char
local pack = string.pack
local unpack = string.unpack
local concat = table.concat

local _M={}

---Decode a buffer containing Unicode data.
--@param buf The string/buffer to be decoded
--@param decoder A Unicode decoder function (such as utf8_dec)
--@param bigendian For encodings that care about byte-order (such as UTF-16),
--                 set this to true to force big-endian byte order. Default:
--                 false (little-endian)
--@return A list-table containing the code points as numbers
function _M.decode(buf, decoder, bigendian)
  local cp = {}
  local pos = 1
  while pos <= #buf do
    pos, cp[#cp+1]  = decoder(buf, pos, bigendian)
  end
  return cp
end

---Encode a list of Unicode code points
--@param list A list-table of code points as numbers
--@param encoder A Unicode encoder function (such as utf8_enc)
--@param bigendian For encodings that care about byte-order (such as UTF-16),
--                 set this to true to force big-endian byte order. Default:
--                 false (little-endian)
--@return An encoded string
function _M.encode(list, encoder, bigendian)
  local buf = {}
  for i, cp in ipairs(list) do
    buf[i] = encoder(cp, bigendian)
  end
  return table.concat(buf, "")
end

---Transcode a string from one format to another
--
--The string will be decoded and re-encoded in one pass. This saves some
--overhead vs simply passing the output of <code>unicode.encode</code> to
--<code>unicode.decode</code>.
--@param buf The string/buffer to be transcoded
--@param decoder A Unicode decoder function (such as utf16_dec)
--@param encoder A Unicode encoder function (such as utf8_enc)
--@param bigendian_dec Set this to true to force big-endian decoding.
--@param bigendian_enc Set this to true to force big-endian encoding.
--@return An encoded string
function _M.transcode(buf, decoder, encoder, bigendian_dec, bigendian_enc)
  local out = {}
  local cp
  local pos = 1
  while pos <= #buf do
    pos, cp = decoder(buf, pos, bigendian_dec)
    out[#out+1] = encoder(cp, bigendian_enc)
  end
  return table.concat(out)
end

--- Determine (poorly) the character encoding of a string
--
-- First, the string is checked for a Byte-order Mark (BOM). This can be
-- examined to determine UTF-16 with endianness or UTF-8. If no BOM is found,
-- the string is examined.
--
-- If null bytes are encountered, UTF-16 is assumed. Endianness is determined
-- by byte position, assuming the null is the high-order byte. Otherwise, if
-- byte values over 127 are found, UTF-8 decoding is attempted. If this fails,
-- the result is 'other', otherwise it is 'utf-8'. If no high bytes are found,
-- the result is 'ascii'.
--
--@param buf The string/buffer to be identified
--@param len The number of bytes to inspect in order to identify the string.
--           Default: 100
--@return A string describing the encoding: 'ascii', 'utf-8', 'utf-16be',
--        'utf-16le', or 'other' meaning some unidentified 8-bit encoding
function _M.chardet(buf, len)
  local limit = len or 100
  if limit > #buf then
    limit = #buf
  end
  -- Check BOM
  if limit >= 2 then
    local bom1, bom2 = byte(buf, 1, 2)
    if bom1 == 0xff and bom2 == 0xfe then
      return 'utf-16le'
    elseif bom1 == 0xfe and bom2 == 0xff then
      return 'utf-16be'
    elseif limit >= 3 then
      local bom3 = byte(buf, 3)
      if bom1 == 0xef and bom2 == 0xbb and bom3 == 0xbf then
        return 'utf-8'
      end
    end
  end
  -- Try bytes
  local pos = 1
  local high = false
  local utf8 = true
  while pos < limit do
    local c = byte(buf, pos)
    if c == 0 then
      if pos % 2 == 0 then
        return 'utf-16le'
      else
        return 'utf-16be'
      end
      utf8 = false
      pos = pos + 1
    elseif c > 127 then
      if not high then
        high = true
      end
      if utf8 then
        local p, cp = utf8_dec(buf, pos)
        if not p then
          utf8 = false
        else
          pos = p
        end
      end
      if not utf8 then
        pos = pos + 1
      end
    else
      pos = pos + 1
    end
  end
  if high then
    if utf8 then
      return 'utf-8'
    else
      return 'other'
    end
  else
    return 'ascii'
  end
end

---Encode a Unicode code point to UTF-16. See RFC 2781.
--
-- Windows OS prior to Windows 2000 only supports UCS-2, so beware using this
-- function to encode code points above 0xFFFF.
--@param cp The Unicode code point as a number
--@param bigendian Set this to true to encode big-endian UTF-16. Default is
--                 false (little-endian)
--@return A string containing the code point in UTF-16 encoding.
function _M.utf16_enc(cp, bigendian)
  local fmt = "<I2"
  if bigendian then
    fmt = ">I2"
  end

  if cp % 1.0 ~= 0.0 or cp < 0 then
    -- Only defined for nonnegative integers.
    return nil
  elseif cp <= 0xFFFF then
    return pack(fmt, cp)
  elseif cp <= 0x10FFFF then
    cp = cp - 0x10000
    return pack(fmt .. fmt, 0xD800 + bit.rshift(cp, 10), 0xDC00 + bit.band(cp , 0x3FF))
  else
    return nil
  end
end

---Decodes a UTF-16 character.
--
-- Does not check that the returned code point is a real character.
-- Specifically, it can be fooled by out-of-order lead- and trail-surrogate
-- characters.
--@param buf A string containing the character
--@param pos The index in the string where the character begins
--@param bigendian Set this to true to encode big-endian UTF-16. Default is
--                 false (little-endian)
--@return pos The index in the string where the character ended
--@return cp The code point of the character as a number
function _M.utf16_dec(buf, pos, bigendian)
  local fmt = "<I2"
  if bigendian then
    fmt = ">I2"
  end

  local cp
  cp, pos = unpack(fmt, buf, pos)
  if cp >= 0xD800 and cp <= 0xDFFF then
    local high = bit.lshift((cp - 0xD800) ,10)
    cp, pos = unpack(fmt, buf, pos)
    cp = 0x10000 + high + cp - 0xDC00
  end
  return pos, cp
end

---Encode a Unicode code point to UTF-8. See RFC 3629.
--
-- Does not check that cp is a real character; that is, doesn't exclude the
-- surrogate range U+D800 - U+DFFF and a handful of others.
--@param cp The Unicode code point as a number
--@return A string containing the code point in UTF-8 encoding.
function _M.utf8_enc(cp)
  local bytes = {}
  local n, mask
  if cp % 1.0 ~= 0.0 or cp < 0 then
    -- Only defined for nonnegative integers.
    return nil
  elseif cp <= 0x7F then
    -- Special case of one-byte encoding.
    return char(cp)
  elseif cp <= 0x7FF then
    n = 2
    mask = 0xC0
  elseif cp <= 0xFFFF then
    n = 3
    mask = 0xE0
  elseif cp <= 0x10FFFF then
    n = 4
    mask = 0xF0
  else
    return nil
  end

  while n > 1 do
    bytes[n] = char(0x80 + bit.band(cp, 0x3F))
    cp = bit.rshift(cp, 6)
    n = n - 1
  end
  bytes[1] = char(mask + cp)

  return table.concat(bytes)
end

---Decodes a UTF-8 character.
--
-- Does not check that the returned code point is a real character.
--@param buf A string containing the character
--@param pos The index in the string where the character begins
--@return pos The index in the string where the character ended or nil on error
--@return cp The code point of the character as a number, or an error string
function _M.utf8_dec(buf, pos)
  pos = pos or 1
  local n, mask
  local bv = byte(buf, pos)
  if bv <= 0x7F then
    return pos+1, bv
  elseif bv <= 0xDF then
    --110xxxxx 10xxxxxx
    n = 1
    mask = 0xC0
  elseif bv <= 0xEF then
    --1110xxxx 10xxxxxx 10xxxxxx
    n = 2
    mask = 0xE0
  elseif bv <= 0xF7 then
    --11110xxx 10xxxxxx 10xxxxxx 10xxxxxx
    n = 3
    mask = 0xF0
  else
    return nil, string.format("Invalid UTF-8 byte at %d", pos)
  end

  local cp = bv - mask

  if pos + n > #buf then
    return nil, string.format("Incomplete UTF-8 sequence at %d", pos)
  end
  for i = 1, n do
    bv = byte(buf, pos + i)
    if bv < 0x80 or bv > 0xBF then
      return nil, string.format("Invalid UTF-8 sequence at %d", pos + i)
    end
    cp = bit.lshift(cp ,6) + bit.band(bv , 0x3F)
  end

  return pos + 1 + n, cp
end

---Helper function for the common case of UTF-16 to UTF-8 transcoding, such as
--from a Windows/SMB unicode string to a printable ASCII (subset of UTF-8)
--string.
--@param from A string in UTF-16, little-endian
--@return The string in UTF-8
function _M.utf16to8(from)
  return _M.transcode(from, _M.utf16_dec, _M.utf8_enc, false, nil)
end

---Helper function for the common case of UTF-8 to UTF-16 transcoding, such as
--from a printable ASCII (subset of UTF-8) string to a Windows/SMB unicode
--string.
--@param from A string in UTF-8
--@return The string in UTF-16, little-endian
function _M.utf8to16(from)
  return _M.transcode(from, _M.utf8_dec, _M.utf16_enc, nil, false)
end

function _M.test()
    local str="中华A已经Bあまり哈哈哈1234567"
    local b=_M.decode(str,_M.utf8_dec,false)
    print(require("suproxy.utils.json").encode(b))
    print(_M.encode(b,_M.utf8_enc,false):hexF())
    print(str:hexF())
    local b=_M.decode(str,_M.utf8_dec,false)
    print(require("suproxy.utils.json").encode(b))
    
    local str="12345abcd"
    print(_M.utf8to16(str):hex())
    
end

return _M