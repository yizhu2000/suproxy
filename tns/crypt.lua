--- Class that handles all Oracle encryption
local cipher=require ("resty.openssl.cipher")
local rand=require("resty.openssl.rand")
require "suproxy.utils.stringUtils"
require("suproxy.utils.pureluapack")
local aes = require "resty.aes"
local _M = {

	getServerKey=function(self,pass,realpass,s_sesskey,auth_vrfy_data)
		local pw_hash = ngx.sha1_bin(realpass .. auth_vrfy_data) .. "\0\0\0\0"
		local srv_sesskey=cipher.new("aes-192-cbc"):decrypt(pw_hash,pw_hash:sub(1,16),s_sesskey,true)
		--srv_sesskey= rand.bytes(40) .. string.fromhex("0808080808080808")
		local pw_hash = ngx.sha1_bin(pass .. auth_vrfy_data) .. "\0\0\0\0"
		local result=cipher.new("aes-192-cbc"):encrypt(pw_hash,pw_hash:sub(1,16),srv_sesskey,true)
		return result,srv_sesskey
	end,

	Decrypt11g = function(self, c_sesskey, s_sesskey, auth_password, pass, salt )
		local sha1 = ngx.sha1_bin(pass .. salt) .. "\0\0\0\0"
		local server_sesskey =cipher.new("aes-192-cbc"):decrypt(sha1,sha1:sub(1,16),s_sesskey,true)
		local client_sesskey = cipher.new("aes-192-cbc"):decrypt(sha1,sha1:sub(1,16),c_sesskey,true)
		local combined_sesskey = {}
		for i=17, 40 do
		  combined_sesskey[#combined_sesskey+1] = string.char( bit.bxor(string.byte(server_sesskey, i) , string.byte(client_sesskey,i)) )
		end
		combined_sesskey = table.concat(combined_sesskey)
        print("combined_sesskey",combined_sesskey:hex())
		combined_sesskey = ( ngx.md5_bin( combined_sesskey:sub(1,16) ) .. ngx.md5_bin(combined_sesskey:sub(17) ) ):sub(1, 24)
		local p,err= cipher.new("aes-192-cbc"):decrypt(combined_sesskey,combined_sesskey:sub(1,16),auth_password)
		return client_sesskey,p:sub(17)
	end,

  -- -- - Creates an Oracle 10G password hash
  
  -- -- @param username containing the Oracle user name
  -- -- @param password containing the Oracle user password
  -- -- @return hash containing the Oracle hash
  -- HashPassword10g = function( self, username, password )
    -- local uspw = (username .. password):upper():gsub(".", "\0%1")
    -- local key = stdnse.fromhex("0123456789abcdef")

    -- -- do padding
    -- uspw = uspw .. string.rep('\0', (8 - (#uspw % 8)) % 8)

    -- local iv2 = openssl.encrypt( "DES-CBC", key, nil, uspw, false ):sub(-8)
    -- local enc = openssl.encrypt( "DES-CBC", iv2, nil, uspw, false ):sub(-8)
    -- return enc
  -- end,

  -- -- Test function, not currently in use
  -- Decrypt10g = function(self, user, pass, srv_sesskey_enc )
    -- local pwhash = self:HashPassword10g( user, pass ) .. "\0\0\0\0\0\0\0\0"
    -- local cli_sesskey_enc = stdnse.fromhex("7B244D7A1DB5ABE553FB9B7325110024911FCBE95EF99E7965A754BC41CF31C0")
    -- local srv_sesskey = openssl.decrypt( "AES-128-CBC", pwhash, nil, srv_sesskey_enc )
    -- local cli_sesskey = openssl.decrypt( "AES-128-CBC", pwhash, nil, cli_sesskey_enc )
    -- local auth_pass = stdnse.fromhex("4C5E28E66B6382117F9D41B08957A3B9E363B42760C33B44CA5D53EA90204ABE")
    -- local pass

    -- local combined_sesskey = {}
    -- for i=17, 32 do
      -- combined_sesskey[#combined_sesskey+1] = string.char( string.byte(srv_sesskey, i) ~ string.byte(cli_sesskey, i) )
    -- end
    -- combined_sesskey = openssl.md5( table.concat(combined_sesskey) )

    -- pass = openssl.decrypt( "AES-128-CBC", combined_sesskey, nil, auth_pass ):sub(17)

    -- print( stdnse.tohex( srv_sesskey ))
    -- print( stdnse.tohex( cli_sesskey ))
    -- print( stdnse.tohex( combined_sesskey ))
    -- print( "pass=" .. pass )
  -- end,

  -- -- - Performs the relevant encryption needed for the Oracle 10g response
  
  -- -- @param user containing the Oracle user name
  -- -- @param pass containing the Oracle user password
  -- -- @param srv_sesskey_enc containing the encrypted server session key as
         -- -- received from the PreAuth packet
  -- -- @return cli_sesskey_enc the encrypted client session key
  -- -- -- @return auth_pass the encrypted Oracle password
  -- Encrypt10g = function( self, user, pass, srv_sesskey_enc )

    -- local pwhash = self:HashPassword10g( user, pass ) .. "\0\0\0\0\0\0\0\0"
    -- -- We're currently using a static client session key, this should
    -- -- probably be changed to a random value in the future
    -- local cli_sesskey = stdnse.fromhex("FAF5034314546426F329B1DAB1CDC5B8FF94349E0875623160350B0E13A0DA36")
    -- local srv_sesskey = openssl.decrypt( "AES-128-CBC", pwhash, nil, srv_sesskey_enc )
    -- local cli_sesskey_enc = openssl.encrypt( "AES-128-CBC", pwhash, nil, cli_sesskey )
    -- -- This value should really be random, not this static cruft
    -- local rnd = stdnse.fromhex("4C31AFE05F3B012C0AE9AB0CDFF0C508")
    -- local auth_pass

    -- local combined_sesskey = {}
    -- for i=17, 32 do
      -- combined_sesskey[#combined_sesskey+1] = string.char( string.byte(srv_sesskey, i) ~ string.byte(cli_sesskey, i) )
    -- end
    -- combined_sesskey = openssl.md5( table.concat(combined_sesskey) )
    -- auth_pass = openssl.encrypt("AES-128-CBC", combined_sesskey, nil, rnd .. pass, true )
    -- auth_pass = stdnse.tohex(auth_pass)
    -- cli_sesskey_enc = stdnse.tohex(cli_sesskey_enc)
    -- return cli_sesskey_enc, auth_pass
  -- end,

  -- - Performs the relevant encryption needed for the Oracle 11g response
  
  -- @param pass containing the Oracle user password
  -- @param cli_sesskey unencrypted client key
  -- @param srv_sesskey_enc containing the encrypted server session key as
         -- received from the PreAuth packet
  -- @param auth_vrfy_data containing the password salt as received from the
         -- PreAuth packet
  -- @return cli_sesskey_enc the encrypted client session key
  -- @return auth_pass the encrypted Oracle password
  Encrypt11g = function( self, pass,cli_sesskey, srv_sesskey_enc, auth_vrfy_data )
    local rnd = rand.bytes(16)
    --local cli_sesskey = rand.bytes(40) .. string.fromhex("0808080808080808")
    local pw_hash = ngx.sha1_bin(pass .. auth_vrfy_data) .. "\0\0\0\0"
	local srv_sesskey=cipher.new("aes-192-cbc"):decrypt(pw_hash, pw_hash:sub(1,16),srv_sesskey_enc)
    local auth_password
    local cli_sesskey_enc
    local combined_sesskey = {}
    for i=17, 40 do
		combined_sesskey[#combined_sesskey+1] = string.char( bit.bxor(string.byte(srv_sesskey, i) ,string.byte(cli_sesskey, i) ))
    end
    combined_sesskey = table.concat(combined_sesskey)
    combined_sesskey = ( ngx.md5_bin( combined_sesskey:sub(1,16) ) .. ngx.md5_bin( combined_sesskey:sub(17) ) ):sub(1, 24)
	local cli_sesskey_enc=cipher.new("aes-192-cbc"):encrypt(pw_hash,pw_hash:sub(1,16),cli_sesskey,true)
	auth_password=cipher.new("aes-192-cbc"):encrypt(combined_sesskey,combined_sesskey:sub(1,16),rnd .. pass)
    return cli_sesskey_enc, auth_password
  end,

}
return _M