local utils = require "suproxy.utils.utils"local jwt = require "resty.jwt"local cjson=require("cjson")local _M = {_VERSION="0.1.11"}

_M.CHECK_STATUS = {
	SUCCESS=0,
	NOT_SSO_CHECK=1,
	AUTH_FAIL=2,
	UNKNOWN_SSO_PROTOCAL=3
}

------JWT Processor------------local JWTProcessor={}

function JWTProcessor.new(ssoParam)
	JWTProcessor.ssoParam=ssoParam
	return JWTProcessor
end

function JWTProcessor:checkRequest()
local x_token=utils.getArgsFromRequest("x_token")
	--判断token是否传递 若没有传递,则不是JWT验证请求
	if x_token == nil then
		return {status=_M.CHECK_STATUS.NOT_SSO_CHECK,message="Not valid sso auth request"}
	end
	return {status=_M.CHECK_STATUS.SUCCESS}
end

function JWTProcessor:valiate()
	-- 验证token签名,如果验证错误,直接提示错误信息
local x_token=utils.getArgsFromRequest("x_token")
local jwt_obj = jwt:verify(self.ssoParam.secret,x_token)
	if jwt_obj.verified == false then
		return {status=_M.CHECK_STATUS.AUTH_FAIL,message="Invalid token: ".. jwt_obj.reason}
	end
	return {status=_M.CHECK_STATUS.SUCCESS,accountData={user=jwt_obj.payload.accountName,attributes=jwt_obj.payload}}
end
------JWT Processor end------------
------CAS Processor------------local CASProcessor={}

function CASProcessor.new(ssoParam)
	CASProcessor.ssoParam=ssoParam
	return CASProcessor
end

function CASProcessor:checkRequest()
	local ticket=utils.getArgsFromRequest("ticket");
	--判断ticket是否传递 若没有传递,则不是CAS验证请求
	if ticket == nil then
		return {status=_M.CHECK_STATUS.NOT_SSO_CHECK}
	end
	return {status=_M.CHECK_STATUS.SUCCESS}	
end
local function cas_ticket_verify(validate_url,service,ticket)
	-----网络请求验证begin------
	local payload = {
		service =service,
		ticket = ticket
	}
	local status, body, err = utils.jget(validate_url, ngx.encode_args(payload))
	
	if not status or status ~= 200  then 
		return  {success=false,message=err}
	end
	
	local decodeResponse=cjson.decode(body)
	
	if decodeResponse==nil or decodeResponse.serviceResponse==nil then
		return {success=false,"response format wrong, can't be parse to json"}
	end
	
	if decodeResponse.serviceResponse.authenticationFailure then
		return {success=false,
		string.format("ticket validation failure, code:%s description:%s",
		decodeResponse.serviceResponse.authenticationFailure.code,
		decodeResponse.serviceResponse.authenticationFailure.description)
		}
	end
	
	if decodeResponse.serviceResponse.authenticationSuccess then
		return {success=true,data=decodeResponse.serviceResponse.authenticationSuccess}
	end

	------网络请求验证身份end----
end

function CASProcessor:valiate()
local ticket=utils.getArgsFromRequest("ticket");
	-- 验证token签名,如果验证错误,直接提示错误信息
local cas_result = cas_ticket_verify(self.ssoParam.validate_url,self.ssoParam.service,ticket)--注意如果使用ngiam sso,则需要修改秘钥与应用中的一致
	if not cas_result.success then
		return {status=_M.CHECK_STATUS.AUTH_FAIL,message="Invalid ticket: ".. cas_result.message}
	end
	
	return {status=_M.CHECK_STATUS.SUCCESS,accountData={user=cas_result.data.user,attributes=cas_result.data}}
end
------CAS Processor end------------

------OAUTH2.0 Processor------------local OAUTHProcessor={}

function OAUTHProcessor.new(ssoParam)
	OAUTHProcessor.ssoParam=ssoParam
	return OAUTHProcessor
end

function OAUTHProcessor:checkRequest(self)
	local code=utils.getArgsFromRequest("code")
	--判断code是否传递 若没有传递,则不是OAUTH验证请求
	if code == nil then
		return {status=_M.CHECK_STATUS.NOT_SSO_CHECK,message="Not valid sso auth request"}
	end
	return {status=_M.CHECK_STATUS.SUCCESS}
end

function OAUTHProcessor:get_token(code)
	local payload = {
		appcode = self.ssoParam.appCode,
		secret = self.ssoParam.client_secret,
		code = code
	}
	local status, body, err = utils.jpost(self.ssoParam.validate_code_url,ngx.encode_args(payload))
	if not status or status ~= 200   then 
		return  {success=false,message=err}
	else 
	   local result=cjson.decode(body)
		if result.errorCode then
			return {success=false,message=body}
		end

		return {success=true,token=result.accessToken}
	end
end

function OAUTHProcessor:get_profile(token)
	local status, body, err = utils.jget(
    self.ssoParam.profile_url,
    ngx.encode_args({ 
		appcode = self.ssoParam.appCode,
		secret = self.ssoParam.client_secret,
		token= token 
	}))
	if not status or status ~= 200   then 
		return  {success=false,message=err}
	else 
		ngx.log(ngx.DEBUG,body)
	   local result=cjson.decode(body)
		if result.errorCode then
			return {success=false,message=body}
		end
		return {success=true,profile=result}
	end
end

function OAUTHProcessor:valiate(code)
	-- 验证token签名,如果验证错误,直接提示错误信息
    if not code then
        code=utils.getArgsFromRequest("code")
    end
	
	local result = self:get_token(code)
	if result.success==false then
		return {status=_M.CHECK_STATUS.AUTH_FAIL,message=result.message}
	end
	local token=result.token
	result = self:get_profile(token)
	if result.success==false then
		return {status=_M.CHECK_STATUS.AUTH_FAIL,message=result.message}
	end
	return {status=_M.CHECK_STATUS.SUCCESS,accountData={user=result.profile.accountName,attributes=result.profile}}
	
end

function OAUTHProcessor:formatLoginPath(loginUrl)
	return loginUrl
end
------JWT Processor end------------

local processorList = {  
	["JWT"] = function(param) 
		return JWTProcessor.new(param) 
	end,  
	["CAS"] = function(param)
		return CASProcessor.new(param) 
	end,
	["OAUTH"] =function(param)
		return OAUTHProcessor.new(param)
	end
}

function _M.getProcessor(ssoParam)
local p= processorList[ssoParam.ssoProtocol]
	if p~=nil then
		return p(ssoParam)
	else
		return nil
	end
end

return _M