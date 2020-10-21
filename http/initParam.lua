local cjson=require("cjson")local Global_Params = {
	appCode ="gate",
	--loginUrl="/auth/ssologin.html",
	loginUrl="/auth/mocklogin.html",
	defaultContext={
		targetURL="/",
		method="GET"
	},
	---[[
	ssoParam={
		ssoProtocol="JWT",
		secret="lua-resty-jwt"
	}
	--]]
	--[[
	ssoParam={
		ssoProtocol="CAS",
		validate_url="xxxxxxxxxxxxxx",
		service="xxxxxxxxxxxx"
	}
	--]]
	--[[
	ssoParam={
		ssoProtocol="OAUTH",
		validate_code_url="xxxxxxxxxxxxx",
		profile_url="xxxxxxxxxxxxxxx",
		callbackurl="xxxxxxxxxxx",
		client_secret="xxxxxxxxxxxxx"
	}
	--]]
}
Global_Params.ssoParam.appCode=Global_Params.appCode
Global_Params.ssoParam.loginUrl=Global_Params.loginUrl
return cjson.encode(Global_Params)
