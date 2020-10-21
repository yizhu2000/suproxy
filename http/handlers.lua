-- Copyright (C) Joey Zhu
local _M = {_VERSION="0.1.11"}
local cjson=require("cjson")
local utils=require("suproxy.utils.utils")
local ssoProcessors=require("suproxy.http.ssoProcessors")
local zlib = require('suproxy.utils.ffi-zlib')

--加载内容
function _M.loadUrl(url)
	res = ngx.location.capture(url,{method=ngx.HTTP_GET})
	return res.body
end

function _M.loadToolBar(localParams)
	local request_uri = ngx.var.scheme.."://"..ngx.var.server_name..":"..ngx.var.server_port..ngx.var.request_uri
	local loginPath=utils.addParamToUrl(localParams.loginUrl,"appCode",localParams.appCode)
	if request_uri~=nil then
		--告诉登录处理器需要返回的地址
		local ctx={method=ngx.var.request_method,targetURL=request_uri}
		--构建其他想要登录处理器回传的参数
		loginPath=utils.addParamToUrl(loginPath,"context",ngx.encode_base64(cjson.encode(ctx)))
	end
	--status,body,err=utils.jget(ngx.var.scheme.."://"..ngx.var.server_name..":"..ngx.var.server_port.."/auth/toolbar.html")
	body=_M.loadUrl("/auth/toolbar.html")
	local username=cjson.decode(ngx.var.userdata).user
	return string.gsub(string.gsub(body, "{{username}}", username),"{{loginUrl}}",loginPath)
end



--替换返回值内容
function _M.replaceResponse(regex,replacement)
	_M.replaceResponseMutiple({{regex=regex,replacement=replacement}})
end

--替换返回值内容,同时替换多值
function _M.replaceResponseMutiple(subs)
	local chunk, eof = ngx.arg[1], ngx.arg[2]
	local buffered = ngx.ctx.buffered
	if not buffered then
	   buffered = {}  -- XXX we can use table.new here 
	   ngx.ctx.buffered = buffered
	end
	if chunk ~= "" then
	   buffered[#buffered + 1] = chunk
	   ngx.arg[1] = nil
	end
	if eof then
		local whole = table.concat(buffered)
		ngx.ctx.buffered = nil
		-- try to unzip
		if ngx.var.upstreamEncoding=="gzip" then
		   local debody = utils.unzip(whole)
		   if debody then
				whole = debody 
		   end
		end
		-- try to add or replace response body
		-- local js_code = ...
		-- whole = whole .. js_code
		for i,v in ipairs(subs) do
			whole = string.gsub(whole, v.regex,  v.replacement)
		end
		ngx.arg[1] = whole
	end
end

--检查权限
function _M.accessCheck(localParams)
	local request_uri = ngx.var.scheme.."://"..ngx.var.server_name..":"..ngx.var.server_port..ngx.var.request_uri
	ngx.var.callbackmethod=ngx.var.request_method
	if ngx.var.http_referer~=nil then
		ngx.var.referer=string.gsub(ngx.var.http_referer,ngx.var.scheme.."://"..ngx.var.server_name..":"..ngx.var.server_port, ngx.var.backaddress)
	end

	local session = require "resty.session".open()
	local processor=ssoProcessors.getProcessor(localParams.ssoParam)
	if processor==nil then
		utils.error("can't find processor for sso protocal "..localParams.ssoParam.ssoProtocol,nil,500)
		return
	end
	--检查请求是否单点登录验证
	local result=processor:checkRequest()
	-- 不是单点验证请求
	if result.status==ssoProcessors.CHECK_STATUS.NOT_SSO_CHECK then
		--如果开启登录验证,则验证session
		ngx.log(ngx.DEBUG,"sessionid:"..ngx.encode_base64(session.id))
		if localParams.checkLogin then
			ngx.log(ngx.DEBUG,"checkLogin:true"..request_uri)
			--session 已经存在
			if session.present then
				
				ngx.var.userdata=cjson.encode(session.data.user)		
				return
			--session 不存在,直接跳转
			else
				local loginPath=utils.addParamToUrl(localParams.loginUrl,"appCode",localParams.appCode)
				if request_uri~=nil then
					--告诉登录处理器需要返回的地址
					local ctx={method=ngx.var.request_method,targetURL=request_uri}
					--构建其他想要登录处理器回传的参数
					loginPath=utils.addParamToUrl(loginPath,"context",ngx.encode_base64(cjson.encode(ctx)))
				end
				---[[
				if processor.formatLoginPath then
					loginPath=processor:formatLoginPath(loginPath)
				end
				--]]
				ngx.log(ngx.DEBUG,"loginPath:"..loginPath)
				ngx.redirect(loginPath)
				return 
			end
		--未开启登录验证,直接报错
		else
			ngx.log(ngx.DEBUG,"checkLogin:false")
			utils.error(result.message,nil,ngx.HTTP_UNAUTHORIZED)
			return
		end
	end
	result=processor:valiate()
	if result.status==ssoProcessors.CHECK_STATUS.SUCCESS then
		-- 验证成功,获取user并建立session
		ngx.var.userdata=cjson.encode(result.accountData)
		local context=utils.getArgsFromRequest("context")
		local contextJson=nil
		if context~=nil then
			contextJson=cjson.decode(ngx.decode_base64(context))
		else
			contextJson=localParams.defaultContext
		end
		
		if contextJson.method~=nil then
			ngx.var.callbackmethod=contextJson.method
		end
		session:start()
		session.data.user=result.accountData
		session:save()
		ngx.log(ngx.INFO, "Session Started -- " .. ngx.encode_base64(session.id))
		--若context中返回的最初访问的页面和当前页面不同,则直接跳转到context中指定的页面
		if contextJson.targetURL~=nil then
			--[[ --删除url中由登录处理程序附加的参数如context和xtoken参数再进行url比较
			if(ngx.req.get_uri_args()["context"]) then
				request_uri=utils.removeParamFromUrl(request_uri,"context")
			end
			if(ngx.req.get_uri_args()["x_token"]) then
				request_uri=utils.removeParamFromUrl(request_uri,"x_token")
			end
			if(ngx.req.get_uri_args()["ticket"]) then
				request_uri=utils.removeParamFromUrl(request_uri,"ticket")
			end
			if(ngx.req.get_uri_args()["params"]) then
				request_uri=utils.removeParamFromUrl(request_uri,"params")
			end
			--]]
			if contextJson.targetURL~=request_uri  then
				return ngx.redirect(contextJson.targetURL)
			end
		end
		ngx.log(ngx.INFO, "Jump to targetURL -- " .. contextJson.targetURL)
		return
	elseif result.status==ssoProcessors.CHECK_STATUS.AUTH_FAIL then
		-- 验证失败
		utils.error(result.message,"Status:"..result.status.." Message:"..result.message,500)
		return 
	else
		utils.error(result.message,"Status:"..result.status.." Message:"..result.message,500)
		return
	end
end

return _M

