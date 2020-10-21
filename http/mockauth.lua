local jwt = require "resty.jwt"local utils= require "suproxy.utils.utils"local cjson=require("cjson")

--获取表单里的用户名密码,这里可以进行身份验证local args = nil
if "GET" == ngx.var.request_method then
	args = ngx.req.get_uri_args()
elseif "POST" == ngx.var.request_method then
	ngx.req.read_body()
	args = ngx.req.get_post_args()
endlocal username=args["name"]local password=args["pass"]
if username == nil or password==nil then
	ngx.log(ngx.WARN, "Username and Password can not be empty ")
	ngx.exit(ngx.HTTP_UNAUTHORIZED)
end
----模拟身份验证begin----

if username~="admin1" or  password~="aA123." then
	ngx.log(ngx.WARN, "Wrong Username or Password ")
	ngx.exit(ngx.HTTP_UNAUTHORIZED)
end

----模拟身份验证end------

--模拟签发jwt tokenlocal jwt_token = jwt:sign(
	"lua-resty-jwt",
	{
		header={typ="JWT", alg="HS256"},
		payload={accountName="admin1"}
	}
)
--获取跳转变量local redirectUrl=nillocal context=ngx.req.get_uri_args()["context"]local jsonContext=cjson.decode(ngx.decode_base64(context))
if jsonContext~=nil and jsonContext["targetURL"]~=nil then redirectUrl=jsonContext["targetURL"] else redirectUrl="/gateway/callback" end

redirectUrl="/gateway/callback"

--参数使用Post方式传递local template=[[
<form Method="POST" action="%s">
	<input type="hidden" name="x_token" value="%s" />
	<input type="hidden" name="context" value="%s" />
</form>
<script type="text/javascript">document.forms[0].submit()</script>
]]
ngx.say(string.format(template,redirectUrl,jwt_token,context))


--[[
--参数使用get redirect方式传递
redirectUrl=utils.addParamToUrl(redirectUrl,"context",ngx_decode_base64(context))
redirectUrl=utils.addParamToUrl(redirectUrl,"x_token",jwt_token)
ngx.redirect(redirectUrl)
--]]