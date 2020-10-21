--[[This Demo shows how to manage session on http modify nginx config, To test itchange the redis ip and port setting and add following section to your config filehttp {    include       mime.types;	lua_code_cache off;    server {        listen       80;        server_name  localhost;		default_type text/html;		location /suproxy/manage{			content_by_lua_file  lualib/suproxy/example/session.lua;		}}]]local utils= require "suproxy.utils.utils"local cjson=require "cjson"local redisIP="127.0.0.1"local port=6379local sessionMan=require ("suproxy.session.sessionManager"):new{ip=redisIP,port=port,expire=30}if not sessionMan then 	ngx.say("connect to Redis "..redisIP..":"..port.." failed" ) 	returnend

if ngx.var.request_uri:match("/suproxy/manage/session/kill") then
    local sid=utils.getArgsFromRcequest("sid")
    local uid=utils.getArgsFromRequest("uid")    local result
    if not sid and not uid then         result=sessionMan:clear() 
    elseif sid then 
        result=sessionMan:kill(sid) 
    else
        result=sessionMan:killSessionOfUser(uid)
    end
    ngx.say(result.." items is removed")
elseif ngx.var.request_uri:match("/suproxy/manage/session/get") then
    local sid=utils.getArgsFromRequest("sid")
    local uid=utils.getArgsFromRequest("uid")
    if not sid and not uid then ngx.say("valid sid or uid should be provided") return  end
    local result
    if sid then 
        result=sessionMan:get(sid) 
    else
        result=sessionMan:getSessionOfUser(uid)
        result=cjson.encode(result)
    end
    ngx.say(result)
elseif ngx.var.request_uri:match("/suproxy/manage/session/all") then
    local result,count=sessionMan:getAll()	ngx.say("count:"..count)
    ngx.say(cjson.encode(result))elseif ngx.var.request_uri:match("/suproxy/manage/session/clear") then    local result=sessionMan:clear()     ngx.say(result.." items is removed")
end


