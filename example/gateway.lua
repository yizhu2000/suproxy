--[[
This demo implements a simple gateway for TNS,TDS,SSH2,LDAP protocols.
To test this demo, modify nginx config, add following section to your
config file. Config server credential in getCredential method, then
use test/test as username/password to login.
make sure the commands.log file path is valid.
stream {
    lua_code_cache off;
    #mock logserver if you do not have one
    server {
		listen 12080;
		content_by_lua_block {
            ngx.log(ngx.DEBUG,"logserver Triggerred")
            local reqsock, err = ngx.req.socket(true)
            reqsock:settimeout(100)
            while(not err) do
                local command,err=reqsock:receive()
                if(err) then ngx.exit(0) end
                local f = assert(io.open("/data/logs/commands.log", "a"))
                if(command) then
                    f:write(command .. "\n")
                    f:close()
                end
            end
        }
	}
	#listen on ports
    server {
        listen 389;
		listen 1521;
		listen 22;
		listen 1433;
        content_by_lua_file lualib/suproxy/example/gateway.lua;
    }
}
#Session manager interfaces. if you want to view and manage your session 
#over http, this should be set.
http {
    include       mime.types;
	lua_code_cache off;
    server {
        listen       80;
        server_name  localhost;
		default_type text/html;
		location /suproxy/manage{
			content_by_lua_file  lualib/suproxy/example/session.lua;
		}
}
]]
-------------------------socket logger init-----------------------
local logger = require "resty.logger.socket"
if not logger.initted() then
	local ok, err = logger.init{
		-- logger server address
		host = '127.0.0.1',
		port = 12080,
		flush_limit = 10,
		drop_limit = 567800,
	}
	if not ok then
		ngx.log(ngx.ERR, "failed to initialize the logger: ",err)
		return
	end
end
----------------------sessiom Man init----------------------------
local sessionManager= require ("suproxy.session.sessionManager"):new{
	--redis server address
	ip="127.0.0.1",
	port=6379,
	expire=-1,
	extend=false
}
----------------------------handlers -----------------------------
--Demo for swap credentials, oauth or other network auth method should be 
--used in real world instead of hardcoded credential
local function getCredential(context,source,credential,session)
	local username=credential.username
	--if session.srvGID=="linuxServer" and session.srvID=="remote" then
		return {username="root",password="xxxxxx"}
	--end
end

--Demo for oauth password exchange 
local function oauth(context,source,credential,session)
 --show how to get password with oauth protocal,using username as code, an
 --app should be add and a password attributes should be add
    local param={
        ssoProtocol="OAUTH",
        validate_code_url="http://changeToYourOwnTokenLink",
        profile_url="http://changeToYourOwnProfile",
        client_secret="changeToYourOwnSecret",
        appcode=session.srvGID
    }
    local authenticator=ssoProcessors.getProcessor(param)
    local result=authenticator:valiate(credential.username)
    local cred
    if result.status==ssoProcessors.CHECK_STATUS.SUCCESS then
        --confirm oauth password attributes correctly configged
        cred.username=result.accountData.user
        cred.password=result.accountData.attributes.password
    end
    if not cred then return cred,"can not get cred from remote server" end
    return cred
end

--Demo for command filter
local function commandFilter(context,source,command,session)
	--change this to implement your own filter strategy
    if command:match("forbidden")then
        return nil,{message=command.." is a forbidden command",code=1234}
    end
    return command
end

local function log(username,content,session)
    local rs={
        os.date("%Y.%m.%d %H:%M:%S", ngx.time()).."\t" ,
        session.clientIP..":"..session.clientPort.."\t",
        username and username.."\t" or "UNKNOWN ",
        content.."\r\n"
    }
    local bytes, err = logger.log(table.concat(rs))
    if err then
        ngx.log(ngx.ERR, "failed to log command: ", err)
    end
end

--Demo for login logging
local function logAuth(context,source,username,session)
    local rs={
        "login with ",
        (session and session.client) and session.client or "unknown client",
        (session and session.clientVersion) and session.clientVersion or ""
    }
    log(username,table.concat(rs),session)
end

--Demo for connect logging
local function logConnect(context,source,connInfo)
    local rs={"connect to ",connInfo.srvIP..":"..connInfo.srvPort}
    log("UNKNOWN",table.concat(rs),connInfo)
end

--Demo for command logging
local function logCmd(context,source,command,reply,session)
    local username=session.username
    log(username,command,session)
    if not reply or reply=="" then return end
    local bytes, err = logger.log("------------------reply--------------------\r\n"
    ..reply:sub(1,4000)
    .."\r\n----------------reply end------------------\r\n\r\n")
    if err then
        ngx.log(ngx.ERR, "failed to log reply: ", err)
    end
end

--Demo for login fail logging
local function logAuthFail(context,source,failInfo,session)
    log(failInfo.username,
		"login fail, fail message: "..(failInfo.message or ""),
		session)
end

--Demo for self-defined authenticator
local function authenticator(context,source,credential,session)
	local result=credential.username=="test" and credential.password=="test" 
	local message=(not result) and "login with "..credential.username.." failed"
	return result,message
end

--Demo for auto response ldap search command, this Demo shows how to handle parser events
local function ldap_SearchRequestHandler(context,src,p)
    if context.command:match("pleasechangeme") then
        local packets=require("suproxy.ldap.ldapPackets")
        local response=packets.SearchResultEntry:new()
        local done=packets.SearchResultDone:new()
        response.objectName="cn=admin,dc=www,dc=test,dc=com"
        response.messageId=p.messageId
        response.attributes={
            {attrType="objectClass",values={"posixGroup","top"}},
            {attrType="cn",values={"group"}},
            {attrType="memberUid",values={"haha","test","test"}},
            {attrType="gidNumber",values={"44789"}},
            {attrType="description",values={"group"}}
        }
        done.resultCode=packets.ResultCode.success
        done.messageId=p.messageId
        response:pack() done:pack()
        context.channel:c2pSend(response.allBytes..done.allBytes)
        --stop forwarding
        p.allBytes=""
    end
end

--Demo for change the welcome info of ssh2 server
local function myWelcome(context,source)
	local digger={"\r\n",
	[[                                                     .-.   ]].."\r\n",
	[[                                                    /   \  ]].."\r\n",
	[[                                     _____.....-----|(o) | ]].."\r\n",
	[[                               _..--'          _..--|  .'' ]].."\r\n",
	[[                             .'  o      _..--''     |  | | ]].."\r\n",
	[[                            /  _/_..--''            |  | | ]].."\r\n",
	[[                   ________/  / /                   |  | | ]].."\r\n",
	[[                  | _  ____\ / /                    |  | | ]].."\r\n",
	[[ _.-----._________|| ||    \\ /                     |  | | ]].."\r\n",
	[[|=================||=||_____\\                      |__|-' ]].."\r\n",
	[[|   suproxy       ||_||_____//                      (o\ |  ]].."\r\n",
	[[|_________________|_________/                        |-\|  ]].."\r\n",
	[[ `-------------._______.----'                        /  `. ]].."\r\n",
	[[    .,.,.,.,.,.,.,.,.,.,.,.,.,                      /     \]].."\r\n",
	[[   ((O) o o o o ======= o o(O))                 ._.'      /]].."\r\n",
	[[    `-.,.,.,.,.,.,.,.,.,.,.,-'                   `.......' ]].."\r\n",
	[[                   scan me to login                        ]].."\r\n",
	"\r\n",
	}                      
	return table.concat(digger),false
end

local switch={}
--dispatch different port to different channel
--Demo for SSH2 processor
switch[22]= function()
    local ssh=require("suproxy.ssh2"):new()
    ssh.AuthSuccessEvent:addHandler(ssh,logAuth)
    ssh.BeforeAuthEvent:addHandler(ssh,getCredential)
	ssh.OnAuthEvent:addHandler(ssh,authenticator)
    ssh.AuthFailEvent:addHandler(ssh,logAuthFail)
    local cmd=require("suproxy.ssh2.commandCollector"):new()
    cmd.CommandEnteredEvent:addHandler(ssh,commandFilter)
    cmd.CommandFinishedEvent:addHandler(ssh,logCmd)
	cmd.BeforeWelcomeEvent:addHandler(ssh,myWelcome)
    ssh.C2PDataEvent:addHandler(cmd,cmd.handleDataUp)
    ssh.S2PDataEvent:addHandler(cmd,cmd.handleDataDown)
	package.loaded.my_SSHB=package.loaded.my_SSHB or
	--change to your own upstreams 
	require ("suproxy.balancer.balancer"):new{
		--{ip="127.0.0.1",port=2222,id="local",gid="linuxServer"},
		--{ip="192.168.46.128",port=22,id="remote",gid="linuxServer"},
        --{ip="192.168.1.121",port=22,id="UBUNTU14",gid="testServer"},
        {ip="192.168.1.152",port=22,id="UBUNTU20",gid="testServer"},
        --{ip="192.168.1.103",port=22,id="SUSE11",gid="testServer"},
        --{ip="192.168.1.186",port=22,id="OPENBSD",gid="testServer"},
        --{ip="192.168.1.187",port=22,id="FreeBSD",gid="testServer"},
	}
    local channel=require("suproxy.channel"):new(package.loaded.my_SSHB,ssh,{sessionMan=sessionManager})
    channel.OnConnectEvent:addHandler(channel,logConnect)
    channel:run()
end
--Demo for TNS processor
switch[1521]=function() 
    --server version is required for password substitution
    local tns=require("suproxy.tns"):new{oracleVersion=11,swapPass=false}
    tns.AuthSuccessEvent:addHandler(tns,logAuth)
    tns.CommandEnteredEvent:addHandler(tns,commandFilter)
    tns.CommandFinishedEvent:addHandler(tns,logCmd)
	tns.AuthFailEvent:addHandler(tns,logAuthFail)
    tns.BeforeAuthEvent:addHandler(tns,getCredential)
	--tns.OnAuthEvent:addHandler(tns,authenticator)
	package.loaded.my_OracleB=package.loaded.my_OracleB or
	--change to your own upstreams 
	require ("suproxy.balancer.balancer"):new{
		{ip="192.168.1.96",port=1521,id="remote",gid="oracleServer"},
		--{ip="192.168.46.157",port=1522,id="local",gid="oracleServer"},
		--{ip="192.168.1.182",port=1521,id="182",gid="oracleServer"},
        --{ip="192.168.1.190",port=1521,id="oracle10",gid="oracleServer"},
	}
    local channel=require("suproxy.channel"):new(package.loaded.my_OracleB,tns,{sessionMan=sessionManager})
    channel.OnConnectEvent:addHandler(channel,logConnect)
    channel:run()
end
--Demo for LDAP processor
switch[389]=function()
    local ldap=require("suproxy.ldap"):new()
    ldap.AuthSuccessEvent:addHandler(ldap,logAuth)
    ldap.AuthFailEvent:addHandler(ldap,logAuthFail)
    ldap.CommandEnteredEvent:addHandler(ldap,commandFilter)
    ldap.CommandFinishedEvent:addHandler(ldap,logCmd)
    ldap.BeforeAuthEvent:addHandler(ldap,getCredential)
	ldap.OnAuthEvent:addHandler(ldap,authenticator)
    ldap.c2pParser.events.SearchRequest:addHandler(ldap,ldap_SearchRequestHandler)
	--change to your own upstreams 
    local channel=require("suproxy.channel"):new({{ip="192.168.46.128",port=389,id="ldap1",gid="ldapServer"}},ldap,{sessionMan=sessionManager})
    channel.OnConnectEvent:addHandler(channel,logConnect)
    channel:run()
end
--Demo for TDS processor
switch[1433]=function()
    local tds=require("suproxy.tds"):new({disableSSL=false,catchReply=true})
    tds.AuthSuccessEvent:addHandler(tds,logAuth)
    tds.CommandEnteredEvent:addHandler(tds,commandFilter)
    tds.CommandFinishedEvent:addHandler(tds,logCmd)
    tds.BeforeAuthEvent:addHandler(tds,getCredential)
	tds.OnAuthEvent:addHandler(tds,authenticator)
    tds.AuthFailEvent:addHandler(tds,logAuthFail)
    package.loaded.my_SQLServerB=package.loaded.my_SQLServerB or
	--change to your own upstreams 
	require ("suproxy.balancer.balancer"):new{
        {ip="192.168.1.135",port=1433,id="srv12",gid="sqlServer"},
        --{ip="192.168.1.120",port=1433,id="srv14",gid="sqlServer"}
    }
    local channel=require("suproxy.channel"):new(package.loaded.my_SQLServerB,tds,{sessionMan=sessionManager})
    channel.OnConnectEvent:addHandler(channel,logConnect)
    channel:run()
end

local fSwitch = switch[tonumber(ngx.var.server_port)]  
if fSwitch then  
    fSwitch() 
end 

