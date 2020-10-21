# SuProxy

# Table of Content

[TOC]

# Introduction 

SuProxy is a event-driven Lua proxy libraries for analyzing, intercepting, load balancing and session management.  It provides APIs for

- Authentication intercept: Read or change credentials during authentication or introduce self-defined authenticator
- Command Input Intercept: monitor, filter or change command input
- Command Output Intercept: monitor, filter or change command reply
- Context Collect: Get network, user,client , server context like IP, port, client or server version etc. from connection
- Session Manage: Store session in redis and List, Kill sessions, and way to implement new Session Manager
- Protocol parser: Parse and encode protocol packets
- Load Balance: Random balancing with fault punishment, and way to implement more complex balancer

Currently, supported protocols include SSH2, ORACLE TNS, SQLSERVER TDS, LDAP etc.

|                                                              | SSH   | SQL Server | Oracle | LDAP  |
| ------------------------------------------------------------ | ----- | ---------- | ------ | ----- |
| Get Username                                                 | Y[^1] | Y[^2]      | Y      | Y[^6] |
| Get Password                                                 | Y[^1] | Y[^2]      | N      | Y[^6] |
| Change Username                                              | Y     | Y          | Y[^4]  | Y     |
| Change Password                                              | Y     | Y          | N      | Y     |
| Third-Party Auth                                             | Y     | Y          | Y[^5]  | Y     |
| Get Command                                                  | Y     | Y          | Y      | Y[^7] |
| Get Reply                                                    | Y     | Y          | N      | Y[^7] |
| Change Command                                               | Y     | Y[^3]      | Y[^3]  | N     |
| Get Network Context<br />(IP,port etc).                      | Y     | Y          | Y      | Y     |
| Get Client Context<br />(client/server program name <br />and version etc.) | Y     | Y          | Y      | N     |

[^1]: Password authentication only
[^2]: Get username and password for SQL server disables SSL encryption
[^3]: Change SQL command is not fully tested, some change like change select command to delete command may not success
[^4]: Change Username for oracle10 is not supported
[^5]: Only username based authentication supported
[^6]: SSL not supported
[^7]: Only search request and it's reply supported

SuProxy is written in pure Lua , and is designed under event-driven pattern, the use and extension of SuProxy libraries are simple: start a listener and listen on it's event, this is an example shows how to start a SSH2 listener and handle authenticate success event of SSH connection. 

```lua
server {
    listen 22;
    content_by_lua_block {
        local ssh=require("suproxy.ssh2"):new()
        local channel=require("suproxy.channel"):new({{ip="192.168.1.135",port=22}},tds)
        channel:run()
		ssh.AuthSuccessEvent:addHandler(ssh,logAuth)
    }
}
```

SuProxy provides basic load balancing ability.  The example below shows how to pass multiple upstream to channel.

```lua
package.loaded.my_SSHB=package.loaded.my_SSHB or
require ("suproxy.balancer.balancer"):new{
    {ip="127.0.0.1",port=2222,id="local",gid="linuxServer"},
    {ip="192.168.46.128",port=22,id="remote",gid="linuxServer"},
    {ip="192.168.1.121",port=22,id="UBUNTU14",gid="testServer"}
}
local channel=require("suproxy.channel"):new(package.loaded.my_SSHB,ssh)
```

SuProxy can collect and maintain session context in memory or redis , below are the information collected by SuProxy in ssh connection. 

```json
{
	"sid": "xxxxxxxxxxxx",
	"uid": "xxxx",
	"stype": "ssh2",
	"uptime": 1600831353.066,
	"ctime": 1600831353.066,
	"ctx": {
		"srvIP": "127.0.0.1",
		"client": "SSH-2.0-PuTTY_Release_0.74",
		"clientIP": "127.0.0.1",
		"clientPort": "56127",
        "username": "xxxx",
		"srvPort": 2222,
		"server": "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.1"
	}
}
```

# Installation

## Download binary(with openresty included)

Windows 64

Ubuntu x

## LuaRock

## Run Test

luajit.exe ./suproxy/test.lua 

# Synopsis

There are 4 steps to initialize a channel

1. Create a processor by processor's new() method, passing necessary to processor
2. Create a channel with upstreams info and processor
3. Handle events triggered by processor or channel
4. Start the channel

Following code create a TNS channel,and process it's events

```lua
--Create a TNS processor and passing server version to it
local tns=require("suproxy.tns"):new({oracleVersion=11})
--Create a channel with upstreams and TNS processor
local channel=require("suproxy.channel"):new({{ip="192.168.1.96",port=1521}},tns)
--Processing events
tns.AuthSuccessEvent:addHandler(tns,logAuth)
tns.CommandEnteredEvent:addHandler(tns,forbidden)
tns.CommandFinishedEvent:addHandler(tns,logCmd)
tns.BeforeAuthEvent:addHandler(tns,simpleUserPassOracle)
channel.OnConnectEvent:addHandler(channel,logConnect)
--start the channel
channel:run()
```

After channel:run() is executed, the channel will listen on the socket for new data, events will then be trigger in different occasion. user program should process those event to finished their job. Both channel and processor may trigger events.

## Processor Creation

Processors parse the stream with protocol specific parsers. 

```lua
--xxx can be ssh2 ldap tns tds for now
require("suproxy.xxx"):new(options)
```

Using above line can create different processor. Currently SSH, TDS, TNS, LDAP processors are ready. Processor may have self-defined options or not. for example, TNS processor can accept two parameters oracleVersion which specify server major version and swapPass which tell processor whether to change user password at login time, see following section for details.

## Channel Creation

Channel maintain the connection between client and server, read data from socket and hand data to different protocol processor for further processing, channel is also responsible for sending data to upstream server.

```lua
require("suproxy.channel"):new({{ip="192.168.1.97",port=1521}},tns)
```

Above line create a channel with one upstream and a TNS protocal processors. If more than one upstream is passed to channel The [default balancer](#Load-Balance) will randomly select from those upstreams. Notice that channel won't start to listen and process until channel.run() is called.

Channel provides 4 methods to read and response to client or server:

**Channel.c2pSend** put data to client-proxy socket

**Channel.p2sSend** put data to proxy-server socket

**Channel.c2pRead** read data from client-proxy socket

**Channel.p2cRead** read data from proxy-server socket

How to use it refer [Read and Response](#Read-and-Response)

channel.new method can accept an extra options  to set socket timeouts

```lua
options.c2pConnTimeout -- client-proxy connect timeout default 10000
options.c2pSendTimeout -- client-proxy send timeout default 10000
options.c2pReadTimeout -- client-proxy read timeout default 3600000
options.p2sConnTimeout --proxy-server connect timeout default 10000
options.p2sSendTimeout --proxy-server send timeout default 10000
options.p2sReadTimeout --proxy-server read timeout 3600000

require("suproxy.channel"):new(upstream,processor,options)
```

## Load Balance

SuProxy provides basic load balancing ability. Multiple upstream can be send to channel, load balancer will randomly select from given upstreams. If one upstream fail, balancer will temporarily suspend this upstream for a while. To create a balancer: call the new method of suproxy.balancer.balancer with upstream list and suspendSpan (optional, default 30 seconds), then pass the balancer to the channel's constructor like this:

```lua
--here use "package.loaded" to ensure balancer only init once across multiple request, cause balancer will maintain the state of those upstreams.
package.loaded.my_SSHB=package.loaded.my_SSHB or
require ("suproxy.balancer.balancer"):new({
    {ip="127.0.0.1",port=2222,id="local",gid="linuxServer"},
    {ip="192.168.46.128",port=22,id="remote",gid="linuxServer"},
    {ip="192.168.1.121",port=22,id="UBUNTU14",gid="testServer"}
},10)
local channel=require("suproxy.channel"):new(package.loaded.my_SSHB,ssh)
```

Each upstream must include IP,Port. Whereas ID and GID are optional fields, ID stands for identifier of this upstream server, GID stands for the group this server belongs. these two fields can be obtained from event handler.

One can easily write its own balancer by implementing getBest and blame methods. Refer balancer.balancer.lua for more information.

## Session Info and Session Management

SuProxy maintains session context includes: server IP,server port, client IP, client port, connect time,username and some processor specific attributes like client version or connect string. Below is the session context of SSH2 processor:

```json
 {
     "srvIP": "127.0.0.1",
     "client": "SSH-2.0-PuTTY_Release_0.74",
     "clientIP": "127.0.0.1",
     "clientPort": "56127",
     "username": "xxxx",
     "srvPort": 2222,
     "connTime":1600831353.066
     "server": "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.1"
}
```

These info will be passed to processor's event handler.

By default, session context is stored locally so is not shared across requests. A Redis session manager is provided to support the Redis storage. Redis session manager also provides simple session management operation like get active session list and kill session. The way to change default session manager is like this:

```lua
local sessionManager= require ("suproxy.session.sessionManager"):new{ip="127.0.0.1",port=6379,expire=-1,extend=false,timeout=2000}
local channel=require("suproxy.channel"):new(package.loaded.my_OracleB,tns,{sessionMan=sessionManager})
```

Where **IP** and **port** is the Redis server's address. **Expire** sets the default expire time span (in second) of session default 3600, -1 means never expire. **extend** indicates whether to extend the session lease after new packets were sent from client, **timeout** indicates Redis timeout in millisecond, default 5000.

LUA code example.session.lua shows how to manage session on http. Add following lines to nginx config to test it.

```nginx
 server {
    listen       80;
    server_name  localhost;
    
    ...

    location /suproxy/manage{
        content_by_lua_file  lualib/suproxy/example/session.lua;
    }
}
```

http://localhost/suproxy/manage/session/all  lists all sessions

http://localhost/suproxy/manage/session/clear kills all sessions

http://localhost/suproxy/manage/session/kill?sid=xxxx kills session by sessionID

http://localhost/suproxy/manage/session/kill?uid=xxxx kills session by uid

http://localhost/suproxy/manage/session/get?sid=xxxx  get session by sessionID

http://localhost/suproxy/manage/session/get?uid=xxxx  kill session by uid

## Event Handling

Both channel and processor triggers events, the way to add handler to event is like this

```lua
event:addHandler(context,handler)
```

Where handler is a function to handle the event, context is on what object will the handler be executed. Handler can visit the parameter defined in context object. 

Typical handler looks like this

```lua
function handler(context,eventSource,[other event params])
    -- handler logic here
end
```

At Least two parameters will be passed to handler: context and eventSource. Context is the executing context defined by addHandler method, eventSource is the object who triggered this event, for most case is the processor itself. Handler can use this to visit processor's inner parameters.

### NoReturnEvent and ReturnedEvent

There are 2 kinds of event: **NoReturnEvent** and **ReturnedEvent** , The handler of ReturnedEvents can return values while NoReturn Event's handler can't.  NoReturnEvent can have multi-handlers but Returned Event can just have one. Adding handler to a Returned Event that already has handler will overwrite the old one. Adding more handlers to a NoReturnEvent in the same case will form a handler chain, every handler in this chain will be executed one after another.

### addHandler and setHandler

For NoReturnEvent，event:addHandler appends new handler to handler chain, setHandler method clear the chain and append the handler on the head. Calling setHandler method makes sure that this is just one handler for the event now.

### Channel Event

#### OnConnectEvent 

This event triggers when connect just established.  A connect information contains following message will be passed to its handler :

```lua
{
    clientIP, --client ip address
    clientPort, --client port if tcp is used
    srvIP, --upstream server ip
    srvPort=serverPort --upstream server port if tcp is used
}
```

Here is an example to process channel's OnConnectEvent, which writes connection info on log file:

```lua
local function logConnect(context,source,connInfo)
    local rs={
        os.date("%Y.%m.%d %H:%M:%S", ngx.time()).."\t" ,
        connInfo.clientIP..":"..connInfo.clientPort.."\t",
        "connect to ",
        connInfo.srvIP..":"..connInfo.srvPort.."\r\n"
    }
    print(table.concat(rs))
end
```

result will be like 

```
2020.09.24 18:28:03	127.0.0.1:60486	connect to 127.0.0.1:2222
```

### Processor Events

Different Processors may implement different events, but all of them implements following events

- BeforeAuthEvent
- AuthSuccessEvent
- AuthFailEvent
- CommandEnteredEvent (for ssh2Processor this is triggered by commandCollector not the processor)
- CommandFinishedEvent (for ssh2Processor this is triggered by commandCollector not the processor)
- ContextUpdateEvent

Each processor event passes different parameters and a session context object to its handler.  The session context object contains all info collected by processor in this session. Below is a typical session context in SSH2.0 processor :

```
{
    "srvIP": "127.0.0.1",
    "client": "SSH-2.0-PuTTY_Release_0.74",
    "clientIP": "127.0.0.1",
    "clientPort": "56127",
    "username": "root"
    "srvPort": 2222,
    "server": "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.1"
}
```

Session context info varies with type of processor and stage of connection, Some processor don't have "client" field or "server" field (LDAP) , some have extra info like connect string (TNS). Also, in some stage of connection, username may not have been collected yet, so username will not appear in context info. However all of them contain  srvIP,srvPort,clientIP,clientPort,connTime and username will be added to context right after user authentication.

#### BeforeAuthEvent

This event triggers before user authentication, this is a perfect timing to swap user credential.  Parameters passed to its handler are **credential** and **session context** object, credential object defines as below (for TNS processor, password is absent).

```lua
{
    username,--string, username entered by user
    password --string, password entered by user
}
```

Event handler of this event can return a new credential, if new credential is returned, the new credential will be forward to upstream instead of the old ones.

Below is an example to pass the original credential to a remote server and get a new credential from it by OAUTH2.0

```lua
local function oauth(context,source,cred,session)
 --show how to get password with oauth protocal,using username as code, an app should be add and a password attributes should be add
    local param={
        ssoProtocal="OAUTH",
        validate_code_url="http://xxxxxxxxxxxx/oauth2/token",
        profile_url="http://xxxxxxxxxxxxx/oauth2/userinfo",
        client_secret="xxxxxxxxxxx",
    }
    local authenticator=authFactory.getAuthenticator(param)
    local result=authenticator:valiate({username=cred.username,password=cred.password})
    local newCred={}
    if result.status==ssoProcessors.CHECK_STATUS.SUCCESS then
        --confirm oauth password attributes correctly configged
        newCred.username=result.accountData.user
        newCred.password=result.accountData.attributes.password
    end
    if not newCred then return nil,"can not get cred from remote server" end
    return newCred
end
```

#### OnAuthEvent

Triggers when credential is authenticated. this is a perfect timing to swap user credential or  introduce self-defined authentication.  Parameters passed to its handler are **credential**(username and password) and **session context** object, credential object defines as below (for TNS processor, password is absent). Difference between BeforeAuthEvent and OnAuthEvent is this: BeforeAuthEvent triggers before any part of credential (like username) is transferred to server, while OnAuthEvent  triggers when authentication really happen and password is transported to server. For some protocol, like LDAP and TDS, this two timing is the same, for processor like SSH2  or TNS, username was transferred before password. If username need to be changed for these processors, new username must be ready in BeforeAuthEvent handler.

Event handler of this event can return auth result , An error message and a new credential(for LDAP and TDS)

This example shows how do self authenticate.

```lua
local function authenticator(context,source,credential,session)
    --OAUTH or other auth protocol should be used to swap real credential in real world
    local result=credential.username=="test" and credential.password=="test"
	if result then
		return result
    else
		local message="login with "..credential.username.." failed"
		return result,message       
    end
end
ssh.OnAuthEvent:addHandler(tns,authenticator)
```

#### AuthSuccessEvent

This event triggers after user authentication finished successfully, this is the right timing to write log file. Parameters passed to its handler are **username** and a  **session context object**

Below is an example of writing login action into log file.

```lua
local function logAuth(context,source,username,session)
    local rs={
        os.date("%Y.%m.%d %H:%M:%S", ngx.time()).."\t" ,
        session.clientIP..":"..session.clientPort.."\t",
        username.."\t",
        "login with ",
        (session and session.client) and session.client or "unknown client",
        (session and session.clientVersion) and session.clientVersion or ""
    }
    print(table.concat(rs))
end
```

result will be like this

```
2020.09.24 19:03:40	127.0.0.1:60844	root	login with SSH-2.0-PuTTY_Release_0.74
```

#### AuthFailEvent

This event triggers when user authentication failed, this is the right timing to write log file. Parameters passed to its handler are a **failInfo** and a **session context object**

failInfo defines as this

```lua
{
	username, --string, failed username 
	message --string, fail message passed
}
```

Below is an example of writing login fail action into log file.

```lua
local function logAuthFail(context,source,failInfo,session)
    local rs={
        os.date("%Y.%m.%d %H:%M:%S", ngx.time()).."\t" ,
        session.clientIP..":"..session.clientPort.."\t",
        failInfo.username.."\t",
        "login fail, fail message:  ",
        failInfo.message
    }
    print(table.concat(rs))
end
```

result will be like this

```
2020.09.24 19:27:48	127.0.0.1:61020	zhuyi	login fail, fail message: wrong password
```

#### CommandEnteredEvent 

This event will trigger before command is send to server. command may be sql/ldap request in case of database/LDAP protocol or shell command in case of SSH connection. This is the perfect timing to do command check or to change certain commands.

Parameters passed to its handler are **command string** and a **session context object**. Handler may return a new command or error message. If new command is returned, the new command will be sent to server instead of  the original one. If error message is returned then the command won't be executed and  processor will notify the client the error message. (way to notify the client varies with processor, some may prompt message, some may not ) below is an example to check command and forbid some keyword in command.

```lua
local function forbidden(context,source,command,session)
    if command:match("forbidden")then
        print("forbidden command triggered")
        return nil,{message=command.." is a forbidden command"}
    end
    return command
end
```

Below is the effect of sql execution on sqlserver

![image-20200925131448360](C:\Users\yizhu\AppData\Roaming\Typora\typora-user-images\image-20200925131448360.png)

Below is the effect of shell command on putty

![image-20200925142204775](C:\Users\yizhu\AppData\Roaming\Typora\typora-user-images\image-20200925142204775.png)

#### CommandFinishedEvent

This event triggers when command is replied from server, command may be sql/ldap request in case of database/LDAP protocol or shell command in case of SSH connection. this is the perfect timing to write command and its reply on file.

Parameters passed to its handler are command string, reply string and a context object.  Reply string may be absent in some processor (TNS reply is not collected in current version), Below is the example to log command and reply

```lua
local function logCmd(context,source,command,reply,session)
    local rs={
        os.date("%Y.%m.%d %H:%M:%S", ngx.time()).."\t" ,
        session.clientIP..":"..session.clientPort.."\t",
        username.."\t",
        command.."\r\n"
    }
    if reply then
        rs[#rs+1]="------------------reply--------------------\r\n"
        rs[#rs+1]=reply
        rs[#rs+1]="\r\n----------------reply end------------------\r\n")
    end
    print(table.concat(rs))
end
```

log file may look like this

```
2020.09.24 19:28:43	127.0.0.1:61020	root	ls
------------------reply--------------------

libc6_2.31-0ubuntu8+lp1871129~1_amd64.deb

----------------reply end------------------
```

#### ContextUpdateEvent

This event triggers when processor has collected new info in session. Listen to this event, program can get context info and construct own session state. following example shows how to record context in to Redis using resty.redis library

```lua
function contextHandler(self,source,ctx) 
    local red = require ("resty.redis"):new()
    red:set_timeouts(10000, 10000, 10000) 
    local ok, err = red:connect("127.0.0.1", 6379)
    if not ok then
        ngx.log(ngx.ERR,"failed to connect: ", err)
        return
    end
    red:set(ctx.clientIP..ctx.clientPort,cjson.encode(ctx))
end
```

### Parser and Parser Events

Every Processor has 2 parsers, c2pParser and s2pParser. c2pParser is responsible for parse client to proxy stream, s2pParser is responsible for parsing server to proxy stream. When these parser successfully parsed a packet, one parser event will be triggered. User program can listen on those event to intercept, change the packet sent to server or stop the forwarding.

Parameters passed to packet event handler is a packet constructed by the parser, which contains protocol specific information.  Handler can get or set its fields to acquire or change the content sent to server. For example, changing the version in a TNS connection can be done like this

```lua
function _M:ConnectHandler(src,packet)
    packet:setTnsVersion(314)
    packet:pack()
end
```

#### Intercept, change and stop Forwarding

This method will repack the packet, this means to calculate the bytes length, regenerate the packet header and the bytes stream  that will be sent to  server. Each time a field is changed, packet.pack() must be called. The byte stream  can be accessed by packet.allBytes.

If we don't want our packet to be forward any more. (eg. handler has already mannully responded) , simply set the packet.allBytes field to "".

```
p.allBytes=""
```

#### Read and Response

Handler can use 4 methods provided by Channel to read and response to client or server:

**Channel.c2pSend** put data to c2p socket

**Channel.p2sSend** put data to p2s socket

**Channel.c2pRead** read data from c2p socket

**Channel.p2cRead** read data from p2s socket

these four Method wrapped nginx stream socket. parameter and return value of them is the same as socket.receive and send, xxxSendMehod take one parameter: the bytes to be sent. Receive method's incoming parameter is the length or pattern for reading.

Below is an example to intercept LDAP SearchRequest and contruct response.

```lua
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
            {attrType="memberUid",values={"haha","zhuyi","joeyzhu"}},
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

local ldap=require("suproxy.ldap"):new()
ldap.c2pParser.events.SearchRequest:addHandler(ldap,ldap_SearchRequestHandler)
```

# Examples

This example.gateway demo implements a simple gateway for TNS,TDS,SSH2,LDAP protocols.
To test this demo, modify nginx config, add following section to your config file. make sure the commands.log file path is valid.

```nginx
stream {
	init_by_lua_file lualib/suproxy/init.lua;
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
```

About the interfaces for session management refer [Session Management](#Session-Info-and-Session-Management)

# SSH2Processor

SSH2 processor proxy SSHv2 protocol and supports following functions:

- Credential Acquire: Both username and password in password login.
- Credential Change: Change both username and password in password login.
- Third-Part Authenticate: Introduce self-defined authenticator.
- Intercept command input.
- Read command reply.
- Change default server welcome info.

## Context Collected(Session Object)

| field          | type   | description                                  | eg.                                       |
| -------------- | ------ | -------------------------------------------- | ----------------------------------------- |
| srvIP          | string | Upstream server IP                           | "192.168.1.7"                             |
| client         | string | Client program and version                   | "SSH-2.0-PuTTY_Release_0.74"              |
| clientIP       | string | Client IP                                    | "127.0.0.1"                               |
| clientPort     | string | Client port                                  | "56127"                                   |
| clientPlatform | string | Client OS info                               | "IBMPC/WIN_NT64-9.1.0"                    |
| username       | string | Username                                     | "root"                                    |
| srvPort        | string | Server port                                  | "22"                                      |
| server         | string | Server program and version                   | "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.1" |
| srvID          | string | Server id passed with upstream servers       | "server3"                                 |
| srvGID         | string | Server group id passed with upstream servers | "group1"                                  |

## Tested Under

- FREEBSD OpenSSH_7.8p1, OpenSSL 1.1.1d-freebsd.

- OpenBSD 6.7  OpenSSH_8.3, LibreSSL 3.1.1.

- SUSE11 OpenSSH_6.6.1p1, OpenSSL 0.9.8j-fips 07 .

- Ubuntu 20.04 LTS OpenSSH_8.2p1 Ubuntu-4ubuntu0.1, OpenSSL 1.1.1f .

- Ubuntu 14.04.4 LTS OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.6, OpenSSL 1.0.1f .

## Processor.new

### syntax

ssh2processor = processor:new(options)

### Options

none

### Example

```lua
local ssh=require("suproxy.ssh2"):new()
```

## Processor Events

### AuthSuccessEvent

This event triggers after user authentication finished successfully, thus 0x34 type packet received from server. 

#### Handler syntax

handler(context,source,username,session)

#### Handler parameters

- context: execution context that is defined when adding handler to event.
- source: a SSH2 processor instance.
- username: username entered when login.
- session: context collected by processor.

#### Example

This example shows how to write login action into log file:

```lua
local function logAuth(context,source,username,session)
    local rs={
        os.date("%Y.%m.%d %H:%M:%S", ngx.time()).."\t" ,
        session.clientIP..":"..session.clientPort.."\t",
        username.."\t",
        "login with ",
        (session and session.client) and session.client or "unknown client",
        (session and session.clientVersion) and session.clientVersion or ""
    }
    print(table.concat(rs))
end
ssh.AuthSuccessEvent:addHandler(ssh,logAuth)
```

result will be like this

```shell
2020.09.24 19:03:40	127.0.0.1:60844	root	login with SSH-2.0-PuTTY_Release_0.74
```

### AuthFailEvent

This event triggers after user authentication failed, thus 0x33 type packet received from server. 

#### Handler syntax

handler(context,source,failInfo,session)

#### Handler parameters

- context: execution context that is defined when adding handler to event.
- source: a SSH2 processor instance.
- failInfo: see below.
- session: context collected by processor.

failInfo: 

| field    | type   | description                     | eg.                                         |
| -------- | ------ | ------------------------------- | ------------------------------------------- |
| username | string | username                        | "root"                                      |
| message  | string | fail message returned by server | "auth methods publickey,password supported" |

#### Example

This example shows how to log login fail action into file.

```lua
local function logAuthFail(context,source,failInfo,session)
    local rs={
        os.date("%Y.%m.%d %H:%M:%S", ngx.time()).."\t" ,
        session.clientIP..":"..session.clientPort.."\t",
        failInfo.username.."\t",
        "login fail, fail message: ",
        failInfo.message or "",
    }
    print(table.concat(rs))
end
ssh.AuthFailEvent:addHandler(ssh,logAuthFail)
```

result will be like this

```shell
2020.10.04 18:55:10	127.0.0.1:50694	test	login fail, fail message: auth methods publickey,password supported
```

### BeforeAuthEvent[ReturnEvent]

Triggers after the first time client send AuthRequestPacket(0x32) to proxy. If a new credential is returned, this new credential will be sent to server instead of the old one

#### Handler syntax

credential,err = handler(context,source,credential,session)

#### Handler input parameters

- context: execution context that is defined when adding handler to event
- source: a SSH2 processor instance
- credential: see below
- session: context collected by processor

Credential:

| field    | type   | description | eg.    |
| -------- | ------ | ----------- | ------ |
| username | string | username    | "root" |
| password | string | password    |        |

#### Handler return values

credential: username and password shall be passed to upstream server.

err: string error message.

Credential:

| field    | type   | description | eg.    |
| -------- | ------ | ----------- | ------ |
| username | string | username    | "root" |
| password | string | password    |        |

#### Example

This example shows how to change the user inputted username and password from the credential swap from a IDP server over OAUTH2.0 .

```lua
local function oauth(context,source,credential,session)
    local param={
        ssoProtocal="OAUTH",
        validate_code_url="http://xxxxxxxxxxxxxxxx/token",
        profile_url="http://xxxxxxxxxxxxxx/userinfo",
        client_secret="xxxxxxxxxxxxxxxxxx",
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
ssh.BeforeAuthEvent:addHandler(ssh,oauth)
```

### OnAuthEvent[ReturnEvent]

Triggers when username and password are sent in AuthRequestPacket(0x32) to proxy.

#### Handler syntax

ok,message = handler(context,source,credential,session)

#### Handler input parameters

- context: execution context that is defined when adding handler to event
- source: a SSH2 processor instance
- credential: see below
- session: context collected by processor

Credential:

| field    | type   | description |
| -------- | ------ | ----------- |
| username | string | username    |
| password | string | password    |

#### Handler return values

ok: true if authenticate success.

error: string error message.

#### Example

This example shows how do self authenticate.

```lua
local function authenticator(context,source,credential,session)
    --OAUTH or other auth protocol should be used to swap real credential in real world
    local result=credential.username=="test" and credential.password=="test"
	if result then
		return result
    else
		local message="login with "..credential.username.." failed"
		return result,message       
    end
end
ssh.OnAuthEvent:addHandler(tns,authenticator)
```

### ContextUpdateEvent

This event triggers after user authentication finished successfully, thus 0x34 type packet received from server. 

#### Handler syntax

handler(context,source,session)

#### Handler parameters

- context: execution context that is defined when adding handler to event.
- source: a SSH2 processor instance.
- session: context collected by processor.

#### Example

This example shows how to print context to error file:

```lua
local function printContext(self,source,ctx) 
    ngx.log(ngx.ERR,cjson.encode(ctx))
end
ssh.ContextUpdateEvent:addHandler(ssh,printContext)
```

result will be like this:

```json
{"clientIP":"127.0.0.1","clientPort":"56948","username":"test","srvIP":"127.0.0.1","server":"SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.1","srvID":"local","srvGID":"linuxServer","srvPort":2222,"client":"SSH-2.0-PuTTY_Release_0.74"}
```

### C2PDataEvent

Triggers when client send ChannelData(0x5e) packet to proxy.

#### Handler syntax

handler(context,source,packet,session)

#### Handler parameters

- context: execution context that is defined when adding handler to event.
- source: a SSH2 processor instance.
- packet: channel data packet.
- session: context collected by processor.

packet: 

| field   | type   | description       | eg.  |
| ------- | ------ | ----------------- | ---- |
| channel | number | recipient channel | 123  |
| data    | string | data              | "A"  |

#### Example

commandCollector.lua under ssh2 directory shows how to collect command and reply from vt100 terminal.

### S2PDataEvent

Triggers when server send ChannelData(0x5e) packet to client 

#### Handler syntax

handler(context,source,packet,session)

#### Handler parameters

- context: execution context that is defined when adding handler to event.
- source: a SSH2 processor instance.
- packet: channel data packet.
- session: context collected by processor.

packet: 

| field   | type   | description       | eg.  |
| ------- | ------ | ----------------- | ---- |
| channel | number | recipient channel | 123  |
| data    | string | data              | "A"  |

#### Example

commandCollector.lua under ssh2 directory shows how to collect command and reply from vt100 terminal.

## Parser Events

SSH2Processor support following ParserEvents, refer ssh2.lua, ssh2Packets.lua, ssh2\parser.lua for more information. more detail will be given in coming document

C2PParser.events.KeyXInitEvent
C2PParser.events.AuthReqEvent
C2PParser.events.DHKeyXInitEvent
C2PParser.events.NewKeysEvent
C2PParser.events.ChannelDataEvent

S2PParser.events.KeyXInitEvent
S2PParser.events.DHKeyXReplyEvent
S2PParser.events.AuthSuccessEvent
S2PParser.events.AuthFailEvent
S2PParser.events.NewKeysEvent
S2PParser.events.ChannelDataEvent

# Command Collector

Command Collector is a VT100 style command parser, which listen on C2PDataEvent and S2PDataEvent and collects command and reply from shell server. Since shell terminal pack the command line in packet sequence, each packet just contain one character. Command Collector buffers them and mark the end of a line to reconstruct the command user entered. Any one who wants to get shell command will need to create it and listen on it's CommandEnteredEvent and CommandFinishedEvent.

Command Collector use return(0x0d) to mark the end of a command line.  

```lua
local ssh=require("suproxy.ssh2"):new()
local cmd=require("suproxy.ssh2.commandCollector"):new()
cmd.CommandEnteredEvent:addHandler(ssh,forbidden)
cmd.CommandFinishedEvent:addHandler(ssh,logCmd)
```

Unicode command and following hotkey is now supported by CommandCollector. Full vt100 escape list can be found here http://ascii-table.com/ansi-escape-sequences-vt-100.php 

- up down arrow
- ctrl+u
- left arrow or ctrl+b
- right arrow or ctrl+f
- home or ctrl+a
- end or ctrl+e
- delete or control+d
- tab 
- backspace
- ctrl+c
- ctrl+? 
- enter

### CommandEnteredEvent[ReturnEvent]

Triggers after Return key (0x0d) been entered by client , if new command is returned then this new command will be sent to server, if error is returned, no command will be sent and error message will be displayed on client.

#### Handler syntax

newCommand,err = handler(context,source,command,session)

#### Handler input parameters

- context: execution context that is defined when adding handler to event.
- source: a SSH2 processor instance.
- command: command string.
- session: context collected by processor.

#### Handler return value

newCommand: command string to be send to server.

err: error message and code, format:

| field   | type   | description   | required |
| ------- | ------ | ------------- | -------- |
| message | string | error message | required |
| code    | number | error code    | optional |

#### Example

This example shows how to filter user input by checking keyword:

```lua
local function commandFilter(context,source,command,session)
    if command:match("forbidden")then
        return nil,{message=command.." is a forbidden command"}
    end
    return command
end
local ssh=require("suproxy.ssh2"):new()
local cmd=require("suproxy.ssh2.commandCollector"):new()
ssh.C2PDataEvent:addHandler(cmd,cmd.handleDataUp)
ssh.S2PDataEvent:addHandler(cmd,cmd.handleDataDown)
cmd.CommandEnteredEvent:addHandler(ssh,commandFilter)
```

### CommandFinishedEvent

This event triggers when command is replied from server.

#### Handler syntax

handler(context,source,command,reply,session)

#### Handler parameters

- context: execution context that is defined when adding handler to event.
- source: a SSH2 processor instance.
- command: command string.
- reply: command reply string.
- session: context collected by processor.

#### Example

This example shows how to  log command and reply:

```lua
local function logCmd(context,source,command,reply,session)
    local rs={
        os.date("%Y.%m.%d %H:%M:%S", ngx.time()).."\t" ,
        session.clientIP..":"..session.clientPort.."\t",
        username.."\t",
        command.."\r\n"
    }
    if reply then
        rs[#rs+1]="------------------reply--------------------\r\n"
        rs[#rs+1]=reply
        rs[#rs+1]="\r\n----------------reply end------------------\r\n")
    end
    print(table.concat(rs))
end
```

result will be like this:

```json
2020.09.24 19:28:43	127.0.0.1:61020	root	ls
------------------reply--------------------

libc6_2.31-0ubuntu8+lp1871129~1_amd64.deb

----------------reply end------------------
```

### BeforeWelcomeEvent[ReturnEvent]

Triggers when first data is received from server, your can handle this event to display self-defined welcome info or introduce some extra authentication.

#### Handler syntax

newWelcome,prepend = handler(context,source,session)

#### Handler input parameters

- context: execution context that is defined when adding handler to event.
- source: a SSH2 processor instance.
- session: context collected by processor.

#### Handler return value

newWelcome: new welcome string.

prepend: boolean value indicate whether to prepend new welcome before original welcome, if false original welcome will be substitute.

#### Example

This example shows how to change the welcome of linux to an ascii image:

```lua
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
	"\r\n",
	}                      
	return table.concat(digger),false
end
local ssh=require("suproxy.ssh2"):new()
local cmd=require("suproxy.ssh2.commandCollector"):new()
cmd.BeforeWelcomeEvent:addHandler(ssh,myWelcome)
```

# TNSProcessor

TNS processor proxy TNS protocol and supports following functions:

- Username Acquire.
- Username Change (for oracle 11g+).
- Password Change (for oracle 11g Only)
- Introduce self-defined authenticator
- Intercept SQL input.

## Context Collected(Session Object)

| field          | type   | description                                  | eg.                                                    |
| -------------- | ------ | -------------------------------------------- | ------------------------------------------------------ |
| srvIP          | string | Upstream server IP                           | "192.168.1.7"                                          |
| client         | string | Client program                               | "navicat"                                              |
| clientIP       | string | Client IP                                    | "127.0.0.1"                                            |
| clientPort     | string | Client port                                  | "56127"                                                |
| clientPlatform | string | Client OS info                               | "IBMPC/WIN_NT64-9.1.0"                                 |
| username       | string | Username                                     | "scott"                                                |
| srvPort        | string | Server port                                  | "1521"                                                 |
| serverVer      | string | Server version                               | "11.2.0.1.0"                                           |
| srvID          | string | Server id passed with upstream servers       | "server3"                                              |
| srvGID         | string | Server group id passed with upstream servers | "group1"                                               |
| srvPlatform    | string | Server OS info                               | "x86_64/Linux 2.4.xx"                                  |
| tnsVer         | number | TNS version number                           | 314                                                    |
| connStr        | string | Connect string client send to server         | "(DESCRIPTION=(CONNECT_DATA=...(HOST=xxx)(PORT=xxx)))" |

## Tested Under

Tested Server:

- Oracle 11g 64bit on Linux.
- Oracle 12c 64bit on Windows 2008 server.
- Oracle 10g 32bit on XP sp1.

Tested Client:

- Navicat Premium 15 64bit (oci 19_6)
- Navicat Premius 12 32bit  (oci 11_2)
- PLSQL 11.2 64bit
- SQLPlus 11.2 64bit
- OJDBC8（Thin Client）

## Processor.new

### syntax

tnsProcessor = processor:new(options)

### Options

| field         | type   | description                                                  | required and default |
| ------------- | ------ | ------------------------------------------------------------ | -------------------- |
| oracleVersion | number | Server version                                               | required             |
| swapPass      | bool   | Indicate password will be changed during authenticate. If set, processor will try to parse password hash for oracle 11g. **It is not recommended to set this flag**. | default false        |

### Example

```lua
local tns=require("suproxy.tns"):new()
```

## Processor Events

### AuthSuccessEvent

This event triggers after user authentication finished successfully and version data been exchanged.

#### Handler syntax

handler(context,source,username,session)

#### Handler parameters

- context: execution context that is defined when adding handler to event.
- source: a TNS processor instance.
- username: username entered when login.
- session: context collected by processor.

#### Example

This example shows how to write login action into log file:

```lua
local function logAuth(context,source,username,session)
    local rs={
        os.date("%Y.%m.%d %H:%M:%S", ngx.time()).."\t" ,
        session.clientIP..":"..session.clientPort.."\t",
        username.."\t",
        "login with ",
        (session and session.client) and session.client or "unknown client",
        (session and session.clientVersion) and session.clientVersion or ""
    }
    print(table.concat(rs))
end
tns.AuthSuccessEvent:addHandler(tns,logAuth)
```

result will be like this

```shell
2020.09.17 15:45:13	127.0.0.1:20873	c##scott	login with navicat.exe
```

### AuthFailEvent

This event triggers after user authentication failed.

#### Handler syntax

handler(context,source,failInfo,session)

#### Handler parameters

- context: execution context that is defined when adding handler to event.
- source: a TNS processor instance.
- failInfo: see below.
- session: context collected by processor.

failInfo: 

| field                          | type   | description                     |
| ------------------------------ | ------ | ------------------------------- |
| username                       | string | username                        |
| message(**not supported yet**) | string | fail message returned by server |

#### Example

This example shows how to log login fail action into file.

```lua
local function logAuthFail(context,source,failInfo,session)
    local rs={
        os.date("%Y.%m.%d %H:%M:%S", ngx.time()).."\t" ,
        session.clientIP..":"..session.clientPort.."\t",
        failInfo.username.."\t",
        "login fail, fail message: ",
        failInfo.message or "",
    }
    print(table.concat(rs))
end
tns.AuthFailEvent:addHandler(tns,logAuthFail)
```

result will be like this

```
2020.10.04 18:55:10	127.0.0.1:50694	test	login fail, fail message: 
```

### BeforeAuthEvent[ReturnEvent]

Triggers before authentication request is sent.  Password in handler's return value will be ignore if the server version is not 11g or swapPass option is turned off. If password or username need to be changed, new credential must be ready in this event handler but not the OnAuthEvent handler.

#### Handler syntax

credential,err = handler(context,source,credential,session)

#### Handler input parameters

- context: execution context that is defined when adding handler to event.
- source: a TNS processor instance.
- credential: see below.
- session: context collected by processor.

Credential:

| field    | type   | description                   |
| -------- | ------ | ----------------------------- |
| username | string | username from client to proxy |

#### Handler return values

credential: username and password shall be passed to upstream server.

err: string error message.

Credential:

| field    | type   | description                                                  | required and default         |
| -------- | ------ | ------------------------------------------------------------ | ---------------------------- |
| username | string | real username for login                                      | required for username change |
| password | string | real password for login, ignored when swapPass is false or oracleVersion is not 11 | required for password change |
| temppass | string | password user entered when login, this must be provided and must equal to the password user entered when login in order to change password | required for password change |

#### Example

This example shows how to change the user inputted username and password.

```lua
local function getCredential(context,source,credential,session)
	return {username="scott",temppass="temppass",password="tiger"}
end
tns.BeforeAuthEvent:addHandler(tns,getCredential)
```

### OnAuthEvent[ReturnEvent]

Triggers when auth request is sent to proxy. 

#### Handler syntax

ok,message = handler(context,source,credential,session)

#### Handler input parameters

- context: execution context that is defined when adding handler to event
- source: a TNS processor instance
- credential: see below
- session: context collected by processor

Credential:

| field    | type   | description                                                  |
| -------- | ------ | ------------------------------------------------------------ |
| username | string | username                                                     |
| password | string | password, not available if the server version is not 11g or swapPass option is turned off or temppass return in BeforeAuthEvent handler does not equal user input |

#### Handler return values

ok: true if authenticate success.

error: string error message.

#### Example

This example shows how do self authenticate.

```lua
local function authenticator(context,source,credential,session)
    --OAUTH or other auth protocol should be used to swap real credential in real world
    local result=credential.username=="xxxxxxx" 
	if result then
		return result
    else
		local message="login with "..credential.username.." failed"
		return result,message       
    end
end
tns.OnAuthEvent:addHandler(tns,authenticator)
```

### ContextUpdateEvent

This event triggers twice during connection establishing. Firstly when session request sent, at this occasion username will be added to context. Secondly when version data is responded from server, then the version data includes major, minor, build, sub build, fix will be added to context.

#### Handler syntax

handler(context,source,session)

#### Handler parameters

- context: execution context that is defined when adding handler to event.
- source: a TNS processor instance.
- session: context collected by processor.

#### Example

This example shows how to print context to error file:

```lua
local function printContext(self,source,ctx) 
    ngx.log(ngx.ERR,cjson.encode(ctx))
end
tns.ContextUpdateEvent:addHandler(tns,printContext)
```

result will be like this:

```json
{"tnsVer":314,"clientIP":"127.0.0.1","srvGID":"oracleServer","username":"scott","connStr":"(DESCRIPTION=(CONNECT_DATA=(SERVICE_NAME=ORCL)(CID=(PROGRAM=C:\\Program?Files\\PremiumSoft\\Navicat?Premium?15\\navicat.exe)(HOST=DESKTOP-PNO06LC)(USER=xxxxx)))(ADDRESS=(PROTOCOL=tcp)(HOST=127.0.0.1)(PORT=1521)))","srvIP":"192.168.1.96","clientPort":"58771","srvID":"remote","client":"navicat.exe","srvPlatform":"x86_64\/Linux 2.4.xx","serverVer":"11.2.0.1.0","clientPlatform":"IBMPC\/WIN_NT64-9.1.0","srvPort":1521}
```

### CommandEnteredEvent[ReturnEvent]

Triggers when SQL request be sent to server , if new command is returned then this new command will be sent to server, if error is returned, no command will be sent and error message will be displayed on client. 

#### Handler syntax

newCommand,err = handler(context,source,command,session)

#### Handler input parameters

- context: execution context that is defined when adding handler to event.
- source: a TNS processor instance.
- command: command string.
- session: context collected by processor.

#### Handler return value

newCommand: command string to be send to server.

err: error message and code, format:

| field   | type   | description   | required |
| ------- | ------ | ------------- | -------- |
| message | string | error message | required |
| code    | number | error code    | optional |

#### Example

This example shows how to filter user input by checking keyword:

```lua
local function commandFilter(context,source,command,session)
    if command:match("forbidden")then
        return nil,{message=command.." is a forbidden command"}
    end
    return command
end
local tns=require("suproxy.tns"):new()
tns.CommandEnteredEvent:addHandler(tns,commandFilter)
```

### CommandFinishedEvent

This event triggers when command is replied from server.

#### Handler syntax

handler(context,source,command,reply,session)

#### Handler parameters

- context: execution context that is defined when adding handler to event.
- source: a TNS processor instance.
- command: command string.
- reply: not supported yet.
- session: context collected by processor.

#### Example

This example shows how to  log command and reply:

```lua
local function logCmd(context,source,command,reply,session)
    local rs={
        os.date("%Y.%m.%d %H:%M:%S", ngx.time()).."\t" ,
        session.clientIP..":"..session.clientPort.."\t",
        username.."\t",
        command.."\r\n"
    }
    print(table.concat(rs))
end
```

result will be like this:

```shell
2020.09.17 17:44:32	127.0.0.1:27634	scott	ALTER SESSION SET CURRENT_SCHEMA = scott
```

## Parser Events

tnsProcessor support following ParserEvents, refer tns.lua, tnsPackets.lua, tns\parser.lua for more information. more detail will be given in coming document
C2PParser.events.ConnectEvent:setHandler
C2PParser.events.AuthRequestEvent
C2PParser.events.SessionRequestEvent
C2PParser.events.SetProtocolEvent
C2PParser.events.SQLRequestEvent
C2PParser.events.Piggyback1169
C2PParser.events.Piggyback116b
C2PParser.events.MarkerEvent

S2PParser.events.SessionResponseEvent
S2PParser.events.VersionResponseEvent
S2PParser.events.SetProtocolEvent
S2PParser.events.AcceptEvent
S2PParser.events.AuthErrorEvent:setHandler

# TDSProcessor

TDS processor proxy TDS protocol and supports following functions:

- Username and password Acquire.
- Username and password Change.
- Introduce self-defined authenticator
- Intercept SQL input.
- Read SQL reply.

*** note read and change the username or password will disable SSL encryption in login process**

## Context Collected(Session Object)

| field      | type   | description                                           | eg.           |
| ---------- | ------ | ----------------------------------------------------- | ------------- |
| srvIP      | string | Upstream server IP                                    | "192.168.1.7" |
| client     | string | Client program (Not available if disableSSL is false) | "Navicat"     |
| clientIP   | string | Client IP                                             | "127.0.0.1"   |
| clientPort | string | Client port                                           | "56127"       |
| clientVer  | string | Client version (Not available if disableSSL is false) | "00000007"    |
| username   | string | Username (Not available if disableSSL is false)       | "sa"          |
| srvPort    | string | Server port                                           | "1433"        |
| serverVer  | string | Server version                                        | "17.02.0.00"  |
| srvID      | string | Server id passed with upstream servers                | "server3"     |
| srvGID     | string | Server group id passed with upstream servers          | "group1"      |
| libName    | string | Library name (Not available if disableSSL is false)   | "ODBC"        |
| tdsVer     | string | TDS protocol version                                  | "04000074"    |

## Tested Under

Tested Server:

- SQL Server 2012.
- SQL Server 2014

Tested Client:

- Navicat Premium 15 64bit 
- Navicat Premius 12 32bit 

## Processor.new

### syntax

tdsProcessor = processor:new(options)

### Options

| field      | type | description                                                  | required and default |
| ---------- | ---- | ------------------------------------------------------------ | -------------------- |
| disableSSL | bool | Whether to stop SSL during login time.  This must be set if username or password need to be read or change. If set to false,  username will not present in context, BeforeAuthEvent OnAuthEvent will not trigger. | default true         |
| catchReply | bool | Whether to parse response of SQL to get the SQL result. Set this flag will affect performance. If set to false, CommandFinishedEvent will not receive reply from processor | default false        |

### Example

```lua
local tds=require("suproxy.tds"):new()
```

## Processor Events

### AuthSuccessEvent

This event triggers after user authentication finished successfully. Specifically when Login7 packet (or Prelogin is responded in SSL login) is responded without error. 

#### Handler syntax

handler(context,source,username,session)

#### Handler parameters

- context: execution context that is defined when adding handler to event.
- source: a TDS processor instance.
- username: username entered when login (If disableSSL is false, not available).
- session: context collected by processor.

#### Example

This example shows how to write login action into log file:

```lua
local function logAuth(context,source,username,session)
    local rs={
        os.date("%Y.%m.%d %H:%M:%S", ngx.time()).."\t" ,
        session.clientIP..":"..session.clientPort.."\t",
        username.."\t",
        "login with ",
        (session and session.client) and session.client or "unknown client",
        (session and session.clientVersion) and session.clientVersion or ""
    }
    print(table.concat(rs))
end
tds.AuthSuccessEvent:addHandler(tds,logAuth)
```

result will be like this

```shell
2020.10.03 18:42:36	127.0.0.1:50855	sa	login with Navicat
```

### AuthFailEvent

This event triggers after user authentication failed. Specifically when Login7 packet is responded with error. 

#### Handler syntax

handler(context,source,failInfo,session)

#### Handler parameters

- context: execution context that is defined when adding handler to event.
- source: a TDS processor instance.
- failInfo: see below.
- session: context collected by processor.

failInfo: 

| field    | type   | description                     |
| -------- | ------ | ------------------------------- |
| username | string | username                        |
| message  | string | fail message returned by server |

#### Example

This example shows how to log login fail action into file.

```lua
local function logAuthFail(context,source,failInfo,session)
    local rs={
        os.date("%Y.%m.%d %H:%M:%S", ngx.time()).."\t" ,
        session.clientIP..":"..session.clientPort.."\t",
        failInfo.username.."\t",
        "login fail, fail message: ",
        failInfo.message or "",
    }
    print(table.concat(rs))
end
tds.AuthFailEvent:addHandler(tds,logAuthFail)
```

result will be like this

```
2020.10.14 17:37:05	127.0.0.1:54104	UNKNOWN login fail, fail message: [18456]用户 'test' 登录失败。
```

### BeforeAuthEvent[ReturnEvent]

Triggers when Login7 packet is sent to proxy. If disableSSL is false, this event will not trigger. In fact OnAuthEvent in this processor can do better if you want to introduce your own authentication or swap password, this method just for compatible with other processor.

#### Handler syntax

credential,err = handler(context,source,credential,session)

#### Handler input parameters

- context: execution context that is defined when adding handler to event
- source: a TDS processor instance
- credential: see below
- session: context collected by processor

Credential:

| field    | type   | description | eg.  |
| -------- | ------ | ----------- | ---- |
| username | string | username    | "sa" |
| password | string | password    |      |

#### Handler return values

credential: username and password shall be passed to upstream server.

err: string error message.

Credential:

| field    | type   | description                                                  | required and default         |
| -------- | ------ | ------------------------------------------------------------ | ---------------------------- |
| username | string | real username for login                                      | required for username change |
| password | string | real password for login, ignored when swapPass is false or oracleVersion is not 11 | required for password change |

#### Example

This example shows how to change the user inputted username and password.

```lua
local function getCredential(context,source,credential,session)
	return {username="sa",password="xxxxxx"}
end
tds.BeforeAuthEvent:addHandler(tds,getCredential)
```

### OnAuthEvent[ReturnEvent]

Triggers when Login7 packet is sent to proxy. If disableSSL is false, this event will not trigger.

#### Handler syntax

ok,message = handler(context,source,credential,session)

#### Handler input parameters

- context: execution context that is defined when adding handler to event
- source: a TDS processor instance
- credential: see below
- session: context collected by processor

Credential:

| field    | type   | description |
| -------- | ------ | ----------- |
| username | string | username    |
| password | string | password    |

#### Handler return values

ok: true if authenticate success.

error: string error message.

credential: real credential that will be sent to server.

Credential:

| field    | type   | description |
| -------- | ------ | ----------- |
| username | string | username    |
| password | string | password    |

#### Example

This example shows how do self authenticate and change.

```lua
local function authenticator(context,source,credential,session)
    --OAUTH or other auth protocol should be used to swap real credential in real world
    local result=credential.username=="test" and credential.password=="test"
	if result then
		return result,nil,{username="sa",password="xxxxxx"}
    else
		local message="login with "..credential.username.." failed"
		return result,message       
    end
end
tds.OnAuthEvent:addHandler(tds,authenticator)
```

### ContextUpdateEvent

This event triggers twice during connection establishing. Firstly when Login7 request sent, at this occasion username, TDS Version, libName, client, clientVer will be added to context. Secondly when Login7 is responded from server, then the server version data, TDS Version  will be added to context. note that the TDS Version will be added twice since in SSL login, first update will not happen.

#### Handler syntax

handler(context,source,session)

#### Handler parameters

- context: execution context that is defined when adding handler to event.
- source: a TDS processor instance.
- session: context collected by processor.

#### Example

This example shows how to print context to error file:

```lua
local function printContext(self,source,ctx) 
    ngx.log(ngx.ERR,cjson.encode(ctx))
end
tds.ContextUpdateEvent:addHandler(tds,printContext)
```

result will be like this:

```json
{"sid":"FDA1390E","uid":"_SUPROXY_UNKNOWN","stype":"tds","uptime":1602735963,"ctx":{"srvIP":"192.168.1.135","tdsVer":"74000004","serverVer":"11.00.3128.00","srvID":"srv12","clientIP":"127.0.0.1","srvGID":"sqlServer","srvPort":1433,"clientPort":"53453"}
```

### CommandEnteredEvent[ReturnEvent]

Triggers when SQL request be sent to server , if new command is returned then this new command will be sent to server, if error is returned, no command will be sent and error message will be displayed on client. 

#### Handler syntax

newCommand,err = handler(context,source,command,session)

#### Handler input parameters

- context: execution context that is defined when adding handler to event.
- source: a TDS processor instance.
- command: command string.
- session: context collected by processor.

#### Handler return value

newCommand: command string to be send to server.

err: error message and code, format:

| field   | type   | description   | required or default |
| ------- | ------ | ------------- | ------------------- |
| message | string | error message | required            |
| code    | number | error code    | default 15343       |

#### Example

This example shows how to filter user input by checking keyword:

```lua
local function commandFilter(context,source,command,session)
    if command:match("forbidden")then
        return nil,{message=command.." is a forbidden command",21}
    end
    return command
end
local tds=require("suproxy.tds"):new()
tds.CommandEnteredEvent:addHandler(tds,commandFilter)
```

### CommandFinishedEvent

This event triggers when command is replied from server. note If catchReply is not set, this event will also be trigger without the reply info.

#### Handler syntax

handler(context,source,command,reply,session)

#### Handler parameters

- context: execution context that is defined when adding handler to event.
- source: a TDS processor instance.
- command: SQL string.
- reply: SQL reply, not available if catchReply is false.
- session: context collected by processor.

#### Example

This example shows how to  log command and reply:

```lua
local function logCmd(context,source,command,reply,session)
    local rs={
        os.date("%Y.%m.%d %H:%M:%S", ngx.time()).."\t" ,
        session.clientIP..":"..session.clientPort.."\t",
        username.."\t",
        command.."\r\n"
    }
    if reply then
        rs[#rs+1]="------------------reply--------------------\r\n"
        rs[#rs+1]=reply
        rs[#rs+1]="\r\n----------------reply end------------------\r\n")
    end
    print(table.concat(rs))
end
```

result will be like this:

```verilog
2020.10.03 18:42:41	127.0.0.1:50860	sa	SELECT d.name db_name, d.database_id, d.state, d.user_access, d.is_read_only, d.collation_name FROM sys.databases d
------------------reply--------------------
db_name	database_id	state	user_access	is_read_only	collation_name
master	1	0	0	0	Chinese_PRC_CI_AS
tempdb	2	0	0	0	Chinese_PRC_CI_AS
model	3	0	0	0	Chinese_PRC_CI_AS
msdb	4	0	0	0	Chinese_PRC_CI_AS
testA	5	0	0	0	Chinese_PRC_CI_AS
----------------reply end------------------
```

## Parser Events

tdsProcessor support following ParserEvents, refer tds.lua, tdsPackets.lua, tds\parser.lua for more information. more detail will be given in coming document
C2PParser.events.SQLBatch
C2PParser.events.Prelogin
C2PParser.events.Login7

S2PParser.events.LoginResponse
S2PParser.events.SSLLoginResponse
S2PParser.events.SQLResponse

# LDAPProcessor

LDAP processor is a simple LDAP proxy  which supports following functions:

- Username and password Acquire.
- Username and password Change.
- Introduce self-defined authenticator
- Intercept search request (note only search request is supported in this version).
- Read search result (note only search request is supported in this version).

## Context Collected(Session Object)

| field      | type   | description                                     | eg.                           |
| ---------- | ------ | ----------------------------------------------- | ----------------------------- |
| srvIP      | string | Upstream server IP                              | "192.168.1.7"                 |
| clientIP   | string | Client IP                                       | "127.0.0.1"                   |
| clientPort | string | Client port                                     | "56127"                       |
| username   | string | Username (Not available if disableSSL is false) | "admin,dc=www,dc=test,dc=com" |
| srvPort    | string | Server port                                     | "386"                         |
| srvID      | string | Server id passed with upstream servers          | "server3"                     |

## Tested Under

Tested Server:

- openldap-2.4.31

## Processor.new

### syntax

ldapProcessor = processor:new(options)

### Options

| field      | type | description                                                  | required and default |
| ---------- | ---- | ------------------------------------------------------------ | -------------------- |
| disableSSL | bool | Whether to stop SSL during login time.  This must be set if username or password need to be read or change. If set to false,  username will not present in context, BeforeAuthEvent OnAuthEvent will not trigger. | default true         |
| catchReply | bool | Whether to parse response of SQL to get the SQL result. Set this flag will affect performance. If set to false, CommandFinishedEvent will not receive reply from processor | default false        |

### Example

```lua
local ldap=require("suproxy.ldap"):new()
```

## Processor Events

### AuthSuccessEvent

This event triggers when bind response successfully. 

#### Handler syntax

handler(context,source,username,session)

#### Handler parameters

- context: execution context that is defined when adding handler to event.
- source: a LDAP processor instance.
- username: username entered when login
- session: context collected by processor.

#### Example

This example shows how to write login action into log file:

```lua
local function logAuth(context,source,username,session)
    local rs={
        os.date("%Y.%m.%d %H:%M:%S", ngx.time()).."\t" ,
        session.clientIP..":"..session.clientPort.."\t",
        username.."\t",
        "login with ",
        (session and session.client) and session.client or "unknown client",
        (session and session.clientVersion) and session.clientVersion or ""
    }
    print(table.concat(rs))
end
ldap.AuthSuccessEvent:addHandler(ldap,logAuth)
```

result will be like this

```
2020.10.03 18:39:04	127.0.0.1:50781	cn=admin,dc=www,dc=test,dc=com	login with unknown client
```

### AuthFailEvent

This event triggers after bind request failed. 

#### Handler syntax

handler(context,source,failInfo,session)

#### Handler parameters

- context: execution context that is defined when adding handler to event.
- source: a LDAP processor instance.
- failInfo: see below.
- session: context collected by processor.

failInfo: 

| field    | type   | description                     |
| -------- | ------ | ------------------------------- |
| username | string | username                        |
| message  | string | fail message returned by server |

#### Example

This example shows how to log login fail action into file.

```lua
local function logAuthFail(context,source,failInfo,session)
    local rs={
        os.date("%Y.%m.%d %H:%M:%S", ngx.time()).."\t" ,
        session.clientIP..":"..session.clientPort.."\t",
        failInfo.username.."\t",
        "login fail, fail message: ",
        failInfo.message or "",
    }
    print(table.concat(rs))
end
ldap.AuthFailEvent:addHandler(ldap,logAuthFail)
```

result will be like this

```
2020.10.03 18:12:45	127.0.0.1:50128	login fail, fail message: fail code: 49
```

### BeforeAuthEvent[ReturnEvent]

Triggers when bind request is sent to proxy. In fact handling OnAuthEvent  is better if you want to introduce your own authentication or swap password, this method just for compatible with other processor.

#### Handler syntax

credential,err = handler(context,source,credential,session)

#### Handler input parameters

- context: execution context that is defined when adding handler to event
- source: a LDAP processor instance
- credential: see below
- session: context collected by processor

Credential:

| field    | type   | description |
| -------- | ------ | ----------- |
| username | string | username    |
| password | string | password    |

#### Handler return values

credential: username and password shall be passed to upstream server.

err: string error message.

Credential:

| field    | type   | description              | required and default         |
| -------- | ------ | ------------------------ | ---------------------------- |
| username | string | real username for login  | required for username change |
| password | string | real password for login, | required for password change |

#### Example

This example shows how to change the user inputted username and password.

```lua
local function getCredential(context,source,credential,session)
	return  {username="cn=admin,dc=www,dc=test,dc=com",password="xxx"}
end
ldap.BeforeAuthEvent:addHandler(ldap,getCredential)
```

### OnAuthEvent[ReturnEvent]

Triggers when BindRequest is sent to proxy. 

#### Handler syntax

ok,message = handler(context,source,credential,session)

#### Handler input parameters

- context: execution context that is defined when adding handler to event
- source: a LDAP processor instance
- credential: see below
- session: context collected by processor

Credential:

| field    | type   | description |
| -------- | ------ | ----------- |
| username | string | username    |
| password | string | password    |

#### Handler return values

ok: true if authenticate success.

error: string error message.

credential: real credential that will be sent to server.

Credential:

| field    | type   | description |
| -------- | ------ | ----------- |
| username | string | username    |
| password | string | password    |

#### Example

This example shows how do self authenticate and change.

```lua
local function authenticator(context,source,credential,session)
    --OAUTH or other auth protocol should be used to swap real credential in real world
    local result=credential.username=="test" and credential.password=="test"
	if result then
		return result,nil, {username="cn=admin,dc=www,dc=test,dc=com",password="xxx"}
    else
		local message="login with "..credential.username.." failed"
		return result,message       
    end
end
ldap.OnAuthEvent:addHandler(ldap,authenticator)
```

### ContextUpdateEvent

This event triggers after bindRequest is sent. 

#### Handler syntax

handler(context,source,session)

#### Handler parameters

- context: execution context that is defined when adding handler to event.
- source: a LDAP processor instance.
- session: context collected by processor.

#### Example

This example shows how to print context to error file:

```lua
local function printContext(self,source,ctx) 
    ngx.log(ngx.ERR,cjson.encode(ctx))
end
ldap.ContextUpdateEvent:addHandler(ldap,printContext)
```

result will be like this:

```json
{"sid":"FDA1390E","uid":"_SUPROXY_UNKNOWN","stype":"ldap","uptime":1602735963,"ctx":{"srvIP":"192.168.1.135","srvID":"srv12","clientIP":"127.0.0.1","srvGID":"sqlServer","srvPort":1433,"clientPort":"53453"}
```

### CommandEnteredEvent[ReturnEvent]

Triggers when SearchRequest be sent to server , if error is returned, no command will be sent. Note new command and error message display have not been supported yet

#### Handler syntax

newCommand,err = handler(context,source,command,session)

#### Handler input parameters

- context: execution context that is defined when adding handler to event.
- source: a LDAP processor instance.
- command: JSON version of search request，includes baseObject, scope and filter.
- session: context collected by processor.

#### Handler return value

newCommand: command string to be send to server**[not supported yet]**.

err: error message, a not nil value indicate nothing should be sent to server. Sending back this message to client is not supported yet.

#### Example

This example shows how to filter user input by checking keyword:

```lua
local function commandFilter(context,source,command,session)
    if command:match("forbidden")then
        return nil,"forbidden"
    end
    return command
end
local ldap=require("suproxy.ldap"):new()
ldap.CommandEnteredEvent:addHandler(ldap,commandFilter)
```

### CommandFinishedEvent

This event triggers when SearchResultDone packet is received from server.

#### Handler syntax

handler(context,source,command,reply,session)

#### Handler parameters

- context: execution context that is defined when adding handler to event.
- source: a LDAP processor instance.
- command: JSON version of search request，includes baseObject, scope and filter .
- reply: Search result includes object name and attributes
- session: context collected by processor.

#### Example

This example shows how to  log command and reply:

```lua
local function logCmd(context,source,command,reply,session)
    local rs={
        os.date("%Y.%m.%d %H:%M:%S", ngx.time()).."\t" ,
        session.clientIP..":"..session.clientPort.."\t",
        username.."\t",
        command.."\r\n"
    }
    if reply then
        rs[#rs+1]="------------------reply--------------------\r\n"
        rs[#rs+1]=reply
        rs[#rs+1]="\r\n----------------reply end------------------\r\n")
    end
    print(table.concat(rs))
end
```

result will be like this:

```verilog
2020.10.03 18:39:11	127.0.0.1:50788	cn=admin,dc=www,dc=test,dc=com	["baseObject":"dc=www,dc=test,dc=com","sope":1,"filter"="(objectclass=*)"]
------------------reply--------------------
["cn=admin,dc=www,dc=test,dc=com",[{"values":["simpleSecurityObject","organizationalRole"],"attrType":"objectClass"}]]
["cn=group,dc=www,dc=test,dc=com",[{"values":["posixGroup","top"],"attrType":"objectClass"}]]
["ou=testou,dc=www,dc=test,dc=com",[{"values":["top","organizationalUnit"],"attrType":"objectClass"}]]
["cn=group1,dc=www,dc=test,dc=com",[{"values":["groupOfUniqueNames","top"],"attrType":"objectClass"}]]
["uid=xxx,dc=www,dc=test,dc=com",[{"values":["posixAccount","top","inetOrgPerson"],"attrType":"objectClass"}]]
["uid=xxx,dc=www,dc=test,dc=com",[{"values":["posixAccount","top","inetOrgPerson"],"attrType":"objectClass"}]]
["uid=haha,dc=www,dc=test,dc=com",[{"values":["posixAccount","top","inetOrgPerson"],"attrType":"objectClass"}]]
["uid=xxx,dc=www,dc=test,dc=com",[{"values":["posixAccount","top","inetOrgPerson"],"attrType":"objectClass"}]]
["cn=test3,dc=www,dc=test,dc=com",[{"values":["inetOrgPerson"],"attrType":"objectClass"}]]
["cn=jira-software-users,dc=www,dc=test,dc=com",[{"values":["groupOfUniqueNames"],"attrType":"objectClass"}]]
["cn=group2,dc=www,dc=test,dc=com",[{"values":["groupOfUniqueNames"],"attrType":"objectClass"}]]
["cn=ttt,dc=www,dc=test,dc=com",[{"values":["inetOrgPerson"],"attrType":"objectClass"}]]
----------------reply end------------------
```

## Parser Events

ldapProcessor support following ParserEvents, refer ldap.lua, ldapPackets.lua, ldap\parser.lua for more information. more detail will be given in coming document
C2PParser.events.SearchRequest
C2PParser.events.BindRequest
C2PParser.events.UnbindRequest

S2PParser.events.BindResponse
S2PParser.events.SearchResultEntry
S2PParser.events.SearchResultDone
