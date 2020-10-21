local _M = {_VERSION="0.1.11"}local table_insert = table.insertlocal table_concat = table.concat

function _M.getTime() return ngx and ngx.time() or os.time() end
function _M.addParamToUrl(urlString, paramName,paramValue)

	if urlString==nil then urlString="" end
	
	if paramValue==nill then paramValue="" end
	
	if paramName==nil then return urlString end
	
	if string.find(urlString,"?") then urlString=urlString.."&" else urlString=urlString.."?" end
	
	urlString=urlString..paramName.."="..paramValue
	
	return urlString
end

function _M._86_64()
    return 0xfffffffff==0xffffffff and 32 or 64 
end

function _M.removeParamFromUrl(urlString, paramName)

	if urlString==nil then urlString="" end
		
	if paramName==nil then return urlString end
	
	urlString=string.gsub (urlString,"[\\?\\&]"..paramName.."=?[^&$]*", "")
	
	ngx.log(ngx.DEBUG,"urlString:"+urlString)
	
    local qmarkindex=string.find(urlString,"\\?")
    local andmarkindex=string.find(urlString,"\\&")
	if qmarkindex==-1 and andmarkindex>0 then
	 urlString=string.gsub (urlString,"\\&", "?")
	end
	

	return urlString
end


--get url or post arguments from request
function _M.getArgsFromRequest(argName)
local args=ngx.req.get_uri_args()
local result=args[argName]
	if result==nil and "POST" == ngx.var.request_method then
			ngx.req.read_body()
			args = ngx.req.get_post_args()
			result=args[argName]
	end
	return result
end


function _M.error(msg, detail, status)    local cjson=require("cjson")
    if status then ngx.status = status end
    ngx.say(cjson.encode({ msg = msg, detail = detail }))
    ngx.log(ngx.ERR,cjson.encode({ msg = msg, detail = detail }))
    if status then ngx.exit(status) end
end

local errors = {
  UNAVAILABLE = 'upstream-unavailable',
  QUERY_ERROR = 'query-failed'
}

_M.errors = errors 
local function request(method)
    return function(url, payload, headers)
        headers = headers or {}
        headers['Content-Type'] = 'application/x-www-form-urlencoded'
        local httpc = require( "resty.http" ).new()
        local params = {headers = headers, method = method }
        if string.sub(string.lower(url),1,5)=='https' then params.ssl_verify = true end
        if method == 'GET' then params.query = payload
        else params.body = payload end
        local res, err = httpc:request_uri(url, params)
        if err then
          ngx.log(ngx.ERR, table.concat(
            {method .. ' fail', url, payload}, '|'
          ))
          return nil, nil, errors.UNAVAILABLE
        else
          if res.status >= 400 then
            ngx.log(ngx.ERR, table.concat({
              method .. ' fail code', url, res.status, res.body,
            }, '|'))
            return res.status, res.body, errors.QUERY_ERROR
          else
            return res.status, res.body, nil
          end
        end
    end
end

_M.jget = request('GET')
_M.jput = request('PUT')
_M.jpost = request('POST')


function _M.unzip(inputString)    local zlib=require('suproxy.utils.ffi-zlib')
	-- Reset vars
    local chunk = 16384
    local output_table = {}
    local count = 0
    local input = function(bufsize)
		ngx.log(ngx.DEBUG,"count:"..count)
        local start = count > 0 and bufsize*count or 1
        local data = inputString:sub(start, (bufsize*(count+1)-1) )
		count = count + 1
		ngx.log(ngx.INFO,"--------data-----------")
		ngx.log(ngx.INFO,data)
		return data
	end
	
    local output = function(data)
		table_insert(output_table, data)
	end
	
    local ok, err = zlib.inflateGzip(input, output, chunk)
	if not ok then
		ngx.log(ngx.ERR,"unzip error")
	end
    local output_data = table_concat(output_table,'')


	return output_data 
end



return _M