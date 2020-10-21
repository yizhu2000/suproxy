--Default random balancer. this balancer randomly select upstreams from given
--list. if one upstream is blamed, this upstream will be unselectable for given
--suspendSpan time.
local tableUtils=require "suproxy.utils.tableUtils"
local utils=require "suproxy.utils.utils"
local OrderedTable=tableUtils.OrderedTable
local _M={}
local function getKey(ip,port) return string.format("ip%sport%s",ip,port) end

function _M:new(upstreams,suspendSpan)
	math.randomseed(utils.getTime())
	local o=setmetatable({},{__index=self})
	assert(upstreams,"upstreams can not be nil")
	o.upstreams=OrderedTable:new()
	o.blameList={}
	o.suspendSpan=suspendSpan or 30
	for i,v in ipairs(upstreams) do
		assert(v.ip,"upstream ip address cannot be null")
		assert(v.port,"upstream ip address cannot be null")
		o.upstreams[getKey(v.ip,v.port)]=v
	end
	return o
end

function _M:getBest()
	for k,v in pairs (self.blameList) do 
		if v.addTime+self.suspendSpan<=utils.getTime() then
			self.upstreams[k]=v.value
		end
	end
	if #self.upstreams ==0 then return nil end
	local i=math.ceil(math.random(1,#self.upstreams))
	if self.upstreams[i] then
		return self.upstreams[i].value
	end
end

function _M:blame(upstream)
	assert(upstream.ip,"upstream ip address cannot be null")
	assert(upstream.port,"upstream ip address cannot be null")
	local key=getKey(upstream.ip,upstream.port)
	if self.upstreams[key] then
		self.blameList[key]={addTime=utils.getTime(),value=self.upstreams[key]}
		self.upstreams:remove(key)	
	end
end

_M.unitTest={}
function _M.test()
	print("------------running balancer test")
	local suspendSpan=5
	local a=_M:new({{ip=1,port=1},{ip=2,port=2},{ip=3,port=3}},suspendSpan)
	print(tableUtils.printTableF(a:getBest(),{inline=true}))
	print(tableUtils.printTableF(a:getBest(),{inline=true}))
	print(tableUtils.printTableF(a:getBest(),{inline=true}))
	print(tableUtils.printTableF(a:getBest(),{inline=true}))
	print(tableUtils.printTableF(a:getBest(),{inline=true}))
	print(tableUtils.printTableF(a:getBest(),{inline=true}))
	print(tableUtils.printTableF(a:getBest(),{inline=true}))
	assert(#(a.upstreams)==3)
	a:blame({ip=1,port=1})
	assert(#(a.upstreams)==2)
	assert(a.upstreams[getKey(1,1)]==nil)
	assert(a.upstreams[getKey(2,2)])
	assert(a.upstreams[getKey(3,3)])
	assert(a.blameList[getKey(1,1)])
	assert(a.blameList[getKey(1,1)].value.ip==1)
	print("------------wait ",suspendSpan," seconds")
	local t0 = os.clock()
	while os.clock() - t0 <= 5 do end
	a:getBest()
	print(tableUtils.printTableF(a.upstreams))
	assert(#(a.upstreams)==3)
	assert(#(a.blameList)==0)
	print("------------balancer test finished")
end
return _M