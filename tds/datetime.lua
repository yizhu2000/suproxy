
--[[ 
参数说明： 
srcDateTime 原始时间字符串，要求格式%Y%m%d%H%M%S,这个时间格式字符串表示4位年份、月份、day、小时、分钟、秒都是2位数字 
interval 对该时间进行加或减具体值,>0表示加 <0表示减 
dateUnit 时间单位，支持DAY、HOUR、SECOND、MINUTE 4种时间单位操作，根据interval具体值对原始时间按指定的单位进行加或减 
例如， 
interval=10，unit='DAY',表示对原始时间加10天 
interval=-1，unit='HOUR',表示对原始时间减1小时 

返回结果是一个os.date,他是一个table结构，里面包含了year,month,day,hour,minute,second 6个属性，跟据需要从结果里面取出需要的属性然后根据需要产生相应的新的日期格式即可。 
]] 

_M={} 

function _M.getNewDate(srcDateTime,interval ,dateUnit)
--从日期字符串中截取出年月日时分秒
local Y = string.sub(srcDateTime,1,4)
local M = string.sub(srcDateTime,5,6)
local D = string.sub(srcDateTime,7,8)
local H = string.sub(srcDateTime,9,10)
local MM = string.sub(srcDateTime,11,12)
local SS = string.sub(srcDateTime,13,14)

--把日期时间字符串转换成对应的日期时间
local dt1 = os.time{year=Y, month=M, day=D, hour=H,min=MM,sec=SS}

--根据时间单位和偏移量得到具体的偏移数据
local ofset=0

if dateUnit =='DAY' then
ofset = 60 *60 * 24 * interval

elseif dateUnit == 'HOUR' then
ofset = 60 *60 * interval

elseif dateUnit == 'MINUTE' then
ofset = 60 * interval

elseif dateUnit == 'SECOND' then
ofset = interval
end

--指定的时间+时间偏移量
local newTime = os.date("*t", dt1 + tonumber(ofset))
return newTime
end
