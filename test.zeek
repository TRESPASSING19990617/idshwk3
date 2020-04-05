type idRecord :record{
     num :count;
     ug :set[string];
};

global idTable :table[addr] of idRecord = table();
event http_reply (c: connection, version: string, code: count, reason: string)
{
local a:addr=c$id$orig_h;
if(a in idTable)
{
    if(to_lower(c$http$user_agent) in idTable[a]$ug)
    {}
    else
    {
    add idTable[a]$ug[to_lower(c$http$user_agent)];
    idTable[a]$num += 1;
    }
}
else
{
    idTable[a]=record($num=1,$ug=set(to_lower(c$http$user_agent)));
}
}

event zeek_done()
{
    for(key in idTable)
    {
       if(idTable[key]$num>=3)
       {
       print fmt("%s is a proxy",key);
       }
       else{}
    }
}