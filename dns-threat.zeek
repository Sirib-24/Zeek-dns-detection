module DNS_Threat;

export{
redef enum Notice::Type +={
DNS_Suspicious_Query
};
}

event dns_request(query:string)
{
local suspicious_patterns = {
"xn--",
"base64",
"cmd",
"powershell",
"malware",
"tunnel",
"data"
};
for(p in suspicious_patterns)
{
if(p in query)
{
NOTICE([
$note = DNS_Suspicious_Query,
$msg = fmt("Suspicious DNS query detected: %s",query),
$conn = c
]);
}
}
}

