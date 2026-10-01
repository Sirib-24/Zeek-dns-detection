suspicious_patterns = ["xn--","base64","cmd","powershell","malware","tunnel","data"]

found = False
with open("dns.log") as f:
	for line in f:
		if line.startswith("#"):
			continue
		fields = line.strip().split("\t")
		if len(fields) < 8:
			continue
		query = fields[9]

		for pattern in suspicious_patterns:
			if pattern in query:
				print(f"Suspicious DNS query detected: {query}")
				found = True
if not found:
	print("No suspicious DNS queries detected.")
