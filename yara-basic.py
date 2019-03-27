import yara
import time

string_rule = """ 
rule host
{ 
	strings:
		$re1 = /Authorization: Basic.*?=/
	condition:
		$re1
}
		
"""

compiled_rule = yara.compile(source=string_rule)

while 1:
	matches = compiled_rule.match(pid=6052)
	if matches:
		for match in matches:
			print(match.strings)
	time.sleep(0.5)

