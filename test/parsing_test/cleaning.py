import re


line = '''1586811319.468538 write(18, "\x51\x51\x51\x51\x51\x51\x51\x51\x51\x51\x51\x51\x51\x51"..., 4096) = -4096'''
template = "[0-9]+\.[0-9]+ ([a-zA-Z0-9_]+\(.*\)) = .*"
retVal=re.match(template ,line)
print(retVal.group(1))
line2 = re.sub("[0-9]","",line).replace(". ","").replace(", ", ",").replace(","," ")
line3 = re.sub("\".+\"","",line2).replace(" = ","").replace("...","").replace("  ","")
#line4 = re.sub("")
print(line3)
