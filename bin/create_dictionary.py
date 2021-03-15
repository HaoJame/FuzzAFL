import sys
import angr
import string
import logging
l = logging.getLogger("Create dicrectory")

print(l)

def hexescape(s):
	out = []
	accept = string.ascii_letters+string.digits+" "
	for c in s:
		if c not in accept:
			out.append("\\x%02x"%ord(c))
		else:
			out.append(c)
	return " ".join(out)
def create(bin,outfile):
	b = angr.Project(bin)
	cfg = b.analyses.CFG(keep_input_state=True)
	string_references = []
	for a in cfg.function_manager.functions.values():
		try:
			string_references.append(f.string_references())
		except ZeroDivisionError:
			pass



	string_references = sum(string_references,[ ])
	strings = [] if len(string_references) == 0 else zip(*string_references)[1]


	vailid_strings = filter(lambda s:len(s) <= 129 and len(s) > 0 ,strings)

	if len(vailid_strings) > 0:
		with open(outfile,"wb") as f:
			for i,s in enumberate(vailid_strings):
				if len(s) <=128:
					esc_c = hexescape(s)
					f.write("string_%d=\"%s\"\n" % (i, esc_s))

		return True

	return False


def main(argv):
	if(len(argv)) < 2:
		l.error("ERROR ARGUMENT TO CREATE DICRECTORY")
		return 1

	binary = argv[1]
	outfile = argv[2]

	return int(not create(binary,outfile))

if __name__ == '__main__':
	sys.exit(main(sys.argv))
