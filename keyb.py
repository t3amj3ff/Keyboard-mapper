# USB Keyboard pcap reconstructor thing
# Cobbled together by TeamJeff and made to work from variouos scripts on Github
# Please excuse any shoddy coding, this is a python learning experience
#
# Keycode info obtained from here - https://www.usb.org/sites/default/files/documents/hut1_12v2.pdf
# Scapy info here - https://scapy.readthedocs.io/en/latest/


# Import extra bits to do stuff
import argparse
from sys import argv

# Help text/instructions
parser = argparse.ArgumentParser(
	formatter_class=argparse.RawTextHelpFormatter,
	description='Reconstruct keystrokes from a USB PCAP file.',
	epilog='''Try this to create a scancode file (works in Windows or Linux)
	tshark
	-r <filename>.pcap
	-Y "((usb.transfer_type == 0x01)&&(frame.len==72))&&!(usb.capdata==00:00:00:00:00:00:00:00)"
	-T fields
	-e usb.capdata
	> scancodes.txt''')

parser.add_argument('-f', '--file', help='File containing the USB keyboard scancodes', required=True)
parser.add_argument('-p', '--pcap', help='Specifies PCAP file, requires Scapy to be installed', action='store_true', required=False)
parser.add_argument('-t', '--text', help='Specifies text file of extracted scancodes from PCAP', action='store_true', required=False)


# USB keyboard keycodes (US layout)
# Shift-Del doesn't do anything so made it blank
key_codes = {
    0x04:["a", "A"], 0x05:["b", "B"], 0x06:["c", "C"], 0x07:["d", "D"], 0x08:["e","E"], 0x09:["f","F"],
    0x0A:["g","G"], 0x0B:["h","H"], 0x0C:["i","I"], 0x0D:["j","J"], 0x0E:["k","K"], 0x0F:["l","L"],
    0x10:["m","M"], 0x11:["n","N"], 0x12:["o","O"], 0x13:["p","P"], 0x14:["q","Q"], 0x15:["r","R"],
    0x16:["s","S"], 0x17:["t","T"], 0x18:["u","U"], 0x19:["v","V"], 0x1A:["w","W"], 0x1B:["x","X"],
    0x1C:["y","Y"], 0x1D:["z","Z"], 0x1E:["1","!"], 0x1F:["2","@"], 0x20:["3","#"], 0x21:["4","$"],
    0x22:["5","%"], 0x23:["6","^"], 0x24:["7","&"], 0x25:["8","*"], 0x26:["9","("], 0x27:["0",")"],
	0x28:["Enter","Enter"], 0x29:["Esc","Esc"], 0x2A:["Backspace","Backspace"], 0x2B:["Tab","BkTab"], 0x2C:[" "," "],
	0x2D:["-","_"], 0x2E:["=","+"], 0x2F:["[","{"], 0x30:["]","}"], 0x31:["\\","|"], 0x32:["#","~"],
	0x33:[";",":"], 0x34:["'","@"], 0x36:[",","<"], 0x37:[".",">"], 0x38:["/","?"], 0x39:["CAPS","CAPS"],
	0x3A:["F1","F1"], 0x3B:["F2","F2"], 0x3C:["F3","F3"], 0x3D:["F4","F4"], 0x3E:["F5","F5"], 0x3F:["F6","F6"],
	0x40:["F7","F7"], 0x41:["F8","F8"], 0x42:["F9","F9"], 0x43:["F10","F10"], 0x44:["F11","F11"], 0x45:["F12","F12"],
	0x46:["PrntScrn","PrntScrn"], 0x47:["ScrlLck","ScrlLck"], 0x48:["Pause","Pause"], 0x49:["Insert","Insert"],
	0x4A:["Home","Home"], 0x4B:["PgUp","PgUp"], 0x4C:["Del",""], 0x4D:["End","End"], 0x4E:["PgDn","PgDn"],
	0x4F:["Right","Right"], 0x50:["Left", "Left"], 0x51:["Down","Down"], 0x52:["Up","Up"], 0x53:["NumLck","NumLck"],
	0x54:["/","/"], 0x55:["*","*"], 0x56:["-","-"], 0x57:["+","+"], 0x58:["Enter","Enter"], 0x59:["1","1"], 
	0x5a:["2","2"], 0x5b:["3","3"], 0x5c:["4","4"], 0x5d:["5","5"], 0x5e:["6","6"], 0x5f:["7","7"], 0x60:["8","8"], 
	0x61:["9","9"], 0x62:["0","0"], 0x63:[".","."]
    }


# extract from a pcap file
def pcapfileconv():
	strKey = ""
	# Read the pcap file
	packets = rdpcap(pcapfile)
	# Process the data
	for packet in packets:
		# Check the packet length is 72 and type 0x01 for a keyboard input in
		data = str(packet)
		if len(data) == 72 and data[9] == '\x01':
			scancode = packet.load[-8:]
			keycode = ord(scancode[2])
	
			# Check the modifier to see if the shift key (0x02 or 0x20) was pressed
			if (ord(scancode[0]) == 02) or (ord(scancode[0]) == 20):
				modifier = 1
			else:
				modifier = 0
	
			# If keycode is 0 skip to the next
			if keycode == 0:
				continue

			strKey += key_codes[keycode][modifier]
		
	# Print the results
	print "Typed text =", strKey

	
# extract from a text file
def codesinfile():
	strKey = ""
	# Open the file and read 1 line at a time
	for scancode in open(scancodefile,"r").readlines():
		keycode = int(scancode[6:8],16)

		# If keycode is 0 skip to the next
		if keycode == 0:
			continue

		# Check the modifier to see if the shift key (0x02 or 0x20) was pressed
		if (int(scancode[0:2],16) == 2) or (int(scancode[0:2],16) == 20):
			modifier = 1
		else:
			modifier = 0
	
		strKey += key_codes[keycode][modifier]
		
	# Print the results
	print "Typed text =", strKey


# Check the number of arguments, show help if wrong
if (len(argv) < 4) or (len(argv) > 4):
	parser.print_help()
	exit()

# set the file type based on the argument used
args = parser.parse_args()
if args.pcap:
	pcapfile = args.file
	# Import Scapy to process here so it doesn't slow down the script if you're not using a pcap
	try:
		from scapy.all import rdpcap
		pcapfileconv()
	except:
		print "Can't load Scapy"
		parser.print_help()
elif args.text:
	scancodefile = args.file
	codesinfile()
else:
	parser.print_help()
