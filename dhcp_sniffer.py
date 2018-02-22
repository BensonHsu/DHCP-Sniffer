import sys
import socket
import ctypes
import binascii
import struct
import argparse
import time

class BPF(object):
	def __init__(self):
		self.SO_ATTACH_FILTER = 26

		# instruction classes
		self.BPF_LD  = 0x00
		self.BPF_JMP = 0x05
		self.BPF_RET = 0x06

		# ld/ldx fields
		self.BPF_W   = 0x00    # word(4 byte)
		self.BPF_H   = 0x08    # helf word(2 byte)
		self.BPF_B   = 0x10    # byte(1 byte)
		self.BPF_ABS = 0x20    # absolute address

		# alu/jmp fields
		self.BPF_JEQ = 0x10
		self.BPF_K   = 0x00

	def fill_sock_filter(self, code, jt, jf, k):
		return struct.pack('HBBI', code, jt, jf, k)

	def statement(self, code, k):
		return self.fill_sock_filter(code, 0, 0, k)

	def jump(self, code, jt, jf, k):
		return self.fill_sock_filter(code, jt, jf, k)


class BPF_DHCP(BPF):
	def __init__(self):
		super(BPF_DHCP, self).__init__()

	def set_dhcp_filter(self, sock):
		command_list = [
			# filter IPv4
			self.statement(self.BPF_LD | self.BPF_ABS | self.BPF_H, 12),
			self.jump(self.BPF_JMP | self.BPF_JEQ | self.BPF_K, 0, 5, 0x0800),

			# filter UDP
			self.statement(self.BPF_LD | self.BPF_ABS | self.BPF_B, 23),
			self.jump(self.BPF_JMP | self.BPF_JEQ | self.BPF_K, 0, 3, 0x11),

			# filter destination port 67
			self.statement(self.BPF_LD | self.BPF_ABS | self.BPF_H, 36),
			self.jump(self.BPF_JMP | self.BPF_JEQ | self.BPF_K, 0, 1, 67),

			# return
			self.statement(self.BPF_RET | self.BPF_K, 0xffffffff), # pass
			self.statement(self.BPF_RET | self.BPF_K, 0x00000000)  # reject
		]
		self.print_commands(command_list)
		commands = b''.join(command_list)
		buffers = ctypes.create_string_buffer(commands)
		fprog = struct.pack('HL', len(command_list), ctypes.addressof(buffers))
		sock.setsockopt(socket.SOL_SOCKET, self.SO_ATTACH_FILTER, fprog)

	def print_commands(self, command_list):
		print("like <tcpdump -dd ...>")
		for i in list(map(lambda x: binascii.hexlify(x).decode('ascii'), command_list)):
			print(i)

class Ethernet(object):
	# ethertype
	ETH_P_ALL = 0x0003
	ETH_P_IP  = 0x0800 

	def __init__(self, packet):
		self._frame_header = packet[0:14]

	def get_source_mac(self):
		return binascii.hexlify(self._frame_header[6:12]).decode()

	def get_dest_mac(self):
		return binascii.hexlify(self._frame_header[0:6]).decode()

	def get_ether_type(self):
		return binascii.hexlify(self._frame_header[12:14]).decode()

class IPv4(object):
	# protocol
	protocol_UDP = 17

	def __init__(self, packet):
		self._ip_header = struct.unpack('!BBHHHBBH4s4s', packet[14:34])

	def get_source_ip(self):
		return socket.inet_ntoa(self._ip_header[8])

	def get_dest_ip(self):
		return socket.inet_ntoa(self._ip_header[9])

	def get_protocol(self):
		return self._ip_header[6]

class UDP(object):
	def __init__(self, packet):
		self._udp_header = struct.unpack('!HHHH', packet[34:42])

	def get_source_port(self):
		return self._udp_header[0]

	def get_dest_port(self):
		return self._udp_header[1]

	def get_length(self):
		return self._udp_header[2]

class DHCP_Protocol(object):
	server_port = 67
	client_port = 68

	# DHCP options
	magic_cookie        = '63825363'
	option_pad          = 0
	option_host_name    = 12
	option_request_ip   = 50
	option_message_type = 53
	option_server_id    = 54
	option_request_list = 55
	option_end          = 255

	@staticmethod
	def get_message_type(value):
		message_type = {
			1: 'DHCPDISCOVER',
			2: 'DHCPOFFER',
			3: 'DHCPREQUEST',
			4: 'DHCPDECLINE',
			5: 'DHCPACK',
			6: 'DHCPNAK',
			7: 'DHCPRELEASE',
			8: 'DHCPINFORM'
		}
		return message_type.get(value, 'None')

# length: number of bytes
class DHCP(object):
	def __init__(self, packet, length):
		self._payload = packet[42:]
		self._length = length
		self._ciaddr = ''
		self._chaddr = ''
		self._option_55 = ''
		self._option_53 = ''
		self._option_12 = ''
		self._option_50 = ''
		self._option_54 = ''

	def parse_payload(self):
		# parse DHCP payload [0:44]
		#    ciaddr [Client IP Address]      : [12:16]
		#    yiaddr [Your IP Address]        : [16:20]
		#    siaddr [Server IP Address]      : [20:24]
		#    giaddr [Gateway IP Address]     : [24:28]
		#    chaddr [Client Hardware address]: [28:44]
		tmp = struct.unpack('!4s', self._payload[12:16])
		self._ciaddr = socket.inet_ntoa(tmp[0])
		self._chaddr = binascii.hexlify(self._payload[28:34]).decode()


	# DHCP options format:
	#     Magic Cookie + DHCP options + FF(end option)
	#     DHCP option format:
	#         code(1 byte) + length(1 byte) + value
	#     Pad and End option format:
	#         code(1 byte)
	def parse_options(self):
		find = False
		payload = binascii.hexlify(self._payload).decode()

		index = payload.find(DHCP_Protocol.magic_cookie)
		if -1 == index:
			return

		index += len(DHCP_Protocol.magic_cookie)
		hex_count = self._length * 2;
		while True:
			code = int(payload[index:index+2], 16)
			if DHCP_Protocol.option_pad == code:
				index += 2
				continue
			if DHCP_Protocol.option_end == code:
				return
			length = int(payload[index+2:index+4], 16)
			value = payload[index+4:index+4+length*2]

			# set DHCP options
			if DHCP_Protocol.option_request_list == code:
				self._option_55 = value
			elif DHCP_Protocol.option_message_type == code:
				self._option_53 = DHCP_Protocol.get_message_type(int(value))
			elif DHCP_Protocol.option_host_name == code:
				self._option_12 = bytes.fromhex(value).decode()
			elif DHCP_Protocol.option_request_ip == code:
				b = bytes.fromhex(value)
				self._option_50 = socket.inet_ntoa(b)
			elif DHCP_Protocol.option_server_id == code:
				b = bytes.fromhex(value)
				self._option_54 = socket.inet_ntoa(b)

			index = index + 4 + length * 2

			if index + 4 >  hex_count:
				break

	@property
	def ciaddr(self):
		return self._ciaddr

	@property
	def chaddr(self):
		return self._chaddr

	@property
	def option_55(self):
		return self._option_55

	@property
	def option_53(self):
		return self._option_53

	@property
	def option_12(self):
		return self._option_12

	@property
	def option_50(self):
		return self._option_50

	@property
	def option_54(self):
		return self._option_54


def convert_hex_str_to_int_str(hexstr):
	pool = []
	for x,y in zip(hexstr[0::2], hexstr[1::2]):
		pool.append(str(int(x+y, 16)))
	return ','.join(pool)

def convert_hex_str_to_mac(hexstr):
	pool = []
	for x,y in zip(hexstr[0::2], hexstr[1::2]):
		pool.append(x+y)
	return ':'.join(pool)

def get_time():
	return time.strftime("%Y-%m-%d %H:%M:%S %z", time.localtime())


simple_dhcp_type = ['DHCPREQUEST']

if __name__ == '__main__':

	# argument parse
	parser = argparse.ArgumentParser()
	parser.add_argument('-i', '--interface', default='eth0', help='sniffer interface to get DHCP packets. default is eth0')
	parser.add_argument('-d', '--detail', action='store_true', help='show more detail packet information. if not set, only {} show.'.format(' '.join(simple_dhcp_type)))
	args = parser.parse_args()

	# bind raw_socket
	sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, 0x0800)

	# use BPF to filter DHCP packet
	BPF_DHCP().set_dhcp_filter(sock)

	sock.bind((args.interface, 0x0800))

	# print setting
	print('bind interface: {}'.format(args.interface))
	if args.detail:
		print('capture type: all DHCP broadcast packets')
	else:
		print('capture type: {}'.format(' '.join(simple_dhcp_type)))
		print("{:30}{:20}{:20}{:20}{:20}{:20}".format('Local Time', 'Message Type', 'Host Name', 'MAC', 'IPv4', 'Option 55'))
		print('-' * 130)

	# only get DHCP packets: 
	#     format: IPv4(EtherType: 0x0800) + UDP(port: 67, 68)
	while True:
		packet = sock.recv(2048)

		# get Ethernet Frame
		ethernet_frame = Ethernet(packet)
		source_mac = ethernet_frame.get_source_mac()
		dest_mac = ethernet_frame.get_dest_mac()
		ether_type = ethernet_frame.get_ether_type()

		# get IPv4 packet
		ip_packet = IPv4(packet)
		protocol = ip_packet.get_protocol()
		source_ip = ip_packet.get_source_ip()
		dest_ip = ip_packet.get_dest_ip()

		# get UDP datagram
		udp = UDP(packet)
		source_port = udp.get_source_port()
		dest_port = udp.get_dest_port()
		udp_length = udp.get_length()

		# get DHCP
		dhcp = DHCP(packet, udp_length - 8)
		dhcp.parse_options()
		dhcp.parse_payload()
		chaddr       = dhcp.chaddr
		ciaddr       = dhcp.ciaddr
		message_type = dhcp.option_53
		request_list = dhcp.option_55
		host_name    = dhcp.option_12
		# there is no option50 (request IP) when DHCP client rebinds lease. Should use ciaddr as IP address in this condition.
		request_ip   = dhcp.option_50 if '' != dhcp.option_50 else ciaddr
		server_id    = dhcp.option_54

		# get now
		now = get_time()

		if args.detail:
			print("message type  : {}".format(message_type))
			print("local time    : {}".format(now))
			print("host name     : {}".format(host_name))
			print("request ip    : {}".format(request_ip))
			print("server id     : {}".format(server_id))
			print("source MAC    : {}".format(convert_hex_str_to_mac(chaddr)))
			print("dest   MAC    : {}".format(convert_hex_str_to_mac(dest_mac)))
			print("source IP     : {}:{}".format(source_ip, source_port))
			print("dest   IP     : {}:{}".format(dest_ip, dest_port))
			print("UDP length    : {}".format(udp_length))
			print("option 55     : {}".format(convert_hex_str_to_int_str(request_list)))
			print("")
		else:
			if message_type not in simple_dhcp_type:
				continue

			print("{:30}{:20}{:20}{:20}{:20}{:20}".format(now, message_type, host_name, convert_hex_str_to_mac(chaddr), request_ip, convert_hex_str_to_int_str(request_list)))


