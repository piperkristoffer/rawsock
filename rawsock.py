
import re
import struct
import subprocess
import uuid
import threading
import sys
import socket
import random
import urlparse

#GLOBALS
source_IP = ''
destination_IP = ''
interface = ''
source_port = random.randint(30000, 50000)
destination_port = 80
tcp_data = {'sequence_no':0, 'ack_no':0, 'ack_flag':0, 'syn_flag':0, 'finish_flag':0, 'application_data':''}
hostname = ''
respathname = ''
filename = ''
index = 0
ssthreshold = 1

def host_and_path_Parser(url):
    print('Host and Path Parser\n')
    global hostname, uriname, filename
    if url == '':
        print("No URL given. Program quitting")
        sys.exit()
    if "https://" not in url:
        url = 'https://' + url

    url_elements = url.split('/')
    scheme_name = url_elements[0] + '//'
    hostname = url_elements[2]
    respathname = url_elements[3:-1]
    filename = url_elements[-1]
    # print(url_elements)
    return

def get_IPddr_srcdest(hostname):
    print('Get IP Addrs')
    global source_IP, destination_IP
    try:
        udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, 0)
        udp_socket.connect(("8.8.8.8", 80))
        source_IP = udp_socket.getsockname()[0].rstrip()

        destination_IP = socket.gethostbyname(hostname).rstrip()
        # print(source_IP)
        # print(destination_IP)

    except:
        print("Error occurred in gathering SRC/DST IP")
        sys.exit()
    return

def makeSend():
    print('Make send socket')
    try:
        send_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    except socket.error as e:
        print("Error in trying to create send socket. Error {}".format(e))
        sys.exit()
    return send_socket

def makeRecv():
    print('Make recv socket')
    try:
        recv_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    except socket.error as e:
        print("Error in trying to create recv socket. Error {}".format(e))
        sys.exit()
    return recv_socket

def send_pack(packet, sock):
    print('Send packet')
    global destination_IP, destination_port
    # print(packet)
    sock.sendto(packet, (destination_IP, destination_port))
    return

def recv_pack(sock):
    print('Recv packet')
    global destination_IP, source_IP
    global destination_port, source_port
    local_src_IP = ""
    local_dst_port = ""

    while((local_src_IP != str(destination_IP) and local_dst_port != str(source_port))
    or (local_src_IP != "" and local_dst_port != "")):
        print('In the loop')
        import pdb; pdb.set_trace()
        recv_packet = sock.recvfrom(65565)
        print('Helo')
        header_key = recv_packet[0:20]
        header = struct.unpack("!2sH8s4s4s", header_key)
        local_src_IP = sock.inet_ntoa(header[3])
        tcp_key = recv_packet[20:40]
        tcp_header = struct.unpack('!HHLLBBHHH', tcp_key)
        local_dst_port = str(tcp_header[1])
        destination_IP = ""
        local_dst_port = ""

    return recv_packet

def ifAckRecvd(recv_sock, max_header = 40):
    print('Check if Acknowledge recvd')
    packet_recv = recv_pack(recv_sock)
    ip_header = struct.unpack('!2sH8s4s4s', packet_recv[0:20])
    mss = 0
    unpack_arguments = "!HHLLBBHHH"

    if(max_tcp_header == 44):
        unpack_arguments += 'L'

    tcp_header = struct.unpack(unpack_arguments, packet_recv[20:max_header])
    length = ip_header[1] - 40
    if(length == 0 or 4):
        seq_no = tcp_header[2]
        ack_no = tcp_header[3]
        tcp_fl = tcp_header[5]

        if (tcp_fl == 4):
            print('Destination Port closed')
            sys.exit()

        if(max_header == 44):
            max_seg = tcp_header[9]
        ack_flag = (tcp_fl & 16)

        if(ack_flag == 16):
            return seq_no, max_seg

    return False, max_seg




def ip_headerMake(header_len):
    print('Make IP Header')
    global source_IP, destination_IP

    length = 5
    version = 4
    version_n_length = length + (version << 4)
    dscp = 0
    total_length = 20 + header_len
    packet_id = random.randint(10000,50000)
    frag_offset = 0
    ttl = 255
    protocol = socket.IPPROTO_TCP
    checksum = 0
    source_addr = socket.inet_aton(source_IP)
    destination_addr = socket.inet_aton(destination_IP)

    # import pdb; pdb.set_trace()
    pseudo_header = struct.pack('!BBHHHBBH4s4s', version_n_length, dscp, total_length, packet_id, frag_offset, ttl, protocol, checksum, source_addr, destination_addr)
    checksum = checksumMake(pseudo_header)
    ip_header = struct.pack('!BBHHHBBH4s4s', version_n_length, dscp, total_length, packet_id, frag_offset, ttl, protocol, checksum, source_addr, destination_addr)

    return ip_header

def makeTCPHandshake(data, send_sock):
    print('Make TCP handshake and send')
    global tcp_data
    tcp_seg = tcp_headerMake(data)
    header_len = 20
    ip_header = ip_headerMake(header_len)
    packet = ip_header + tcp_seg
    send_pack(packet, send_sock)
    tcp_data = data

def TCP_handshake(send_sock, recv_sock):
    print('Do TCP Handhsake')
    global tcp_data

    tcp_data['sequence_no'] = 0
    tcp_data['ack_no'] = 0
    tcp_data['ack_flag'] = 0
    tcp_data['syn_flag'] = 1
    tcp_data['finish_flag'] = 0
    tcp_data['application_data'] = ''

    data = tcp_data
    makeTCPHandshake(data, send_sock)
    new_ack, max_seg = ifAckRecvd(recv_sock, 44)
    import pdb; pdb.set_trace()

    if(new_ack == False):
        print("Handshake failure \n")
        sys.exit()
    else:
        tcp_data['sequence_no'] = 1
        tcp_data['sequence_no'] = 1
        tcp_data['ack_no'] = new_ack + 1
        tcp_data['ack_flag'] = 1
        tcp_data['syn_flag'] = 0
        tcp_data['finish_flag'] = 0
        tcp_data['application_data'] = ''

        data = tcp_data
        makeTCPHandshake(data, send_sock)
        return new_ack, max_seg, tcp_data['sequence_no']

def tcp_headerMake(data, PSH=0):
    print('Make TCP header')
    global source_port, destination_port

    sequenceNum = data['sequence_no']
    ackNum = data['ack_no']
    data_offset = (5 << 4) + 0
    FIN_fl = data['finish_flag']
    SYN_fl = data['syn_flag']
    RST_fl = 0
    PSH_fl = PSH
    ACK_fl = data['ack_flag']
    URG_fl = 0
    TCP_fls = FIN_fl + (SYN_fl << 1) + (RST_fl << 2) + (PSH_fl << 3) + (ACK_fl << 4) + (URG_fl << 5)
    win_size = socket.htons(1500)
    checksum = 0
    URG_ptr = 0
    app_data_len = len(data['application_data'])

    if (app_data_len%2):
        app_data_len += 1
    if data['application_data']:
        tcp_header = struct.pack("!HHLLBBHHH"+str(app_data_len)+'s', source_port, destination_port, sequenceNum, ackNum, data_offset, TCP_fls, win_size, checksum, URG_ptr)
    else:
        tcp_header = struct.pack("!HHLLBBHHH", source_port, destination_port, sequenceNum, ackNum, data_offset, TCP_fls, win_size, checksum, URG_ptr)

    source_addr = socket.inet_aton(source_IP)
    destination_addr = socket.inet_aton(destination_IP)

    # import pdb; pdb.set_trace()
    pseudo_header = struct.pack('!4s4sBBH', source_addr, destination_addr, 0, socket.IPPROTO_TCP, len(tcp_header))
    pseudo_header = pseudo_header + tcp_header
    checksum = checksumMake(pseudo_header)

    if data['application_data']:
        tcp_segment = struct.pack("!HHLLBBHHH"+str(app_data_len)+'s', source_port, destination_port, sequenceNum, ackNum, data_offset, TCP_fls, win_size, checksum, URG_ptr, data['application_data'].encode('iso-8859-1'))
    else:
        tcp_segment = struct.pack("!HHLLBBHHH", source_port, destination_port, sequenceNum, ackNum, data_offset, TCP_fls, win_size, checksum, URG_ptr)

    return tcp_header

def checksumMake(header):
    print('Make Checksum')

    checksum = 0
    for x in range(0, len(header), 2):

        wrd1 = struct.unpack("!H", header[x]+"\x00")[0] << 8
        wrd2 = struct.unpack("!H", header[x+1]+"\x00")[0]

        # wrd = (header[x] << 8) + (header[x+1])
        wrd = wrd1 + wrd2
        checksum = checksum + wrd

    checksum = (checksum >> 16) + (checksum & 0xffff)
    checksum = checksum + (checksum >> 16)
    checksum = ~(checksum) & 0xffff
    return checksum

def GetRequest(http_get, seq_no, ack_no, congestion_win, mss, send_sock, recv_sock):
    print('Send GET')
    global index, ssthreshold, tcp_data
    last_part = 0
    if(ssthreshold == 1):
        congestion_win = 1
        ssthreshold = 0
    else:
        product = congestion_win * mss
        index=index+product
        congestion_win = min(2*congestion_win, 40)

    if(len(http_get) - index <= 0):
        return

    if (len(http_get) - index > congestion_win * mss):
        seg = http_get[index:(index + congestion_win * mss)]
    else:
        seg = http_get[index:]
        last_part = 1

    tcp_data['sequence_no'] = seq_no
    tcp_data['ack_no'] = ack_no + 1
    tcp_data['ack_flag'] = 1
    tcp_data['syn_flag'] = 0
    tcp_data['finish_flag'] = 0
    tcp_data['application_data'] = segment
    PSH_flag = 1

    data = tcp_data
    makeTCPHandshake(data, send_sock)

    seq_no_recv, mss = ifAckRecvd(recv_sock)
    while((seq_no_recv == False) and (ssthreshold == 0)):
        seq_no_recv, mss = ifAckRecvd(recv_sock)

    if(last_part == 1):
        return
    GetRequest(http_get, seq_no + congestion_win*mss, ack_no, congestion_win, mss, send_sock, recv_sock)

def GetResponse(seq_no, ack_no, recv_sock, send_sock):
    print('Get Response')
    global tcp_data

    FIN = 1
    collected = {}
    shutdown = 0
    while(shutdown != 1):
        recv_packet = recv_pack(recv_sock)
        ip_packed = recv_packet[0:20]
        tcp_packed = recv_packet[20:40]

        ip_header = struct.unpack("!2sH8s4s4s", ip_packed)
        recv_length = ip_header[1] - 40
        tcp_header = struct.unpack("!HHLLBBHHH", tcp_packed)
        ACK_PSH_FIN_RST_flag = tcp_header[5]
        new_seq_no = int(tcp_header[3])
        new_ack_no = int(tcp_header[2])

        if(recv_length != 0):
            unpack_arg = "!" + str(recv_length) + "s"
            app_seg = struct.unpack(unpack_arg, recv_packet[40:(recv_length + 40)])
            collected[new_ack_no] = app_seg[0]
            if(checksumComp(recv_packet, recv_length)):
                tcp_data['sequence_no'] = new_seq_no
                tcp_data['ack_no'] = new_ack_no + recv_length
                tcp_data['ack_flag'] = 1
                tcp_data['syn_flag'] = 0
                tcp_data['finish_flag'] = 0
                tcp_data['application_data'] = ''

                data = tcp_data
                makeTCPHandshake(data, send_sock)

        if(ACK_PSH_FIN_RST_flag == 25) or (ACK_PSH_FIN_RST_flag == 17) or (ACK_PSH_FIN_RST_flag == 4):
            if (ACK_PSH_FIN_RST_flag == 4):
                print("Port closed at server")
                sys.exit()
        shutdown = 1
        tcp_data['sequence_no'] = new_seq_no
        tcp_data['ack_no'] = new_ack_no + recv_length + 1
        tcp_data['ack_flag'] = 1
        tcp_data['syn_flag'] = 0
        tcp_data['finish_flag'] = FIN
        tcp_data['application_data'] = ''

        data = tcp_data
        makeTCPHandshake(data, send_sock)

    return new_seq_no, new_ack_no, collected

def checksumComp(packet, length):
    print('Compare checksum')
    ip_header = struct.unpack("!BBHHHBBH4s4s", packet[0:20])
    reserved = 0
    tcp_length = ip_header[2] - 20
    protocol = ip_header[6]
    source_ip = ip_header[8]
    destination_ip = ip_header[9]
    tcp_header_packed = packet[20:]

    unpack_arguments = '!HHLLBBHHH' + str(length) + 's'

    if(length % 2):
        length += 1

    packing_argument = '!HHLLBBHHH' + str(length) + 's'
    tcp_header = struct.unpack(unpack_arguments, tcp_header_packed)

    received_tcp_segment = struct.pack(packing_argument, tcp_header[0], tcp_header[1], tcp_header[2], tcp_header[3], tcp_header[4], tcp_header[5], tcp_header[6], 0, tcp_header[8], tcp_header[9])
    pseudo_header = struct.pack("!4s4sBBH", source_ip, destination_ip, reserved, protocol, tcp_length)
    message = pseudo_header + received_tcp_segment
    checksum_received_packet = tcp_header[7]

    return (checksum_received_packet == calculate_checksum(message))


def main():
    global hostname
    URL = sys.argv[1]


    #Getting URL vars, and SRC & DST IP vars
    host_and_path_Parser(URL)
    get_IPddr_srcdest(hostname)

    #Creating Sockets
    send_sock = makeSend()
    recv_sock = makeRecv()

    #TCP Handshake
    new_ack, max_seg, new_seq = TCP_handshake(send_sock, recv_sock)

    HTTP_GET = "GET " + respathname + " HTTP/1.1\r\n" + "Host: " + hostname + "\r\n\r\n"
    GetRequest(HTTP_GET, new_seq, new_ack, 3, mss, send_sock, recv_sock)

    response_seq_no, response_ack_no, response = GetResponse(new_ack, new_seq, recv_sock, send_sock)

    only_response = ""

    for x in sorted(response):
        only_response += response[x].decode('iso-8859-1')

    if(re.search(r'^HTTP/\/\d\.\ds200\sOK', only_response)):
        with open(file_name, 'w') as page:
            page.write(only_response.split('\r\n\r\n')[1])
    else:
        print("Response not 200")
        sys.exit()

    send_sock.close()
    recv_sock.close()
    page.close()



if __name__ == "__main__":
    # import pdb; pdb.set_trace()
    main()
