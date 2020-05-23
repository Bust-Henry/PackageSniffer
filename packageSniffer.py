import socket

# the public network interface
HOST = socket.gethostbyname(socket.gethostname())

# create a raw socket and bind it to the public interface
s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
s.bind((HOST, 0))

# Include IP headers
s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

# receive all packages
s.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

# receive a package
bytelist = []
iplist = []
with open("readbytes", "ab") as bytefile:
    with open("ips.txt", "a") as ipfile:
        while True:
            print(s.recvfrom(65565))
            bytefile.write(s.recvfrom(65565)[0])
            ipfile.write(s.recvfrom(65565)[1][0] + "\n")

# disabled promiscuous mode
# -->  s.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
