class Lines:
    #loads file into a class object that keeps track of content index in line
    def __init__(self, file):
        self.file = file
        self.num = None
        self.text = None
        self.idx = 0
    
    #removes spaces in line and separates line number/line content
    def parse(self):
        line = self.file.readline()
        self.num = line[:4]
        self.text = line[6:].replace(" ", "").strip()   # added strip()
        self.idx = 0

class Ethernet:
    #Ethernet layer decoding
    def __init__(self):
        self.s_mac = None
        self.hs_mac = None
        self.d_mac = None
        self.hd_mac = None
        self.type = None
        self.type_name = None
        self.type_table = {'0x0800':'IPv4', '0x0806':'ARP', '0X0842':'Wake-on-LAN', '0x2000':'CDP', '0x22ea':'SRP', '0x22f0':'AVTP', '0x22f3':'TRILL', 
                           '0x6002':'MOP', '0x6003':'DECnet', '0x6004':'LAT', '0x8035':'RARP', '0x8102':'SLPP', '0x8137':'IPX', '0x8204':'QNX', '0x86dd':'IPv6',
                           '0x8808':'Ethernet flow control', '0x8809':'LACP', '0x8819':'CobraNet', '0x8847':'MPLS unicast', '0x8848':'MPLS multicast', 
                           '0x8863':'PPPoE Discovery', '0x8864':'PPPoE Session', '0x887b':'HomePlug', '0x8892':'PROFINET', '0x889a':'SCSI', '0x88a2':'ATA',
                           '0x88a4':'EtherCat', '0x88b9':'GSE', '0x88ba':'SV', '0x88cc':'LLDP', '0x88cd':'SERCOS III', '0x88e3':'MRP', '0x88f7':'PTP', 
                           '0x88f8':'NC-SI', '0x88fb':'PRP', '0x8902':'CFM', '0x8906':'FCoE', '0x8915':'RoCE', '0x891d':'TTE', '0x892f':'HSR', '0x9000':'ECTP'}

    def parse(self, lines):
        self.d_mac = lines.text[lines.idx:lines.idx+2]
        lines.idx += 2
        for i in range(5):
            self.d_mac += ':'
            self.d_mac += lines.text[lines.idx:lines.idx+2]
            lines.idx += 2
        self.hd_mac = '0x' + lines.text[lines.idx-12:lines.idx]
        self.s_mac = lines.text[lines.idx:lines.idx+2]
        lines.idx += 2
        for i in range(5):
            self.s_mac += ':'
            self.s_mac += lines.text[lines.idx:lines.idx+2]
            lines.idx += 2
        self.hs_mac = '0x' + lines.text[lines.idx-12:lines.idx]
        self.type = '0x' + lines.text[lines.idx:lines.idx+4]
        lines.idx += 4
        self.type_name = self.type_table.get(self.type.lower(), 'N/A')
        # parsed up to byte 14 (idx 28) of line 0x0000

class IP:
    #ip layer decoding
    def __init__(self):
        self.hversion = None
        self.version = None
        self.hIHL = None
        self.IHL = None
        self.tos = None
        self.hlength = None
        self.length = None
        self.id = None
        self.hflags = None
        self.r = None
        self.df = None
        self.mf = None
        self.offset = None
        self.httl = None
        self.ttl = None
        self.protocol = None
        self.protocol_name = None
        self.checksum = None
        self.hsource = None
        self.source = None
        self.hdestination = None
        self.destination = None
        self.hoptions = None
        self.options = None
        # self.option_meaning = []
        self.protocol_table = {'0x00':'HOPOPT', '0x01':'ICMP', '0x02':'IGMP', '0x03':'GGP', '0x04':'IP-in-IP', '0x05':'ST', '0x06':'TCP', '0x07':'CBT', '0x08':'EGP',
                               '0x09':'IGP', '0x0a':'BBN-RCC-MON', '0x0b':'NVP-II', '0x0c':'PUP', '0x0d':'ARGUS', '0x0e':'EMCON', '0x0f':'XNET', '0x10':'CHAOS',
                               '0x11':'UDP', '0x12':'MUX', '0x13':'DCN-MEAS', '0x14':'HMP', '0x15':'PRM', '0x16':'XNS-IDP', '0x17':'TRUNK-1', '0x18':'TRUNK-2',
                               '0x19':'LEAF-1', '0x1a':'LEAF-2', '0x1b':'RDP', '0x1c':'IRTP', '0x1d':'ISO-TP4', '0x1e':'NETBLT', '0x1f':'MFE-NSP', '0x20':'MERIT-INP',
                               '0x21':'DCCP', '0x22':'3PC', '0x23':'IDPR', '0x24':'XTP', '0x25':'DDP', '0x26':'IDPR-CMTP', '0x27':'TP++', '0x28':'IL', '0x29':'IPv6',
                               '0x2a':'SDRP', '0x2b':'IPv6-Route', '0x2c':'IPv6-Frag', '0x2d':'IDRP', '0x2e':'RSVP', '0x2f':'GRE', '0x30':'DSR', '0x31':'BNA', 
                               '0x32':'ESP', '0x33':'AH', '0x34':'I-NLSP', '0x35':'SwIPe', '0x36':'NARP', '0x37':'MOBILE', '0x38':'TLSP', '0x39':'SKIP', 
                               '0x3a':'IPv6-ICMP', '0x3b':'IPv6-NoNxt', '0x3c':'IPv6-Opts', '0x3d':'Any host internal protocol', '0x3e':'CFTP', 
                               '0x3f':'Any local network', '0x40':'SAT-EXPAK', '0x41':'KRYPTOLAN', '0x42':'RVD', '0x43':'IPPC', '0x44':'Any distributed file system',
                               '0x45':'SAT-MON', '0x46':'VISA', '0x47':'IPCU', '0x48':'CPNX', '0x49':'CPHB', '0x4a':'WSN', '0x4b':'PVP', '0x4c':'BR-SAT-MON',
                               '0x4d':'SUN-ND', '0x4e':'WB-MON', '0x4f':'WB-EXPAK', '0x50':'ISO-IP', '0x51':'VMTP', '0x52':'SECURE-VMTP', '0x53':'VINES', 
                               '0x54':'TTP', '0x55':'NSFNET-IGP', '0x56':'DGP', '0x57':'TCF', '0x58':'EIGRP', '0x59':'OSPF', '0x5a':'Sprite-RPC', '0x5b':'LARP',
                               '0x5c':'MTP', '0x5d':'AX.25', '0x5e':'OS', '0x5f':'MICP', '0x60':'SCC-SP', '0x61':'ETHERIP', '0x62':'ENCAP', 
                               '0x63':'Any private encryption scheme', '0x64':'GMTP', '0x65':'IFMP', '0x66':'PNNI', '0x67':'PIM', '0x68':'ARIS', '0x69':'SCPS', 
                               '0x6a':'QNX', '0x6b':'A/N', '0x6c':'IPComp', '0x6d':'SNP', '0x6e':'Compaq-Peer', '0x6f':'IPX-in-IP', '0x70':'VRRP', '0x71':'PGM',
                               '0x72':'Any 0-hop protocol', '0x73':'L2TP', '0x74':'DDX', '0x75':'IATP', '0x76':'STP', '0x77':'SRP', '0x78':'UTI', '0x79':'SMP',
                               '0x7a':'SM', '0x7b':'PTP', '0x7c':'IS-IS over IPv4', '0x7d':'FIRE', '0x7e':'CRTP', '0x7f':'CRUDP', '0x80':'SSCOPMCE', '0x81':'IPLT',
                               '0x82':'SPS', '0x83':'PIPE', '0x84':'SCTP', '0x85':'FC', '0x86':'RSVP-E2E-IGNORE', '0x87':'Mobility Header', '0x88':'UDPLite',
                               '0x89':'MPLS-in-IP', '0x8a':'MANET', '0x8b':'HIP', '0x8c':'Shim6', '0x8d':'WESP', '0x8e':'ROHC', '0x8f':'Ethernet', '0x90':'AGGFRAG',
                               '0x91':'NSH'}
        # self.options_table = {'00':'EOOL', '01':'NOOP', '02':'SEC', '07':'RR', '0A':'ZSU', '0B':'MTUP', '0C':'MTUR', '0F':'ENCODE', '19':'QS', '1E':'EXP', '44':'TS',
        #                       '52':'TR', '5E':'EXP', '82':'SEC', '83':'LSR', '85':'E-SEC', '86':'CIPSO', '88':'SID', '89':'SSR', '8E':'VISA', '90':'IMITD', '91':'EIP',
        #                       '93':'ADDEXT', '94':'RTRALT', '95':'SDB', '97':'DPS', '98':'UMP', '9E':'EXP', 'CD':'FINN', 'DE':'EXP'}

    def parse(self, lines):
        self.hversion = '0x' + lines.text[lines.idx:lines.idx+1]
        self.version = int(lines.text[lines.idx:lines.idx+1], 16)
        lines.idx += 1
        self.hIHL = '0x' + lines.text[lines.idx:lines.idx+1]
        self.IHL = int(lines.text[lines.idx:lines.idx+1], 16) * 4
        lines.idx += 1
        self.tos = '0x' + lines.text[lines.idx:lines.idx+2]
        lines.parse()
        self.hlength = '0x' + lines.text[lines.idx:lines.idx+4]
        self.length = int(lines.text[lines.idx:lines.idx+4], 16)
        lines.idx += 4
        self.id = '0x' + lines.text[lines.idx:lines.idx+4]
        lines.idx += 4
        self.hflags = '0x' + lines.text[lines.idx:lines.idx+4]
        offset = int(lines.text[lines.idx:lines.idx+4], 16)
        if offset & 32768 == 32768:
            self.r = 1
        else:
            self.r = 0
        if offset & 16384 == 16384:
            self.df = 1
        else:
            self.df = 0
        if offset & 8192 == 8192:
            self.mf = 1
        else:
            self.mf = 0
        self.offset = offset & 8191
        lines.idx += 4
        self.httl = '0x' + lines.text[lines.idx:lines.idx+2]
        self.ttl = int(lines.text[lines.idx:lines.idx+2], 16)
        lines.idx += 2
        self.protocol = '0x' + lines.text[lines.idx:lines.idx+2]
        self.protocol_name = self.protocol_table.get(self.protocol, 'N/A')
        lines.idx += 2
        self.checksum = '0x' + lines.text[lines.idx:lines.idx+4]
        lines.idx += 4
        self.hsource = '0x' + lines.text[lines.idx:lines.idx+2]
        self.source = str(int(lines.text[lines.idx:lines.idx+2], 16))
        lines.idx += 2
        for i in range(3):
            self.source += '.'
            self.hsource += lines.text[lines.idx:lines.idx+2]
            self.source += str(int(lines.text[lines.idx:lines.idx+2], 16))
            lines.idx += 2
        self.hdestination = '0x' + lines.text[lines.idx:lines.idx+2]
        self.destination = str(int(lines.text[lines.idx:lines.idx+2], 16))
        lines.idx += 2
        for i in range(3):
            self.destination += '.'
            if lines.idx == 32:
                lines.parse()
            self.hdestination += lines.text[lines.idx:lines.idx+2]
            self.destination += str(int(lines.text[lines.idx:lines.idx+2], 16))
            lines.idx += 2
        #2 bytes of line read; idx = 4
        if self.IHL != 20:
            self.parse_options(lines)
    
    #stores options as string
    def parse_options(self, lines):
        option_length = self.IHL - 20
        remaining = option_length
        options_text = ''
        while remaining != 0:
            if 32 - lines.idx >= remaining:
                options_text += lines.text[lines.idx:lines.idx+remaining]
                lines.idx += remaining
                remaining = 0
            else:
                options_text += lines.text[lines.idx:]
                remaining -= (32-lines.idx)
                lines.parse()
        self.options = options_text
        #if need to decode option meanings
        # idx = 0
        # while idx < len(self.options):
        #     if idx == 0:
        #         option = self.options[idx:idx+2]
        #         if option != '07':
        #             self.option_meaning.append((option, self.options_table.get(option, 'N/A')))
        #         else:
        #             length = -1
        #         idx += 2
        #     elif option == '07':
        #         if length == -1:
        #             length = int(self.options[idx:idx+2], 16)
        #             RR = []
        #     else:
        #         option = self.options[idx:idx+2]
        #         if option != '07':
        #             self.option_meaning.append((option, self.options_table.get(option, 'N/A')))
        #         else:
        #             length = -1
        #         idx += 2

class UDP:
    #udp decoder
    def __init__(self):
        self.hs_port = None
        self.s_port = None
        self.hd_port = None
        self.d_port = None
        self.hlength = None
        self.length = None
        self.checksum = None

    def parse(self, lines):
        # check if 8 bytes (16 hex) is remaining in the line
        if lines.idx < 15:
            section = lines.text[lines.idx:lines.idx+16]
            lines.idx = lines.idx + 16
        elif lines.idx == 15:
            section = lines.text[lines.idx:]
            lines.parse()
        else:
            remaining = 16 - (32 - lines.idx)
            section = lines.text[lines.idx:]
            lines.parse()
            section += lines.text[:remaining]
            lines.idx = remaining
        return section

    def decode(self, lines):
        text = self.parse(lines)
        self.hs_port = '0x' + text[:4]
        self.s_port = int(text[:4], 16)
        self.hd_port = '0x' + text[4:8]
        self.d_port = int(text[4:8], 16)
        self.hlength = '0x' + text[8:12]
        self.length = int(text[8:12], 16)
        self.checksum = '0x' + text[12:]

class DNS:
    #dns decoder
    def __init__(self):
        self.id = None
        self.flags = None
        self.QR = None
        self.OpCode = None
        self.AA = None
        self.TC = None
        self.RD = None
        self.RA = None
        self.errors = None
        self.hnum_q = None
        self.num_q = None
        self.hnum_answer = None
        self.num_answer = None
        self.hnum_authority = None
        self.num_authority = None
        self.hnum_additional = None
        self.num_additional = None
        self.questions = []
        self.answers = []
        self.authority = []
        self.additional = []
        self.type_table = {1:'A', 28:'AAAA', 18:'AFSDB', 42:'APL', 257:'CAA', 60:'CDNSKEY', 59:'CDS', 37:'CERT', 5:'CNAME', 62:'CSYNC', 49:'DHCID', 32769:'DLV', 
                           39:'DNAME', 48:'DNSKEY', 43:'DS', 108:'EUI48', 109:'EUI64', 13:'HINFO', 55:'HIP', 65:'HTTPS', 45:'IPSECKEY', 25:'KEY', 36:'KX', 29:'LOC',
                           15:'MX', 35:'NAPTR', 2:'NS', 47:'NSEC', 50:'NSEC3', 51:'NSEC3PARAM', 61:'OPENPGPKEY', 12:'PTR', 17:'RP', 46:'RRSIG', 24:'SIG', 53:'SMIMEA',
                           6:'SOA', 33:'SRV', 44:'SSHFP', 64:'SVCB', 32768:'TA', 249:'TKEY', 52:'TLSA', 250:'TSIG', 16:'TXT', 256:'URI', 63:'ZONEMD', 252:'AXFR', 
                           251:'IXFR', 41:'OPT'}
        self.class_table = {'0x0001':'IN', '0x0003':'CH', '0x0004':'HS'}    # added missing 0


    def parse(self, lines):
        section = ""
        while lines.text != "":
            section += lines.text[lines.idx:]
            lines.parse()
        return section
        

    def decode(self, lines):
        text = self.parse(lines)
        idx = 0
        self.id = '0x' + text[idx:idx+4]
        idx += 4
        #identify flags
        self.flags = int(text[idx:idx+4], 16)
        if self.flags & 32768 == 32768:
            self.QR = (1, 'Response')
        else:
            self.QR = (0, 'Query')
        if self.flags & 8192 == 8192:
            self.OpCode = ('010 0', 'Inverse Query')
        else:
            self.OpCode = ('000 0', 'Standard Query')
        if self.flags & 512 == 512:
            self.TC = (1, 'Message Truncated')
        else:
            self.TC = (0, 'Message not Truncated')
        if self.flags & 256 == 256:
            self.RD = (1, 'Recursive Query')
        else:
            self.RD = (0, 'Non-recursive Query')
        if self.QR[0] == 1:
            if self.flags & 1024 == 1024:
                self.AA = (1, 'Authoritative DNS Answer')
            else:
                self.AA = (0, 'Non-authoritative DNS Answer')
            if self.flags & 128 == 128:
                self.RA = (1, 'Recursion Available')
            else:
                self.RA = (0, 'Recursion not Available')
            if self.flags & 4 == 4:
                self.errors = ('0100', 'Format Error in Query')
            elif self.flags & 2 == 2:
                self.errors = ('0010', 'Server Failure')
            elif self.flags & 1 == 1:
                self.errors = ('0001', 'Name Does not Exist')
            else:
                self.errors = ('0000', 'No Error')
        self.flags = '0x' + text[idx:idx+4]
        idx +=4
        self.hnum_q = '0x' + text[idx:idx+4]
        self.num_q = int(text[idx:idx+4], 16)
        idx += 4
        self.hnum_answer = '0x' + text[idx:idx+4]
        self.num_answer = int(text[idx:idx+4], 16)
        idx += 4
        self.hnum_authority = '0x' + text[idx:idx+4]
        self.num_authority = int(text[idx:idx+4], 16)
        idx += 4
        self.hnum_additional = '0x' + text[idx:idx+4]
        self.num_additional = int(text[idx:idx+4], 16)
        idx += 4

        BYTE_CH = 2
        TYPE_CH, CLASS_CH, RDATA_LEN_CH = 4, 4, 4
        TTL_CH = 8
        
        NAME_END = "00" # ending label for data label
        SEP = '.'       # separator for names and IP addresses

        CMPR_HIND = 0xc000  # compression label hex indicator    
        CMPR_CH = 4

        cmpr_table = dict()    

        def decompress(offset):
            if offset in cmpr_table:
                return cmpr_table[offset]
            
            data_label = ""
            ptr = offset * BYTE_CH
            # read data labels, if any
            while (text[ptr:ptr+BYTE_CH] != NAME_END and 
                   int(text[ptr:ptr+CMPR_CH], 16) & CMPR_HIND != CMPR_HIND):
                label_len = int(text[ptr:ptr+BYTE_CH], 16)
                ptr += BYTE_CH
                for byte in range(label_len):
                    data_label += chr(int(text[ptr:ptr+BYTE_CH], 16))
                    ptr += BYTE_CH
                data_label += SEP

            if text[ptr:ptr+BYTE_CH] == NAME_END:   # end of data labels
                data_label = data_label[:-1]    # remove extra '.'
                cmpr_table[offset] = data_label
            else:   # reached compression label
                offset = int(text[ptr:ptr+CMPR_CH], 16) - CMPR_HIND
                data_label += decompress(offset)
            return data_label
        
        def decode_name(idx):
            rname = ""
            # read data labels, if any
            while (text[idx:idx+BYTE_CH] != NAME_END and 
                   int(text[idx:idx+CMPR_CH], 16) & CMPR_HIND != CMPR_HIND):
                label_len = int(text[idx:idx+BYTE_CH], 16)
                idx += BYTE_CH
                for byte in range(label_len):
                    rname += chr(int(text[idx:idx+BYTE_CH], 16))
                    idx += BYTE_CH
                rname += SEP
            
            if text[idx:idx+BYTE_CH] == NAME_END:   # end of data labels
                rname = rname[:-1]  # remove extra '.'
                idx += BYTE_CH  # skip "00" indicating end of NAME
            else: # reached compression label
                offset = int(text[idx:idx+CMPR_CH], 16) - CMPR_HIND
                rname += decompress(offset)
                idx += CMPR_CH
            return idx, rname

        def decode_type(idx):
            itype = int(text[idx:idx+TYPE_CH], 16)
            rtype = self.type_table.get(itype)
            idx += TYPE_CH
            return idx, itype, rtype
        
        def decode_class(idx):
            rclass = self.class_table.get("0x" + text[idx:idx+CLASS_CH])
            idx += CLASS_CH
            return idx, rclass

        def decode_ttl(idx):
            ttl = int(text[idx:idx+TTL_CH], 16)
            idx += TTL_CH
            return idx, ttl

        def decode_ipaddr(idx, rdata_len):
            ipaddr = ""
            for byte in range(rdata_len):
                ipaddr += str(int(text[idx:idx+BYTE_CH], 16))
                ipaddr += SEP
                idx += BYTE_CH
            ipaddr = ipaddr[:-1]  # remove extra '.'
            return idx, ipaddr
        
        def decode_rdata_len(idx):
            rdata_len = int(text[idx:idx+RDATA_LEN_CH], 16)
            idx += RDATA_LEN_CH
            return idx, rdata_len
        
        def decode_rdata(idx, itype, rdata_len):
            rdata = ""
            match itype:
                case 1 | 28:        # A, AAAA
                    idx, rdata = decode_ipaddr(idx, rdata_len)
                case 5 | 2 | 15:    # CNAME, NS, MX
                    idx, rdata = decode_name(idx)
                case _ :            # Other types
                    rdata = None                
            return idx, rdata
        
        # given number of items; decode and append to list (list in list or tuple in list)
        for i in range(self.num_q):
            idx, qname = decode_name(idx)
            idx, _, qtype = decode_type(idx)
            idx, qclass = decode_class(idx)
            self.questions.append((qname, qtype, qclass))

        for i in range(self.num_answer):
            idx, rname = decode_name(idx)
            idx, itype, rtype = decode_type(idx)
            idx, rclass = decode_class(idx)
            idx, ttl = decode_ttl(idx)
            idx, rdata_len = decode_rdata_len(idx)
            idx, rdata = decode_rdata(idx, itype, rdata_len)
            self.answers.append((rname, rtype, rclass, ttl, rdata_len, rdata))

        for i in range(self.num_authority):
            idx, rname = decode_name(idx)
            idx, itype, rtype = decode_type(idx)
            idx, rclass = decode_class(idx)
            idx, ttl = decode_ttl(idx)
            idx, rdata_len = decode_rdata_len(idx)
            idx, rdata = decode_rdata(idx, itype, rdata_len)
            self.authority.append((rname, rtype, rclass, ttl, rdata_len, rdata))
            
        for i in range(self.num_additional):
            idx, rname = decode_name(idx)
            idx, itype, rtype = decode_type(idx)
            idx, rclass = decode_class(idx)
            idx, ttl = decode_ttl(idx)
            idx, rdata_len = decode_rdata_len(idx)
            idx, rdata = decode_rdata(idx, itype, rdata_len)
            self.additional.append((rname, rtype, rclass, ttl, rdata_len, rdata))


class DHCP:
    def __init__(self):
        self.mtype = None
        self.htype = None
        self.hlen = None
        self.hops = None
        self.xid = None
        self.secs = None
        self.flags = None
        self.ciaddr = None
        self.yiaddr = None
        self.siaddr = None
        self.giaddr = None
        self.chaddr = None
        self.chaddr_pad = None
        self.sname = None
        self.file = None
        self.options = None
        self.magic_cookie = None
        self.htype_table = {1:"Ethernet (10Mb)", 2:"Experimental Ethernet (3Mb)", 3:"Amateur Radio AX.25", 4:"Proteon ProNET Token Ring",
                            5:"Chaos", 6:"IEEE 802 Networks", 7:"ARCNET", 8:"Hyperchannel", 9:"Lanstar", 10:"Autonet Short Address",
                            11:"LocalTalk", 12:"LocalNet (IBM PCNet or SYTEK LocalNET)", 13:"Ultra link", 14:"SMDS", 15:"Frame Relay",
                            16:"Asynchronous Transmission Mode (ATM)"}
        self.message_type_table = {
            1: "DHCP DISCOVER", 2: "DHCP OFFER", 3: "DHCP REQUEST", 4: "DHCP DECLINE", 5: "DHCP ACK", 6: "DHCP NAK", 7: "DHCP RELEASE", 8: "DHCP INFORM"
        }
        
        
        self.options_table = {
            1: "Subnet Mask", 2: "Time Offset", 3: "Router", 4: "Time Server", 5: "Name Server", 6: "Domain Name Server", 
            7: "Log Server", 8: "Cookie Server", 9: "LPR Server", 10: "Impress Server", 11: "Resource Location Server",
            12: "Host Name", 13: "Boot File Size", 14: "Merit Dump File", 15: "Domain Name", 16: "Swap Server", 17: "Root Path",
            18: "Extensions Path", 19: "IP Forwarding Enable/Disable", 20: "Non-Local Source Routing Enable/Disable",
            21: "Policy Filter", 22: "Maximum Datagram Reassembly Size", 23: "Default IP Time-to-live", 24: "Path MTU Aging Timeout",
            25: "Path MTU Plateau Table", 26: "Interface MTU", 27: "All Subnets are Local", 28: "Broadcast Address", 29: "Perform Mask Discovery",
            30: "Mask Supplier", 31: "Perform Router Discovery", 32: "Router Solicitation Address", 33: "Static Route", 34: "Trailer Encapsulation",
            35: "ARP Cache Timeout", 36: "Ethernet Encapsulation", 37: "TCP Default TTL", 38: "TCP Keepalive Interval", 39: "TCP Keepalive Garbage",
            40: "Network Information Service Domain", 41: "Network Information Servers", 42: "NTP Servers", 43: "Vendor Specific Information",
            44: "NetBIOS over TCP/IP Name Server", 45: "NetBIOS over TCP/IP Datagram Distribution Server", 46: "NetBIOS over TCP/IP Node Type",
            47: "NetBIOS over TCP/IP Scope", 48: "X Window System Font Server", 49: "X Window System Display Manager", 50: "Request IP Address",
            51: "IP Address Lease Time", 52: "Option Overload", 53: "DHCP Message Type", 54: "Server Identifier", 55: "Parameter Request List",
            56: "Message", 57: "Maximum DHCP Message Size", 58: "Renewal (T1) Time Value", 59: "Rebinding (T2) Time Value", 60: "Vendor class identifier",
            61: "Client-identifier", 62: "NetWare/IP Domain Name", 63: "NetWare/IP sub Options", 64: "NIS+ Domain", 65: "NIS+ Servers", 66: "TFTP Server Name",
            67: "Bootfile Name", 68: "Mobile IP Home Agent", 69: "Simple Mail Transport Protocol (SMTP) Server", 70: "Post Office Protocol (POP3) Server",
            71: "Network News Transport Protocol (NNTP) Server", 72: "Default World Wide Web (WWW) Server", 73: "Default Finger Server", 74: "Default Internet Relay Chat (IRC) Server",
            75: "StreetTalk Server", 76: "StreetTalk Directory Assistance (STDA) Server", 77: "User Class Information", 78: "SLP Directory Agent", 79: "SLP Service Scope",
            80: "Rapid Commit", 81: "FQDN", 82: "Relay Agent Information", 83: "iSNS", 84: "RDNSS Selection", 85: "KRB5 Realm Name", 86: "KRB5 KDC",
            87: "Client NTP", 119: "Domain Search", 120: "SIP Servers DHCP Option", 121: "Classless Static Route Option", 122: "CCC", 123: "GeoConf",
            249: "Private/Classless Static Route Option", 252: "Private Proxy Auto-Discovery", 255: "End of Options List"
        }

    def parse(self, lines):
        section = ""
        while lines.text != "":
            section += lines.text[lines.idx:]
            lines.parse()
        return section
    
    def decode(self, lines):
        BYTE_CH = 2
        SEC_CH, FLAGS_CH = 4, 4
        XID_CH = 8
        COOKIE_CH = 8
        HW_ADDR_PAD_CH = 20
        SNAME_CH = 128
        FNAME_CH = 256

        FLAG_BITS = 16
        IP_ADDR_BYTES = 4
        HW_ADDR_BYTES = 6

        BFLAG_HIND = 0x8000
        IP_SEP = '.'
        MAC_SEP = ':'
        NAME_END = "00"

        text = self.parse(lines)
        idx = 0

        # decode portion of DHCP header message that is of fixed size

        # decode op code / message type; 1 byte
        op = int(text[idx:idx+BYTE_CH], 16)
        idx += BYTE_CH
        if op == 1: self.mtype = "BOOTREQUEST"
        elif op == 2: self.mtype = "BOOTREPLY"

        # decode hardware address type; 1 byte
        htype_int = int(text[idx:idx+BYTE_CH], 16)
        idx += BYTE_CH
        self.htype = self.htype_table.get(htype_int)

        # decode hardware address length; 1 byte
        self.hlen = int(text[idx:idx+BYTE_CH], 16)
        idx += BYTE_CH

        # decode hops; 1 byte
        self.hops = int(text[idx:idx+BYTE_CH], 16)
        idx += BYTE_CH

        # decode transaction ID; 4 bytes
        self.xid = "0x" + text[idx:idx+XID_CH]
        idx += XID_CH

        # decode seconds elapsed since client began address acquisition or renewal process; 2 bytes
        self.secs = int(text[idx:idx+SEC_CH], 16)
        idx += SEC_CH

        # decode BROADCAST and MUST BE ZERO flags; total 2 bytes
        flags_int = int(text[idx:idx+FLAGS_CH], 16)
        idx += FLAGS_CH
        self.flags = ""
        for bit in range(FLAG_BITS):
            self.flags += str(flags_int & (BFLAG_HIND >> bit))
        
        # decode client IP address; 4 bytes
        self.ciaddr = str(int(text[idx:idx+BYTE_CH], 16))
        idx += BYTE_CH
        for byte in range(IP_ADDR_BYTES-1):
            self.ciaddr += IP_SEP + str(int(text[idx:idx+BYTE_CH], 16))
            idx += BYTE_CH
        
        # decode 'your' (client) IP address; 4 bytes
        self.yiaddr = str(int(text[idx:idx+BYTE_CH], 16))
        idx += BYTE_CH
        for byte in range(IP_ADDR_BYTES-1):
            self.yiaddr += IP_SEP + str(int(text[idx:idx+BYTE_CH], 16))
            idx += BYTE_CH

        # decode IP address of next server to use in bootstrap; 4 bytes
        self.siaddr = str(int(text[idx:idx+BYTE_CH], 16))
        idx += BYTE_CH
        for byte in range(IP_ADDR_BYTES-1):
            self.siaddr += IP_SEP + str(int(text[idx:idx+BYTE_CH], 16))
            idx += BYTE_CH

        # decode relay agent IP address; 4 bytes
        self.giaddr = str(int(text[idx:idx+BYTE_CH], 16))
        idx += BYTE_CH
        for byte in range(IP_ADDR_BYTES-1):
            self.giaddr += IP_SEP + str(int(text[idx:idx+BYTE_CH], 16))
            idx += BYTE_CH

        # decode client hardware address and padding; 6 + 10 bytes
        self.chaddr = text[idx:idx+BYTE_CH]
        idx += BYTE_CH
        for byte in range(HW_ADDR_BYTES-1):
            self.chaddr += MAC_SEP + text[idx:idx+BYTE_CH]
            idx += BYTE_CH

        self.chaddr_pad = text[idx:idx+HW_ADDR_PAD_CH]
        idx += HW_ADDR_PAD_CH
        
        # decode optional server host name; 64 bytes
        if text[idx:idx+BYTE_CH] != NAME_END:
            self.sname = ""
            ptr = idx
            while text[ptr:ptr+BYTE_CH] != NAME_END:
                self.sname += chr(int(text[ptr:ptr+BYTE_CH], 16))
                ptr += BYTE_CH
        
        idx += SNAME_CH

        # decode boot file name
        if text[idx:idx+BYTE_CH] != NAME_END:
            self.file = ""
            ptr = idx
            while text[ptr:ptr+BYTE_CH] != NAME_END:
                self.file += chr(int(text[ptr:ptr+BYTE_CH], 16))
                ptr += BYTE_CH
        
        idx += FNAME_CH
        
        #decode magic cookie
        if text[idx:idx+COOKIE_CH] != NAME_END:
            self.magic_cookie = text[idx:idx+COOKIE_CH]
            idx += COOKIE_CH
        
        # decode options
        self.options = []
        while text[idx:idx+BYTE_CH] != "ff":
            option = int(text[idx:idx+BYTE_CH], 16)
            idx += BYTE_CH
            if option == 0:
                break
            length = int(text[idx:idx+BYTE_CH], 16)
            idx += BYTE_CH
            data = text[idx:idx+length*BYTE_CH]
            idx += length*BYTE_CH
            if option == 53:
                self.options.append((option, self.options_table[option], f"{int(data, 16)} ({self.message_type_table[int(data, 16)]})"))
            elif option == 55:
                parameters = []
                for i in range(length):
                    parameters.append((int(data[i*BYTE_CH:i*BYTE_CH+BYTE_CH], 16), self.options_table.get(int(data[i*BYTE_CH:i*BYTE_CH+BYTE_CH], 16))))
                self.options.append((option, self.options_table[option], parameters))
            elif option == 57:
                self.options.append((option, self.options_table[option], f'{int(data, 16)} bytes'))
            elif option == 61:
                client_mac = ""
                idtype = self.htype_table.get(int(data[:2], 16))
                for i in range(2, len(data)):
                    client_mac += data[i]
                    if i % 2 == 1 and i != len(data)-1:
                        client_mac += MAC_SEP
                self.options.append((option, self.options_table[option], f"Type: {int(data[:2], 16)} ({idtype}) Client Mac: {client_mac}"))
            else:
                self.options.append((option, self.options_table[option], data))
        
        # decode end of options list
        self.options.append((255, self.options_table[255], "End of Options List"))
        
        


#fix output reqs
while True:
    f = open(input('Hex dump file name: '), 'r')
    print()
    text = Lines(f)
    text.parse()
    layer2 = Ethernet()
    layer2.parse(text)
    layer3 = IP()
    layer3.parse(text)
    #print layer 2 stuff
    print('Layer 2: Ethernet II')
    print('Destination: {0} ({1})'.format(layer2.hd_mac, layer2.d_mac))
    print('Source: {0} ({1})'.format(layer2.hs_mac, layer2.s_mac))
    print('Type: {0} ({1})'.format(layer2.type, layer2.type_name))
    print()
    #print layer 3 stuff
    print('Layer 3: IPv4')
    print('Version: {0} ({1})'.format(layer3.hversion, layer3.version))
    print('IHL: {0} ({1} bytes)'.format(layer3.hIHL, layer3.IHL))
    print('ToS: {}'.format(layer3.tos))
    print('Total Length: {0} ({1})'.format(layer3.hlength, layer3.length))
    print('Identification: {}'.format(layer3.id))
    print('Flags: {}'.format(layer3.hflags))
    print(' Reserved: {}'.format(layer3.r))
    print(' DF: {}'.format(layer3.df))
    print(' MF: {}'.format(layer3.mf))
    print(' Fragment Offset: {}'.format(layer3.offset))
    print('TTL: {0} ({1})'.format(layer3.httl, layer3.ttl))
    print('Protocol: {0} ({1})'.format(layer3.protocol, layer3.protocol_name))
    print('Header Checksum: {}'.format(layer3.checksum))
    print('Source Address: {0} ({1})'.format(layer3.hsource, layer3.source))
    print('Destination Address: {0} ({1})'.format(layer3.hdestination, layer3.destination))
    if layer3.options != None:
        print('Options: 0x{}'.format(layer3.options))
    print()
    #print layer 4; skip if not udp
    if layer3.protocol == '0x11':
        layer4 = UDP()
        layer4.decode(text)
        print('Layer 4: UDP')
        print('Source Port: {0} ({1})'.format(layer4.hs_port, layer4.s_port))
        print('Destination Port: {0} ({1})'.format(layer4.hd_port, layer4.d_port))
        print('Length: {0} ({1})'.format(layer4.hlength, layer4.length))
        print('Checksum: {}'.format(layer4.checksum))
        print()
        #print layer 7 stuff
        #dhcp finish
        if layer4.s_port == 68 or layer4.d_port == 68:
            layer7 = DHCP()
            layer7.decode(text)
            print(f"Message type: {layer7.mtype}")
            print(f"Hardware type: {layer7.htype}")
            print(f"Hardware address length: {layer7.hlen}")
            print(f"Hops: {layer7.hops}")
            print(f"Transaction ID: {layer7.xid}")
            print(f"Seconds elapsed: {layer7.secs}")
            print(f" {layer7.flags[0]}... .... .... .... = Broadcast flag")
            print(f" .{layer7.flags[1:4]} {layer7.flags[4:8]} {layer7.flags[8:12]} {layer7.flags[12:]} = Reserved flags")
            print(f"Client IP address: {layer7.ciaddr}")
            print(f"Your (client) IP address: {layer7.yiaddr}")
            print(f"Next server IP address: {layer7.siaddr}")
            print(f"Relay agent IP address: {layer7.giaddr}")
            print(f"Client MAC address: {layer7.chaddr}")
            print(f"Client hardware address padding: {layer7.chaddr_pad}")
            print("Server host name not given" if layer7.sname is None else f"Server host name: {layer7.sname}")
            print("Boot file name not given" if layer7.file is None else f"Boot file name: {layer7.file}")
            print("Magic cookie not given" if layer7.magic_cookie is None else f"Magic cookie: {layer7.magic_cookie}")
            print("Options: ")
            for option in layer7.options:
                print(f"\t{option[0]} ({option[1]}): {option[2]}")
            print()
            

        elif layer4.s_port == 53 or layer4.d_port == 53:
            layer7 = DNS()
            layer7.decode(text)
            print('Transaction ID: {}'.format(layer7.id))
            print('Flags: {}'.format(layer7.flags))
            print(' {0}... .... .... .... = {1}'.format(layer7.QR[0], layer7.QR[1]))
            print(' .{0}... .... .... = {1}'.format(layer7.OpCode[0], layer7.OpCode[1]))
            if layer7.QR[0] == 1:
                print(' .... .{0}.. .... .... = {1}'.format(layer7.AA[0], layer7.AA[1]))
            print(' .... ..{0}. .... .... = {1}'.format(layer7.TC[0], layer7.TC[1]))
            print(' .... ...{0} .... .... = {1}'.format(layer7.RD[0], layer7.RD[1]))
            if layer7.QR[0] == 1:
                print(' .... .... {0}... .... = {1}'.format(layer7.RA[0], layer7.RA[1]))
                print(' .... .... .... {0} = {1}'.format(layer7.errors[0], layer7.errors[1]))
            print('Questions: {}'.format(layer7.num_q))
            print('Answers RRs: {}'.format(layer7.num_answer))
            print('Authority RRs: {}'.format(layer7.num_authority))
            print('Additional RRs: {}'.format(layer7.num_additional))
            if len(layer7.questions) != 0:
                print('Queries: ')
                for question in layer7.questions:
                    print('\tName: {}'.format(question[0]))
                    print('\tType: {}'.format(question[1]))
                    print('\tClass: {}'.format(question[2]))
                    print()
            if len(layer7.answers) != 0:
                print('Answers: ')
                for answer in layer7.answers:
                    print('\tName: {}'.format(answer[0]))
                    print('\tType: {}'.format(answer[1]))
                    print('\tClass: {}'.format(answer[2]))
                    print('\tTime to live: {}'.format(answer[3]))
                    print('\tData Length: {}'.format(answer[4]))
                    print('\tAddress: {}\n'.format(answer[5]) if answer[5] is not None else "", end="")
                    print()
            if len(layer7.authority) != 0:
                print('Authority Records: ')
                for record in layer7.authority:
                    print('\tName: {}'.format(record[0]))
                    print('\tType: {}'.format(record[1]))
                    print('\tClass: {}'.format(record[2]))
                    print('\tTime to live: {}'.format(record[3]))
                    print('\tData Length: {}'.format(record[4]))
                    print('\tAddress: {}\n'.format(record[5]) if record[5] is not None else "", end="")
                    print()
            if len(layer7.additional) != 0:
                print('Additional Records: ')
                for record in layer7.additional:
                    print('\tName: {}'.format(record[0]))
                    print('\tType: {}'.format(record[1]))
                    print('\tClass: {}'.format(record[2]))
                    print('\tTime to live: {}'.format(record[3]))
                    print('\tData Length: {}'.format(record[4]))
                    print('\tAddress: {}\n'.format(record[5]) if record[5] is not None else "", end="")
                    print()
    else:
        print('Layer 4: N/A')
        print()
        print('Layer 7: N/A')
    while text.num != '0010' and len(text.text) != 0:
        text.parse()
    if len(text.text) == 0:
        f.close()
        again = input('Analyze another file? (Y/N): ')
        while again.lower() not in ['y', 'n']:
            print('Invalid Input')
            again = input('Analyze another file? (Y/N): ')
        if again.lower() == 'n':
            break
