How to run the program:

Download the Decoder.py file
Type "python {pathname of Decoder.py}" in the command line
Type the pathname of the hexdump file that needs to be analyzed in the command line
Once the output has been printed to the command line, you may type one of the following characters (case-insensitive):
    'Y' = analyze another file
    'N' = terminate the program
    'S' = save the command line output to a file


Structure of the code:

class Lines
    Loads file into a class object that keeps track of content index in line

    parse()
        Processes a single line - removes spaces in line and separates line number/line content

class Ethernet
    Decodes Layer 2 of the packet (Ethernet)

    parse()
        Processes and decodes the Ethernet header

class IP
    Decodes Layer 3 of the packet (IP)

    parse()
        Processes and decodes the IP header
    parse_options()
        Called by parse()
        Stores the hex of options in a string

class UDP
    Decodes Layer 4 of the packet (UDP)

    parse()
        Stores the UDP header in a string for decoding by decode()
    decode()
        Decodes the UDP header

class DNS
    Decodes Layer 7 of the packet (DNS)

    parse()
        Stores the remainder of the packet in a string for decoding by decode()
    decode()
        Decodes the DNS header

class DHCP
    Decodes Layer 7 of the packet (DHCP)

    parse()
        Stores the remainder of the packet in a string for decoding by decode()
    decode()
        Decodes the DHCP header

Remainder of the code is for printing to command line and saving the output to file.