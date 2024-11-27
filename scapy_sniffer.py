import json
from datetime import datetime
from scapy.all import sniff, IP, TCP, UDP, ICMP

# Define the JSON file for logging
LOG_File = "packet_log.json"

def log_packet(packet_data):
    """Append packet data to a JSON file."""
    try:
        # Open the file in append+read mode or create it if it doesn't exist
        with open(LOG_File, 'a') as log_file:
            json.dump(packet_data, log_file)
            log_file.write("\n") # Ensure each entry is on a new line for readability
    except Exception as e:
        print(f"Error logging packet: {e}")


def packet_callback(packet):
    """Process packets and log them."""
    packet_data = {}
    try:
        # Add a timestamp
        packet_data["timestamp"] = datetime.now().isoformat()
        
        if IP in packet:
            ip_layer = packet[IP]
            packet_data["source_ip"] = ip_layer.src
            packet_data["destination_ip"] = ip_layer.dst
        
            if TCP in packet:
                tcp_layer = [TCP]
                packet_data["protocol"] = "TCP"
                packet_data["source_port"] = tcp_layer.sport
                packet_data["destination_port"] = tcp_layer.dport
                
            elif UDP in packet:
                udp_layer = packet[UDP]
                packet_data["protocol"] = "UDP"
                packet_data["source_port"] = udp_layer.dport
                
            elif ICMP in packet:
                icmp_layer = packet[ICMP]
                packet_data["protocol"] = "ICMP"
                packet_data["icmp_type"] = icmp_layer.type 
                packet_data["icmp_code"] = icmp_layer.code 
            else:
                packet_data["protocol"] = "Other"
            
            # Print to the console for real-time monitoring
            print(json.dumps(packet_data, indent=4))
        
            # Log the packet data to a JSON file
            log_packet(packet_data)
        
        else:
            print("Non-IP Packet")
    except Exception as e:
        print(f"Error processing packet: {e}")
              
def main():
    print("Starting Scapy packet sniffer...")
    sniff(prn=packet_callback, store=False)
    
if __name__=='__main__':
    main()
            