#Student Names who worked on this project:
 #Noor Nihay 
 #Kaiden Barnes
 #Elijah Depadua 

#importing modules
import socket
import csv
import ipaddress
import re
import sys
import concurrent.futures
from concurrent.futures import ThreadPoolExecutor
import logging

#port scanner with Port Filtering(2 points) and service detection(1), Logging and Reporting(2 points)
def scan_port(target, port, filter_type):
    logging.basicConfig(filename='port_scanner.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect((target, port))


        banner = sock. recv(1024).decode('utf-8').strip()

        result = sock.connect((target, port))
        if (filter_type == "open") or (filter_type == "none"):
            print(f"Port {port} is open")
            print(f"Service Banner: {banner}")
            logging.info(f"Port {port} is open")
            logging.info(f"Service Banner: {banner}")
        else:
            pass

    except ConnectionRefusedError:
        if (filter_type == "closed") or (filter_type == "none"):
            print(f"Port {port} is closed")
            logging.info(f"Port {port} is closed")
        else:
            pass

    except socket.timeout:
        if (filter_type == "timeout") or (filter_type == "none"):
            print(f"Port {port} timed out")
            logging.info(f"Port {port} timed out")
        else:
            pass

    except Exception as e:
        if (filter_type == "error") or (filter_type == "none"):
            print(f"An error occured while scanning port {port}: {e}")
            logging.error(f"An error occurred while scanning port {port}: {e}")
        else:
            pass
    finally:
        sock.close()


        
#Function for initializing user inputs and target, Scan Modes(1 point), custom port lists(1 point), Support for scanning multiple targets(2 points), IP Range Scanning(1 point)
def target_initialization():

    start_port = int(input("Enter the starting port(if custom scan): "))
    end_port = int(input("Enter the ending port(if custom scan): "))
    scan_type = input("Enter a scan type(type 'thorough' for a thorough scan of all ports, 'quick' for a quick scan of common ports, 'custom' for a custom scan from inputted start port to end port, or 'custom_port_list' for a scan of a list of custom ports): ")
    filter_type = input("Enter a port filter type('open' for open ports, 'closed' for closed ports, 'timeout' for timed out ports, 'error' for ports with errors, and 'none' for no filter ): ")

    ip_question = input("would you like to scan a range of addresses? (Y/N): ")

    if ip_question == 'N':
        ip = input("please enter target ip or hostname:  ")
        main(ip, start_port, end_port, scan_type, filter_type)

    elif ip_question == 'Y':
        start_ip = input("please enter start ip of range: ")
        end_ip = input("please enter end ip of range: ")
        ip_range = ipaddress.IPv4Network(f"{start_ip}-{end_ip}", strict=False)
        ip_network = ipaddress.IPv4Network(ip_range)
        #Multiple concurrent targets (scans each target in the range with the main function concurrently)
        with concurrent.futures.ThreadPoolExecutor() as executor:
            for ip in ip_network:
                main(ip, start_port, end_port, scan_type, filter_type)
    else:
        print("please enter a valid input.")



#Main function     
def main(ip, start_port, end_port, scan_type, filter_type):
    
    target = ip
    
    def validate(target, start_port, end_port):
        #Port Range Validation(1 point)
        def in_range(port):
            return (0 < port < 65536)


        #IP Validation
        def valid_ip(ip):
            try:       
                ipaddress.IPv4Address(ip)
                return True
            except ipaddress.AddressValueError:
                return False

        #Hostname Validation
        def valid_hostname(hostname):
            pattern = re.compile(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')
            return bool(pattern.match(hostname))

        #use validate functions together
        if ((valid_hostname(target) == True) or (valid_ip(target) == True)) & ((in_range(start_port) == True) & (in_range (end_port) == True)):
            pass
        else: #exit code if inputs are not valid
            print("Please enter a valid input.")
            sys.exit
    
    #call validate function to validate inputs
    validate(target, start_port, end_port)
    
    #Thorough Scan Function    
    def thorough_scan(target, filter_type):
        for port in range(0, 65536):
            scan_port(target, port, filter_type)
        
    #Custom Scan Function   
    def custom_scan(target, start_port, end_port, filter_type):
        for port in range(start_port, end_port + 1):
            scan_port(target, port, filter_type)
    
    #Quick Scan function (Common ports)     
    def quick_scan(target, filter_type):
        COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 587, 3389]
        for port in COMMON_PORTS:
            scan_port(target, port, filter_type)

    #custom port scan function
    def custom_port_scan(target, filter_type, port_list):
        for port in port_list:
            scan_port(target, port, filter_type)
  

    #scan types
    if scan_type == "thorough": 
        thorough_scan (target, filter_type)
        
    elif scan_type == "quick":
        quick_scan (target, filter_type)
            
    elif scan_type == "custom":
        custom_scan (target, start_port, end_port, filter_type)
            
    elif scan_type == "custom_port_list":
        port_str = input("Please Enter a list of ports seperated by commas: ")
        port_split = port_str.split(',')
        port_list = [int(port) for port in port_split]
        custom_port_scan (target, filter_type, port_list)
        

        
        
    
    
    
def export_to_csv(results, filename):
    with open(filename, 'w', newline='') as csvfile:
        csv_writer = csv.writer(csvfile)
        csv_writer.writerow(['Port', 'Status'])
        for result in results:
            if result:  # Added this condition to check if result is not None
                port, status = re.match(r'Port (\d+) (.+)', result).groups()
                csv_writer.writerow([port, status])
                print(result)  # Print the result while writing to CSV


if __name__ == "__main__":
    results = target_initialization()
    #Output Customization(1 point)
    outputQuestion = input("Would you like to export this file to csv?")
    if outputQuestion == 'Y':
        export_to_csv(results, "output.csv")
        print("Scan results exported to output.csv.")
    else:
        pass

    
