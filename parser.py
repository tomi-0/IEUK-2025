from collections import Counter
from datetime import datetime

def count_ip():

    suspicious_ip = []

    # Initialize a dictionary to hold IP address counts
    ip_counts = {}

    with open("sample-log.log", 'r') as file:  

        # Process each line in the file
        for line in file:
            ip_address = line.split()[0]  # Assuming the first part of the line is the IP address

            if ip_address in ip_counts:
                ip_counts[ip_address] += 1
            else:
                ip_counts[ip_address] = 1

    for ip_count in ip_counts.items():
        if ip_count[1] > 50:  # Only print IPs that appear more than 50 times
            #print(f"IP Address: {ip_count[0]:20}  Count: {ip_count[1]}")
            suspicious_ip.append(ip_count[0])

    return suspicious_ip


def test_user_Agent():
    suspicious_ip = []
    suspicious_agents = ["curl", "python", "Go-http-client", "Java", "Wget", "bot", "scraper"]

    with open("sample-log.log", 'r') as file:  

        for line in file:
            user_agent = line.split()[11] 
            ip_address = line.split()[0] 

            for agent in suspicious_agents:
                if agent in user_agent:
                    suspicious_ip.append(ip_address)

    return suspicious_ip


def test_fast_repeats():

    # set of suspicious IP's to avoid duplicates
    suspicious_ip = set()
    with open("sample-log.log", 'r') as file:  

        second_counter = Counter() # Creates a sort of dictionary for counting

        for line in file:
            date_time = line.split()[4]
            ip_address = line.split()[0]

            # Extracts the time part assuming it's always in the same format
            date_time = date_time.strip('[')
            time_part = date_time[11:19]

            # Will count how mnay requests made by an IP per second
            # Count (IP, second)
            key = (ip_address, time_part)
            second_counter[key] += 1

            # Adds IPs making more than 10 requests in the same second
            if second_counter[key] > 10:
                suspicious_ip.add(ip_address)

    return list(suspicious_ip)


def main():
    block_list = []

    # These tests can be used in combination ro automatically find
    # potential bots to be blacklisted

    ip_high_vol = count_ip()
    ip_user_agent = test_user_Agent()
    ip_fast_repeat = test_fast_repeats()

    for ip in ip_high_vol:
        if ip in ip_user_agent:
            block_list.append(ip)
        if ip in ip_fast_repeat:
            block_list.append(ip)

    block_list = tuple(block_list)
    
    print("🚫 Block list:")
    for ip in block_list:
        print(ip)

    with open("blocklist.txt", 'w') as file:
        for ip in block_list:
            file.write(ip + "\n")

if __name__ == "__main__":
    main()