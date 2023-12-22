from easysnmp import Session, EasySNMPTimeoutError
import datetime
import struct
from collections import defaultdict
import time
import warnings


class EPON:
    def __init__(self, olt_ip, community_string,):
        self.olt_ip = olt_ip
        self.community_string = community_string

        self.session = Session(hostname=self.olt_ip, community=self.community_string, version=2)

    def ont_status_code(self, code):
        status_mapping = {
            '0': "authenticated",
            '2': "deregistered",
            '4': "lost",
            '5': "auto_configured",
        }
        return status_mapping.get(code, "unknown")

    def ont_dereg_reason_code(self, code):
        status_mapping = {
            "0": "unknown",
            "2": "normal",
            "3": "mpcp-down",
            "4": "oam-down",
            "5": "firmware-download",
            "6": "illegal-mac",
            "7": "admin-down",
            "8": "wire-down",
            "9": "power-off"
        }
        return status_mapping.get(code)
    
    def convert_lastderegtime(self, byte_string):
        if isinstance(byte_string, str):
            byte_values = [ord(char) for char in byte_string]
            byte_string = bytes(byte_values)

        if len(byte_string) >= 7:
            year = struct.unpack('>H', byte_string[0:2])[0]
            month = byte_string[2]
            day = byte_string[3]
            hour = byte_string[4]
            minute = byte_string[5]
            second = byte_string[6]

            dt = datetime.datetime(year, month, day, hour, minute, second)
            
            return dt.strftime('%Y-%m-%d %H:%M:%S')




    def find_index_branch(self, branch_name, all_ports):
        for variable in all_ports:
            if variable.value == branch_name:
                return variable.oid.split('.')[-1]

    def check_wire_down_onts(self):
        oid_ont = "1.3.6.1.4.1.3320.101.9.1.1.1" #.1.3.6.1.4.1.3320.101.11.1.1.2.8
        oid_all_ports = '1.3.6.1.2.1.2.2.1.2.' # .1.3.6.1.2.1.17.1.4.1.2
        oid_ont_mac = '1.3.6.1.4.1.3320.101.10.1.1.3.' # .1.3.6.1.4.1.3320.152.1.1.3.12.1.112.165.106.1.93.
        oid_ont_status = '1.3.6.1.4.1.3320.101.10.1.1.26.' #.1.3.6.1.4.1.3320.101.11.1.1.6.8.
        oid_ont_lastderegreason = 'iso.3.6.1.4.1.3320.101.11.1.1.11.'
        oid_ont_lastderegtime = '1.3.6.1.4.1.3320.101.11.1.1.10'


        #.1.3.6.1.2.1.17.1.4.1.2 - ifindex
        #.1.3.6.1.2.1.2.2.1.2 - oid_all_ports
        #.1.3.6.1.2.1.2.2.1.8 - ont_status



        all_onts = self.session.walk(oid_ont)
        all_ports = self.session.walk(oid_all_ports)

        ont_info = {}
        onts_on_branch = defaultdict(list)

        for ont in all_onts:
            ont_value = ont.value

            port_name = self.session.get(oid_all_ports + ont_value).value
            ont_mac_hex = self.session.get(oid_ont_mac + ont_value).value
            ont_status = self.session.get(oid_ont_status + ont_value).value

            ont_mac = ':'.join(['{:02x}'.format(ord(c)) for c in ont_mac_hex])

            branch, onu_number = port_name.split(':')

            branch_index = self.find_index_branch(branch, all_ports)

            if branch not in onts_on_branch:
                onts_on_branch[branch] = []

            if ont_status == '2':
                hex_parts = ont_mac.split(':')
                ont_dec_mac = '.'.join(str(int(part, 16)) for part in hex_parts)

                ont_lastderegreason = self.session.get(oid_ont_lastderegreason + '.' + branch_index + '.' + ont_dec_mac).value
                ont_lastderegtime_str = self.convert_lastderegtime(self.session.get(oid_ont_lastderegtime + '.' + branch_index + '.' + ont_dec_mac).value)

                onts_on_branch[branch].append({
                    'branch': branch_index,
                    'ont_number': onu_number,
                    'ont_port': ont_value,
                    'ont_mac': ont_mac,
                    'ont_status': self.ont_status_code(ont_status),
                    'ont_lastderegreason': self.ont_dereg_reason_code(ont_lastderegreason),
                    'ont_lastderegtime': ont_lastderegtime_str
                })

        #print(onts_on_branch)

        for branch, onu_list in onts_on_branch.items():
            wire_down_onu_list = [onu for onu in onu_list if onu['ont_lastderegreason'] == 'wire-down']
            power_off_onu_count = sum(1 for onu in onu_list if onu['ont_lastderegreason'] == 'power-off')

            if len(wire_down_onu_list) >= 2 and power_off_onu_count == 0:
                registration_times = [datetime.datetime.strptime(onu['ont_lastderegtime'], '%Y-%m-%d %H:%M:%S') for onu in wire_down_onu_list]

                time_threshold = datetime.timedelta(seconds=3)
                registration_times.sort()

                i = 0
                while i < len(registration_times) - 1:
                    time_diff = registration_times[i + 1] - registration_times[i]
                    if time_diff <= time_threshold:
                        same_time_onus = [
                            onu for onu in wire_down_onu_list if datetime.datetime.strptime(onu['ont_lastderegtime'], '%Y-%m-%d %H:%M:%S') == registration_times[i]
                        ]

                        print(f"розреєстровані ону//")
                        print(f"{branch.split('/')[1].strip()} гілка// {len(same_time_onus)} ону//")
                        print(f"час {registration_times[i].strftime('%H:%M:%S')} //\n")

                        # Замість while змінив на простий for, щоб краще керувати ітераціями
                        for j in range(i, len(registration_times) - 1):
                            if registration_times[j + 1] - registration_times[j] > time_threshold:
                                break
                        i = j + 1
                    else:
                        i += 1

file_path = 'ips.txt'

not_work_olt = ["GP3600", "P3310B"] #олти для яких розробляється програмне рішення


while True:
    with open(file_path, 'r') as file:
        for line in file:
            olt_ip = line.strip()  
            if not olt_ip:
                continue

            community_string = "public"

            try:
                session = Session(hostname=olt_ip, community=community_string, version=2)
                oid_olt_info = '1.3.6.1.2.1.1.1.0.'
                olt_info = session.get(oid_olt_info)

                for olt in not_work_olt:

                    if olt in olt_info.value: 
                        print("Program does not work for this switch model!")
                    else:
                        print("OLT-" + olt_ip)
                        olt_manager = EPON(olt_ip=olt_ip, community_string=community_string)
                        olt_manager.check_wire_down_onts()
            except EasySNMPTimeoutError:
                print(f"Connection timeout for OLT {olt_ip}. Skipping this device.")
                print(" An error occurred! \n Check:\n 1) Internet connection.\n 2) Firewall or security software\n 3) The SNMP service is not available\n")

    time.sleep(3)
