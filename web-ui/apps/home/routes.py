# -*- encoding: utf-8 -*-
"""
Copyright (c) 2019 - present AppSeed.us
"""

from apps.home import blueprint
from flask import render_template, request
from flask_login import login_required,current_user
import os
from datetime import datetime
from jinja2 import TemplateNotFound
import json
import sys
sys.path.append("/Users/ajith.prabhum/crab/KubePWN-main")
from sast import parse_pod_yaml,determine_resource_type_from_generate_name
from networks import check_network_policies
import yaml
import re
from apps.home.misc import *
import subprocess

def contains_word(verb_list, words):
    #print(f"Checking verb list: {verb_list}")
    for word in words:
        if word in verb_list:
            #print(f"Found word: {word}")
            return True
    for sublist in verb_list:
        if isinstance(sublist, list) and contains_word(sublist, words):
            return True
    return False

def remove_escape_sequences(text):
    escape_sequences = [
        r'\\e\[0;31m', r'\\e\[91;1m', r'\\e\[1;32m', r'\\e\[0;37m',
        r'\\e\[0;36m', r'\\e\[0m', r'\\e\[1;37m', r'\\e\[0;36m',
        r'\\e\[1;34m', r'\\e\[1;93m', r'\\e\[0;93m'
    ]
    pattern = '|'.join(escape_sequences)
    cleaned_text = re.sub(pattern, '', text)
    return cleaned_text



def convert_resource_quota_data_to_html_table(raw_data):
    lines = raw_data.strip().split("\n")
    table_html = '<table class="table">'
    table_html += '<thead><tr><th>Resource</th><th>Used</th><th>Hard</th></tr></thead>'
    table_html += '<tbody>'

    in_resource_data = False

    for line in lines:
        if line.startswith("Resource") and not in_resource_data:
            in_resource_data = True
            continue
        elif line.strip() == "":
            in_resource_data = False
            continue
        
        if in_resource_data:
            columns = line.split()
            if len(columns) == 3:
                resource = columns[0]
                used = columns[1]
                hard = columns[2]
                # Exclude rows where resource is "Resource", "Used", or "Hard"
                if resource not in ["Resource", "Used", "Hard","--------","---"]:
                    table_html += f'<tr><td>{resource}</td><td>{used}</td><td>{hard}</td></tr>'

    table_html += '</tbody></table>'
    return table_html



def parse_input_data(input_data):
    lines = input_data.strip().split("\n")
    parsed_data = []

    for line in lines:
        # Split the line into name, pod_selector, and age using space as the delimiter
        name, pod_selector, age = line.split()

        # Check if the line contains unwanted words and skip it if it does
        if name.upper() == "NAME" or pod_selector.upper() == "POD-SELECTOR" or age.upper() == "AGE":
            continue

        # Create a dictionary with keys 'name', 'pod_selector', and 'age' and append it to parsed_data list
        parsed_data.append({'name': name, 'pod_selector': pod_selector, 'age': age})

    # Return the list of dictionaries containing parsed data
    return parsed_data



def parse_input_data2(input_data):
    lines = input_data.strip().split("\n")
    parsed_data = []

    for line in lines:
        name, priv, caps, selinux, runasuser, fs_group, sup_group, readonly_rootfs, volumes = line.split()

        # Check if any field has a specific value, exclude the line if it does
        if any(value in ['NAME', 'PRIV', 'CAPS', 'SELINUX', 'RUNASUSER', 'FSGROUP', 'SUPGROUP', 'READONLYROOTFS', 'VOLUMES']
               for value in [name, priv, caps, selinux, runasuser, fs_group, sup_group, readonly_rootfs, volumes]):
            continue  # Skip this line and move to the next iteration of the loop

        # If none of the fields have the specific values, add the parsed data to the list
        parsed_data.append({
            'name': name,
            'priv': priv,
            'caps': caps,
            'selinux': selinux,
            'runasuser': runasuser,
            'fs_group': fs_group,
            'sup_group': sup_group,
            'readonly_rootfs': readonly_rootfs,
            'volumes': volumes
        })

    return parsed_data


def parse_input_data3(input_data):
    exclusion_list = ['NAME', 'PRIV', 'CAPS', 'SELINUX', 'RUNASUSER', 'FSGROUP', 'SUPGROUP', 'READONLYROOTFS', 'VOLUMES']
    lines = input_data.strip().split("\n")
    parsed_data = []

    for line in lines:
        name, priv, caps, selinux, runasuser, fs_group, sup_group, readonly_rootfs, volumes = line.split()

        # Check if any word in the exclusion list is in the values, if so, skip this line
        if any(excluded_word in (name, priv, caps, selinux, runasuser, fs_group, sup_group, readonly_rootfs, volumes) for excluded_word in exclusion_list):
            continue

        parsed_data.append({
            'name': name,
            'priv': priv,
            'caps': caps,
            'selinux': selinux,
            'runasuser': runasuser,
            'fs_group': fs_group,
            'sup_group': sup_group,
            'readonly_rootfs': readonly_rootfs,
            'volumes': volumes
        })

    return parsed_data

@blueprint.route('/index')
@login_required
def index():

    return render_template('home/index.html', segment='index')


@blueprint.route('/<template>')
@login_required
def route_template(template):

    try:

        if not template.endswith('.html'):
            template += '.html'

        # Detect the current page
        segment = get_segment(request)

        # Serve the file (if exists) from app/templates/home/FILE.html
        return render_template("home/" + template, segment=segment)

    except TemplateNotFound:
        return render_template('home/page-404.html'), 404

    except:
        return render_template('home/page-500.html'), 500


# Helper - Extract current page name from request
def get_segment(request):

    try:

        segment = request.path.split('/')[-1]

        if segment == '':
            segment = 'index'

        return segment

    except:
        return None

@blueprint.route('/audit_results')
def audit_results():
    folder_path = '../audit_results'
    unique_file_names = set()  
    file_info = []
    for file_name in os.listdir(folder_path):
        if file_name.endswith('.txt'):
            file_path = os.path.join(folder_path, file_name)
            with open(file_path, 'r') as file:
                file_content = file.read()
            file_name_parts = file_name.split('_')
            display_name = file_name_parts[0] if len(file_name_parts) > 1 else file_name
            scan_status = 'SCAN FAILED' if len(file_content) < 5 else 'Scan Completed'
            if display_name not in unique_file_names: 
                unique_file_names.add(display_name)  
                creation_time = os.path.getctime(file_path)
                formatted_time = datetime.fromtimestamp(creation_time).strftime('%Y-%m-%d %H:%M:%S')
                file_info.append({'name': display_name, 'creation_time': formatted_time, 'status': scan_status})
    folder_path1 = '../namespace_scans'
    folder_path3 = '../runtimeanalysis'
    try:
        file_count1 = len(unique_file_names)
        file_count2 = len([f for f in os.listdir(folder_path) if os.path.isfile(os.path.join(folder_path, f))]);
        file_count3 = len([f for f in os.listdir(folder_path3) if os.path.isfile(os.path.join(folder_path3, f))]);
    except:
        file_count1 = 0
        file_count2 = 0
        file_count3 = 0

    return render_template('/home/audit_results.html', file_info=file_info,file_count1=file_count1,file_count2=file_count2,file_count3=file_count3)


@blueprint.route('/audit_pods')
def audit_pods():
    folder_path = '../audit_results'
    namespace_param = request.args.get('namespace')

    if namespace_param:
        matching_pods = []
        for file_name in os.listdir(folder_path):
            if file_name.endswith('.txt') and namespace_param in file_name:
                pod_name = file_name.split('_')[1].split('.')[0]
                matching_pods.append(pod_name)

        namespace_scan_file_path = f'../namespace_scans/{namespace_param}.json'
        namespace_scan_data = {}
        if os.path.exists(namespace_scan_file_path):
            with open(namespace_scan_file_path, 'r') as json_file:
                namespace_scan_data = json.load(json_file)
                print(namespace_scan_data['ResourceQuotas'])
                try:
                    rc_data = convert_resource_quota_data_to_html_table(namespace_scan_data['ResourceQuotas'])
                except:
                    rc_data = "NA"
                try: 
                    network_config = parse_input_data(namespace_scan_data['NetworkPolicies'])
                except:
                    network_config = "No Network Policies found"
                try:
                    pod_security_policy = parse_input_data2(namespace_scan_data['PSPs'])
                except:
                    pod_security_policy = "No PSPs found"
                try:
                    scc = parse_input_data3(namespace_scan_data['SCCs'])
                except:
                    scc = "No SCCs found"
            word1 = "compute-resources"
            word2 = "object-counts"
            word3 = "Resource Limits"
            pattern1 = re.compile(rf'\b{re.escape(word1)}\b', re.IGNORECASE)
            pattern2 = re.compile(rf'\b{re.escape(word2)}\b', re.IGNORECASE)
            pattern3 = re.compile(rf'\b{re.escape(word3)}\b', re.IGNORECASE)

            rcQuota_check = False
            oc_check = False 
            rlimit_check = False

            if re.search(pattern1, namespace_scan_data['ResourceQuotas']):
                rcQuota_check = True
            if re.search(pattern2, namespace_scan_data['ResourceQuotas']):
                oc_check = True
            if re.search(pattern3, namespace_scan_data['ResourceQuotas']):
                rlimit_check = True
    
        else:
            rc_data = "No resource quota.\n\nNo LimitRange resource."
            network_config = "No Network Policies found"
            pod_security_policy = "No PSPs found"
            scc = "No SCCs found"
            namespace_scan_data = None
            rcQuota_check = False
            oc_check = False 
            rlimit_check = False
       
        if len(rc_data)<112:
            rc_data = "NA"


        if matching_pods:
            print(rc_data)

            try:
                ingress, egress, pselector, nselector,ingress_ports, egress_ports, pod_selector, namespace_selector_labels = check_network_policies(namespace_param)
                netsuccess = True
            except Exception as e:
                print("Network Policies not found")
                ingress = None
                egress = None
                pselector = None
                nselector = None
                ingress_ports = None
                egress_ports = None
                pod_selector = None
                namespace_selector_labels = None
                netsuccess = None
                print(e)
                print(netsuccess)

            return render_template('/home/tables_pod.html', pods=matching_pods, namespace=namespace_param, file_content=None, namespace_scan_data=namespace_scan_data,rc_data=rc_data,network_config=network_config,pod_security_policy=pod_security_policy,scc=scc,rcQuota_check=rcQuota_check,oc_check=oc_check,rlimit_check=rlimit_check,ingress=ingress,egress=egress,pselector=pselector,nselector=nselector,ingress_ports=ingress_ports,egress_ports=egress_ports,pod_selector=pod_selector,namespace_selector_labels=namespace_selector_labels,netsuccess=netsuccess)
        else:
            return render_template('/home/error_page.html', error_message=f"No pods could be found for the provided namespace name '{namespace_param}'.")
    else:
        return render_template('/home/error_page.html', error_message="No 'namespace' parameter provided in the query string.")


def parse_exploit_text(input_text):
    exploits_pattern = r'Possible Exploits:(.*?)$'
    exploits_match = re.search(exploits_pattern, input_text, re.DOTALL)

    if exploits_match:
        exploits_text = exploits_match.group(1).strip()
        exploits_list = exploits_text.split('[+] ')
        
        exploits_data = []
        for exploit_text in exploits_list[1:]:  # Skip the empty first element
            exploit_lines = exploit_text.strip().split('\n')
            title = exploit_lines[0].strip()
            details = exploit_lines[1].strip().replace('Details: ', '')
            exposure = exploit_lines[2].strip().replace('Exposure: ', '')
            tags = exploit_lines[3].strip().replace('Tags: ', '')
            download_url = exploit_lines[4].strip().replace('Download URL: ', '')
            comments = exploit_lines[5].strip().replace('Comments: ', '')
            
            exploit_entry = {
                "Title": title,
                "Details": details,
                "Exposure": exposure,
                "Tags": tags,
                "Download_URL": download_url,
                "Comments": comments
            }
            exploit_entry['Exposure'] = exploit_entry['Exposure'].replace('Details:', '')
            exploits_data.append(exploit_entry)
            #print(cveno)
        
        return exploits_data
    else:
        return None

def clean_line(line):
    # Remove unwanted characters and whitespaces from the line
    cleaned_line = line.strip().replace('\x1b', '')  # Removes escape sequences
    return cleaned_line

def extract_kernel_info(file_path):
    start_line = "Kernel Version Analysis:"
    end_line = "Flag:"
    found_start = False
    extracted_lines = []

    with open(file_path, 'r', encoding='utf-8', errors='ignore') as file:
        for line in file:
            cleaned_line = clean_line(line)
            if found_start and end_line in cleaned_line:
                break
            if found_start:
                extracted_lines.append(cleaned_line)
            if start_line in cleaned_line:
                found_start = True

    return "\n".join(extracted_lines)

@blueprint.route('/view_pod')
def view_pod():
    folder_path = '../runtimeanalysis'
    namespace_param = request.args.get('namespace')
    pod_param = request.args.get('pod')

    if namespace_param and pod_param:
        matching_containers = []
        file_content = ""
        resource_type = ""
        for file_name in os.listdir(folder_path):
            if namespace_param in file_name and pod_param in file_name: 
                container_name = file_name.split('_')[-1].split('.')[0]
                print(file_name)
                if container_name != "analysis":
                    matching_containers.append(container_name)
                file_name = file_name 
                f1 = parse_pod_yaml(f"../podresults/{pod_param}_{namespace_param}.yaml")
                f1 = yaml.dump(f1, default_flow_style=False)
                resource_type = determine_resource_type_from_generate_name(f1)
                file_path = os.path.join(folder_path, file_name)
                file_content = extract_kernel_info(file_path)
                file_content = remove_escape_sequences(file_content)
                file_content2 = open(file_path, 'r').read()
                #print(file_content)
                kernel_version_pattern = r'Kernel version:\s+(\S+)'
                architecture_pattern = r'Architecture:\s+(\S+)'
                kernel_version_match = re.search(kernel_version_pattern, file_content)
                architecture_match = re.search(architecture_pattern, file_content)
                exploit_data = parse_exploit_text(file_content)
                cve_pattern = r'\[CVE-\d{4}-\d{4,7}\]'
                cve_matches = re.findall(cve_pattern, file_content)
                num_cves = len(cve_matches)

                if kernel_version_match:
                    kernel_version = kernel_version_match.group(1)
                else:
                    kernel_version = None

                if architecture_match:
                    architecture = architecture_match.group(1)
                else:
                    architecture = None

                if kernel_version is None:
                   kernel_version_pattern = r'SysAnalysis:\s+\w+\s+\S+\s+(\d+(\.\d+)+-\w+)'
                   kernel_version_match = re.search(kernel_version_pattern, file_content2)
                   if kernel_version_match is not None:
                       kernel_version = kernel_version_match.group(1)
                   #print("results:"+kernel_version_match)
                if architecture is None:
                   architecture_pattern = r'\b(?:x86[_-]?64|amd64|i\d{3,4}|arm(?:64|v(?:7|8)))\b'
                   architecture_match = re.search(architecture_pattern, file_content2)

                   if architecture_match is not None:
                       architecture = architecture_match.group(0)

        if matching_containers:
            print(matching_containers)
            return render_template('/home/view_pod.html', matching_containers=matching_containers, namespace=namespace_param, file_content=file_content, resource_type=resource_type, pod_param=pod_param, kernel_version=kernel_version, architecture=architecture,exploit_data=exploit_data,num_cves=num_cves)
        else:
            return render_template('/home/error_page.html', error_message=f"No pod info could be found for '{namespace_param}' and pod name '{pod_param}'.")
    else:
        return render_template('/home/error_page.html', error_message="No 'namespace' and/or 'pod' parameter provided in the query string.")

@blueprint.route('/result')
def show_results():
    folder_path = '../audit_results'
    folder_path2 = '../runtimeanalysis'
    namespace_param = request.args.get('namespace')
    pod_param = request.args.get('pod')
    container_param = request.args.get('container')
    #print(namespace_param)
    #print(pod_param)
    #print(container_param)
    file_content = ""
    resource_type = ""
    bin_cap = None
    formatted_time = ""
    warning_count = 0
    pass_count = 0
    uidn = 0

    if namespace_param and pod_param and container_param:
        file_name = f"{namespace_param}_{pod_param}_analysis.txt"
        file_name_2 = f"{namespace_param}_{pod_param}_analysis.txt_{container_param}"
        #print(file_name)

        if os.path.isfile(os.path.join(folder_path, file_name)):
            file_path = os.path.join(folder_path, file_name)
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as file:
                file_content = file.read()
                creation_time = os.path.getctime(file_path)
                formatted_time = datetime.fromtimestamp(creation_time).strftime('%Y-%m-%d %H:%M:%S')
                warning_count = file_content.count('Warning')
                pass_count = file_content.count('PASS')
                non_default_cron_jobs = None

                if os.path.isfile(os.path.join(folder_path2, file_name_2)):
                    file_path2 = os.path.join(folder_path2, file_name_2)
                    with open(file_path2, 'r', encoding='utf-8', errors='ignore') as file2:
                        file_content2 = file2.read()
                        creation_time2 = os.path.getctime(file_path2)
                        formatted_time2 = datetime.fromtimestamp(creation_time2).strftime('%Y-%m-%d %H:%M:%S')
                        uid_line, uidn, gid, groups = uid(file_content2)
                        
                        if uidn is not None:
                            uidn = int(uidn)
                        if gid is not None:
                            gid = int(gid)

                        pattern = r'CapPrm:\s+([a-fA-F\d]+)'
                        match = re.search(pattern, file_content2)
                        dangerous_capabilities_found2 = None
                        dangerous_capabilities_found = ['cap_sys_admin', 'cap_dac_override', 'cap_dac_read_search',
                               'cap_net_admin', 'cap_sys_ptrace', 'cap_sys_module',
                               'cap_sys_rawio', 'cap_mknod']
                        cap_msg = None 
                        dyes = False

                        if match:
                            capprm_value = match.group(1)
                            capabilities_list = None
                            print("CapPrm value:", capprm_value)
                            try:
                                ot = subprocess.run(["capsh", "--decode=" + capprm_value], stdout=subprocess.PIPE)
                                decoded_output = ot.stdout.decode('utf-8')
                                #print(decoded_output)

                                pattern = r"cap_\w+"
                                capabilities_list = re.findall(pattern, decoded_output)
                                #print(capabilities_list)
                                cap_msg = None
                                dangerous_capabilities_found2 = [cap for cap in capabilities_list if cap in dangerous_capabilities_found]
                                print(dangerous_capabilities_found2)

                                if dangerous_capabilities_found2:
                                    cap_msg = "Following dangerous and risky capabilities are found:"
                                    dyes=True
                                    #print(cap_msg)
                                    print(dangerous_capabilities_found2)
                                else:
                                    dyes=False
                                    dangerous_capabilities_found2 = None
                                    cap_msg = "No Dangerous Capabilities were found."
                            except Exception as e:
                                print("Error:", e)

        
                        else:
                            capprm_value = "CAPPRM could not be determined"
                            cap_msg = None 
                            dangerous_capabilities_found2 = None
                            dyes = None
                            print("Pattern not found.")
                            capabilities_list = None

                        bin_cap = binaries_with_cap(file_content2)

                        pattern = r'Checking processes running using ps binary\n(.*?)(?=\n\n|\n$)'

                        match = re.search(pattern, file_content2, re.DOTALL)

                        result_ps_lines = []
                        if match:
                            extracted_lines = match.group(1)
                            lines = [line.strip() for line in extracted_lines.split('\n') if line.strip()]
                            #print('\n'.join(lines))
                            result_ps_lines.append(lines)
                            res2 = []
                            #print("ps lines:"+result_ps_lines)
                        else:
                            print("Pattern not found.")
                            result_ps_lines = None
                        #print("PS DATA:"+result_ps_lines)
                        pattern = r'Below results are for files which have suid bit set\n(.*?)(?=\n-e)'

                        match = re.search(pattern, file_content2, re.DOTALL)

                        suid_binaries = []
                        if match:
                            extracted_lines = match.group(1)
                            for line in extracted_lines.splitlines():
                                if line.strip():
                                    suid_binaries.append(line.strip())
                        else:
                            print("Pattern not found.")
                            suid_binaries = None
                        filtered_words = ['gpasswd', 'chsh', 'newgrp', 'mount', 'chfn', 'umount', 'passwd', 'su', 'ping', 'ping6', 'sudo', 'crontab', 'at']
                        if suid_binaries is not None:
                            unusual_suid_binaries = [binary for binary in suid_binaries if not any(word in binary for word in filtered_words)]
                        else: 
                            unusual_suid_binaries = None 
                        if suid_binaries is not None:
                            unusual_suid_binaries = None 


                        pattern = r'Below are the files which have SGID bit set\n(.*?)(?=\nChecking ulimit)'
                        matches = re.search(pattern, file_content2, re.DOTALL)

                        sgid_binaries = None
                        if matches:
                            sgid_binaries = matches.group(1).strip().split('\n')
                        else:
                            print("Pattern not found. - sgid binaries")
                            sgid_binaries = None
                        print(sgid_binaries)
                        filtered_words = ['unix_chkpwd', 'pam_extrausers_chkpwd', 'chage', 'expiry', 'wall', 'fonts', 'mail', 'local']
                        if sgid_binaries is not None:
                            unusual_sgid_binaries = [binary for binary in sgid_binaries if not any(word in binary for word in filtered_words)]
                        else: 
                            unusual_sgid_binaries = None 
                        if sgid_binaries is not None:
                            unusual_sgid_binaries = None 
                        print(suid_binaries)
                        print(sgid_binaries)
                        pattern = r'Checking ulimit\s+.*\n((?:.*\n)*)'
                        regex = re.compile(pattern)
                        match = regex.search(file_content2)
                        ulimit_unlimited = False
                        ulimit_value = ""
                        if match:
                             ulimit_section = match.group(1)
                             if 'unlimited' in ulimit_section:
                                 ulimit_unlimited = True
                                 print("Ulimit unlimited")
                        else:
                            print("Pattern not found - ulimit")
                        pattern = r'Warning: Pod logs contain sensitive data: (.*?)(?=\s)'

                        match = re.search(pattern, file_content2)

                        if match:
                            sensitive_data = match.group(1).strip()
                            if sensitive_data == "...":
                                sensitive_data = None
                        else:
                            print("Pattern not found.")
                            sensitive_data = None

                        print(sensitive_data)
                        pattern = r'Flag:(.*?)\nFlag2:(.*?)\n'

                        match = re.search(pattern, file_content2, re.DOTALL)

                        if match:
                            Flag1 = match.group(1).strip()
                            Flag2 = match.group(2).strip()
                        else:
                            print("Pattern not found.")
                            Flag1 = None
                            Flag2 = None 
                        if Flag1 == "Nonewprivs flag is not set.":
                            Flag1 = None
                        if Flag2 == "Seccomp flag is not set.":
                            Flag2 = None

                        pattern = r'Docker Sockets:\s+(.*?)\n\nReadable files belonging to root and not world-readable:'


                        match = re.search(pattern, file_content2)

                        if match:
                            docker_sockets_content = match.group(1).strip()
                            print("Docker Sockets Content:")
                            print(docker_sockets_content)
                        else:
                            print("Pattern not found.")
                            docker_sockets_content = None
                        pattern = r'Readable files belonging to root and not world-readable:\s+(.*?)\n\n'

                        match = re.search(pattern, file_content2, re.DOTALL)

                        readable_root_files = []
                        if match:
                            extracted_lines = match.group(1)
                            for line in extracted_lines.splitlines():
                                if line.strip():
                                    readable_root_files.append(line.strip())
                        else:
                            print("Pattern not found.")
                            print(readable_root_files)
                            readable_root_files = None

                        pattern = r'Interesting writable files by group \(world-writable but not executable by others\):\s+(.*?)\n\n'

                        match = re.search(pattern, file_content2, re.DOTALL)

                        interesting_writable_gfiles = []
                        if match:
                            extracted_lines = match.group(1)
                            for line in extracted_lines.splitlines():
                               if line.strip():
                                   interesting_writable_gfiles.append(line.strip())
                        else:
                            print("Pattern not found.")
                            print(interesting_writable_gfiles)
                            interesting_writable_gfiles=None
                        pattern = r'Users with shell access:\s+(.*?)\n\nSensitive Environment Variables:\s+'

                        match = re.search(pattern, file_content2, re.DOTALL)
                        if match:
                            users_with_shell_access_content = match.group(1).strip()
                            users_with_shell_access_content = users_with_shell_access_content.split()
                            print("Users with Shell Access:")
                            print(users_with_shell_access_content)
                        else:
                            print("Pattern not found.")
                            users_with_shell_access_content = None
                        pattern = r'Sensitive Environment Variables:\s+(.*?)\n\n'

                        match = re.search(pattern, file_content2, re.DOTALL)

                        if match:
                            sensitive_env_variables_content = match.group(1).strip()
                            print("Sensitive Environment Variables:")
                            print(sensitive_env_variables_content)
                        else:
                            print("Pattern not found.")
                            sensitive_env_variables_content = None
                        pattern = r'Cron Jobs:(.*?)Writable'

                        match = re.search(pattern, file_content2, re.DOTALL)

                        if match:
                            cron_jobs_content = match.group(1).strip()
                            #print("Cron Jobs Content:")
                            print(cron_jobs_content)
                            non_default_cron_jobs = re.findall(r'^\S+.*$', cron_jobs_content, re.MULTILINE)
                            exclude_words = ['e2scrub_all', 'apt-compat', 'dpkg', 'root','/etc/cron.d:', 'total 12', '/etc/cron.daily:', 'total 16', 'SHELL=/bin/sh','PATH:','PATH']

                            filtered_cron_jobs = [line for line in non_default_cron_jobs if not any(word in line for word in exclude_words)]
                            non_default_cron_jobs = filtered_cron_jobs
                            cron_lines = re.findall(r'(\S+ \S+ \S+ \S+ \S+ \S+).*?(/[\w/.-]+)', cron_jobs_content, re.DOTALL)
                            cron_dict = [{"Schedule": schedule, "Command": command.strip()} for schedule, command in cron_lines]

                            if len(non_default_cron_jobs) < 1:
                                non_default_cron_jobs = None



                        else:
                            print("Pattern not found.")
                            cron_jobs_content=None
                            cron_dict=None
                        
                        cap_trad = cap_trad_way(file_content2)
                        print("cap trad:")
                        print(cap_trad)

                        pattern = r'Writable /etc/passwd Status:\s+(.*?)$'

                        match = re.search(pattern, file_content2, re.MULTILINE)

                        if match:
                            writable_passwd_status = match.group(1).strip()
                            print("Writable /etc/passwd Status:")
                            print(writable_passwd_status)
                        else:
                            print("Pattern not found.")
                            writable_passwd_status = None

                        pattern = r'Config:\s+(.*?)$'

                        match = re.search(pattern, file_content2, re.MULTILINE)

                        if match:
                            config_protection = match.group(1).strip()
                            print("PROTECTION CONFIG STATUS:")
                            print(config_protection)
                        else:
                            print("Pattern not found.")
                            config_protection = None
                        pattern = r'Proto Local Address\s+Foreign Address\s+PID/Program name\n(.*?)(?:\n\n|\n$)'

                        match = re.search(pattern, file_content2, re.DOTALL | re.MULTILINE)

                        if match:
                            network_info_content = match.group(1).strip()
                            print("Network Information:")
                            print(network_info_content)
                        else:
                            print("Pattern not found.")
                            network_info_content = None
                        
                        regex_pattern = r'Results for runtime SA:(.*?)(?:\n\s*\n|\Z)'

                        matches = re.search(regex_pattern, file_content2, re.DOTALL)

                        if matches:
                            extracted_content = matches.group(1).strip()
                            print(extracted_content)
                        else:
                            extracted_content = "No match found."
                            print("No match found.")

                        lines = extracted_content.strip().split('\n')
                        headers = lines[0].split()

                        output_list = []
                        
                        try:
                             KEY_SHORTNAMES = {
                                            headers[0]: "Resources",
                                            headers[1]: "Non-ResourceURLs",
                                            headers[2]: "ResourceNames",
                                            headers[3]: "Verbs",
                                            headers[4]: "rtype"
                                          }
                        except:
                            print("No match found.")
                            KEY_SHORTNAMES = None

                        for line in lines[1:]:
                            values = line.split()
                            resource_name = values[2]
                            verbs = values[3:]
    
                            if resource_name.startswith('[') and resource_name.endswith(']'):
                               resource_names = []
                               verbs = [resource_name] + verbs
                            else:
                               resource_names = [resource_name]
                            
                            cat1_keywords = ["pods", "deployments", "replicasets", "cronjobs", "jobs", "daemonset", "statefulsets", "secrets", "pods/exec","*"]
                            cat2_keywords = ["roles", "rolebindings", "serviceaccount", "psp", "scc", "clusterroles", "clusterrolebindings","*"]


                            key_words = values[0].split('.')
                            print("debug:"+str(key_words))
                            #print(values[0])

                            if any(keyword in key_words for keyword in cat1_keywords):
                               rtype = "cat1"
                            elif any(keyword in key_words for keyword in cat2_keywords):
                               rtype = "cat2"
                            else:
                               rtype = None  # Default value if no match is found
                            print(rtype)
                            item_dict = {
                                     KEY_SHORTNAMES[headers[0]]: values[0],
                                     KEY_SHORTNAMES[headers[1]]: values[1],
                                     KEY_SHORTNAMES[headers[2]]: resource_names,
                                     KEY_SHORTNAMES[headers[3]]: verbs,
                                     KEY_SHORTNAMES[headers[4]]: rtype
                                       }
                            output_list.append(item_dict)
                        
                        f1 = parse_pod_yaml(f"../podresults/{pod_param}_{namespace_param}.yaml")
                        f1 = yaml.dump(f1, default_flow_style=False)
                        resource_type = determine_resource_type_from_generate_name(f1)
                        print(resource_type)
                        print(output_list)
                        runtimefail = False
                        try:
                            ingress, egress, pselector, nselector,ingress_ports, egress_ports, pod_selector, namespace_selector_labels = check_network_policies(namespace_param)
                            netsuccess = True
                        except Exception as e:
                            print("Network Policies not found")
                            ingress = None
                            egress = None
                            pselector = None
                            nselector = None
                            ingress_ports = None
                            egress_ports = None
                            pod_selector = None
                            namespace_selector_labels = None
                            netsuccess = None
                            print(e)
                        print(netsuccess)
                        capsh_out, caps_out = capsh_check(file_content2)
                        if capsh_out is not None:
                            dangerous_capabilities_found1 = ['cap_sys_admin', 'cap_dac_override', 'cap_dac_read_search',
                               'cap_net_admin', 'cap_sys_ptrace', 'cap_sys_module',
                               'cap_sys_rawio', 'cap_mknod']
                            dang_caps_present = [x for x in dangerous_capabilities_found1 if x in caps_out]
                            if not len(dang_caps_present)>=1:
                                dang_caps_present = None
                        else:
                            dang_caps_present = None
                        
                        try:
                            int_check = check_internet_status(file_content2)
                        except:
                            int_check = None

                        try:
                            dock_sock = extract_docker_sockets(file_content2)
                        except:
                            dock_sock = None
                        


                        #print(cap_msg)
                        return render_template('/home/results.html', dock_sock=dock_sock,int_check=int_check,netsuccess=netsuccess,namespace=namespace_param, file_content=file_content,
                                           resource_type=resource_type, pod_param=pod_param,
                                           container_param=container_param, formatted_time=formatted_time,
                                           warning_count=warning_count, pass_count=pass_count, uid_line=uid_line,
                                           uidn=uidn, gid=gid, groups=groups, cap_msg=cap_msg,dangerous_capabilities_found=dangerous_capabilities_found2,capabilities_list=capabilities_list, dyes=dyes,bin_cap=bin_cap, result_ps_lines=result_ps_lines, formatted_time2=formatted_time2,suid_binaries=suid_binaries,sgid_binaries=sgid_binaries,ulimit_unlimited=ulimit_unlimited,ulimit_value=ulimit_value,sensitive_data=sensitive_data,Flag1=Flag1,Flag2=Flag2,docker_sockets_content=docker_sockets_content,readable_root_files=readable_root_files,interesting_writable_gfiles=interesting_writable_gfiles,users_with_shell_access_content=users_with_shell_access_content,sensitive_env_variables_content=sensitive_env_variables_content,cron_jobs_content=cron_jobs_content,writable_passwd_status=writable_passwd_status,config_protection=config_protection,network_info_content=network_info_content,unusual_suid_binaries=unusual_suid_binaries,unusual_sgid_binaries=unusual_sgid_binaries,non_default_cron_jobs=non_default_cron_jobs,output_list=output_list,ingress=ingress, egress=egress, pselector=pselector, nselector=nselector,ingress_ports=ingress_ports, egress_ports=egress_ports, pod_selector=pod_selector, namespace_selector_labels=namespace_selector_labels,cron_dict=cron_dict,contains_word=contains_word,capsh_out=capsh_out,caps_out=caps_out,dang_caps_present=dang_caps_present,cap_trad=cap_trad)
                else:   
                    runtimefail = True
                    return render_template('/home/results.html',namespace=namespace_param, file_content=file_content,
                                           resource_type=resource_type, pod_param=pod_param,
                                           container_param=container_param, formatted_time=formatted_time,
                                           warning_count=warning_count, pass_count=pass_count,runtimefail=runtimefail)
    else:
        return render_template('/home/error_page.html',
                                           error_message=f"No container info could be found for '{namespace_param}' and pod name '{pod_param}'.")
    
@blueprint.route('/profile')
def profile():
    return render_template('/home/profile.html',current_user=current_user)
