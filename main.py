import argparse
import subprocess
import sys
import os
import concurrent.futures
import yaml
import re
import glob
import json
import tempfile
import shutil
import time
import logging
import builtins
from sast import parse_pod_yaml, check_security_context
#from unique import process_pod_names

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
input_directory = 'podresults'
output_directory = 'audit_results'
binaries_path = 'binaries'
runtime_analysis_directory = 'runtimeanalysis'
os.makedirs("./runtimeanalysis", exist_ok=True)
os.makedirs("./namespace_scans", exist_ok=True)
os.makedirs("./podresults", exist_ok=True)
all_mode = False
file_urls = [
    "https://github.com/agent-killjoy/Binaries/raw/main/capsh",
    "https://github.com/agent-killjoy/Binaries/raw/main/curl",
    "https://github.com/agent-killjoy/Binaries/raw/main/netstat",
    "https://github.com/agent-killjoy/Binaries/raw/main/ps",
    "https://github.com/agent-killjoy/Binaries/raw/main/tar",
    "https://github.com/agent-killjoy/Binaries/raw/main/wget"
]


def write_to_file(filename,content):
    with open(filename, 'a') as f:
        f.write(content+"\n")



def analyze_container_runtime(pod_name, namespace_name, result_file_path):
    try:
        get_containers_command = f"kubectl get pod {pod_name} -n {namespace_name} -o jsonpath='{{.spec.containers[*].name}}'"
        containers = subprocess.check_output(get_containers_command, shell=True, executable="/bin/bash")
        containers = containers.decode('utf-8').split()
        #print(containers)
        if containers is None:
            #print(f"Unable to find containers for pod {pod_name} in namespace {namespace_name}")
            logging.debug(f"Unable to find containers for pod {pod_name} in namespace {namespace_name}")
            return

        for container in containers:
            print ("Starting Runtime analysis for containers in pod " + pod_name + "\n")
            kubectl_command = f"kubectl exec {pod_name} -c {container} -n {namespace_name} -- sh -c 'echo -e \"Checking uid\\n\"; id; (capsh 2>/dev/null || /tmp/binaries/capsh 2>/dev/null); code=$?; if [ \"$code\" -eq 0 ];then echo -e \"\\nChecking capabilities using capsh binary\\n\"; (capsh --print 2>/dev/null || /tmp/binaries/capsh --print 2>/dev/null); else echo -e \"\\nChecking capsh permissions in traditional way\\n\"; cat /proc/self/status | grep -i cap ;fi; echo -e \"\\nChecking if any binary inside the container has any capabilities\\n\"; getcap -r / 2>/dev/null; (ps 2>/dev/null || /tmp/binaries/ps 2>/dev/null); code=$?; if [ \"$code\" -eq 0 ];then echo -e \"\\nChecking processes running using ps binary\\n\"; (ps -ef 2>/dev/null || /tmp/binaries/ps -ef 2>/dev/null); else echo -e \"\\nChecking processess running in traditional way\\n\"; ls -l /proc/*/exe ;fi; echo -e \"\\nBelow results are for files which have suid bit set\\n\"; find / -perm /4000 2>/dev/null; echo -e \"\\nBelow are the files which have SGID bit set\\n\"; find / -perm /2000 2>/dev/null; echo -e \"\\nChecking ulimit \\n\"; ulimit;' > {result_file_path}_{container} 2>&1"
            subprocess.run(kubectl_command, shell=True, check=True, executable="/bin/bash")
            result_f = f"{result_file_path}_{container}"
            risky = check_risky_permissions(namespace_name, pod_name, result_f,container)
            run_linux_exploit_suggester(namespace_name, pod_name, result_f,container)
            check_extra_security(namespace_name, pod_name, result_f,container)
            securityconfig = check_security_config(namespace_name, pod_name, result_f,container)
            check_internet_connectivity(pod_name,namespace_name, result_f,container)
            check_network_connections(namespace_name, pod_name, result_f,container)
            

        print("Runtime analysis of containers in pod "+ pod_name +" is completed successfully \n")
    except subprocess.CalledProcessError as e:
        print("Runtime Analysis was skipped due to error, use verbose mode to see the error. \n")
        logging.debug(f"Error occurred: {e}")


def run_linux_exploit_suggester(namespace, pod_name,result_filename,container_name=None):
    try:
        if container_name is None:
            uname_output = subprocess.check_output(['kubectl', 'exec', '-n', namespace, pod_name, '--', 'uname', '-a']).decode().strip()
            write_to_file(result_filename,"SysAnalysis: "+uname_output)

        else:
            uname_output = subprocess.check_output(['kubectl', 'exec', '-n', namespace, pod_name, '-c', container_name, '--', 'uname', '-a']).decode().strip()
            write_to_file(result_filename,"SysAnalysis: "+uname_output)

        exploit_suggester_output = subprocess.check_output(['./utilities/expsuggest.sh', '--uname', uname_output]).decode()

        logging.debug("Kernel Version Analysis:")
        logging.debug(exploit_suggester_output)
        write_to_file(result_filename,"Kernel Version Analysis: "+exploit_suggester_output)

    except subprocess.CalledProcessError as e:
        logging.debug(f'Error running commands: {e}')
    except Exception as e:
        logging.debug(f'An error occurred: {e}')


def check_extra_security(namespace, pod_name, result_filename,container_name=None):
    SENSITIVE_ENV_VARS = ['PASSWORD', 'SECRET', 'API_KEY', 'TOKEN', 'KEY'] 
    try:
        if container_name is None:
            nonewprivs_flag = subprocess.check_output(f'kubectl exec -n {namespace} {pod_name} -- cat /proc/self/status | grep -i nonewprivs', shell=True)
        else:
            nonewprivs_flag = subprocess.check_output(f'kubectl exec -n {namespace} {pod_name} -c {container_name} -- cat /proc/self/status | grep -i nonewprivs', shell=True)
        if nonewprivs_flag.split()[1] == b'1':
            logging.debug("Nonewprivs flag is set.")
            write_to_file(result_filename,"Flag:Nonewprivs flag is set.")
        else:
            logging.debug("Nonewprivs flag is not set.")
            write_to_file(result_filename,"Flag:Nonewprivs flag is not set.")

        
        if container_name is None:
            seccomp_flag = subprocess.check_output(f'kubectl exec -n {namespace} {pod_name} -- cat /proc/self/status | grep -i seccomp', shell=True)
        else:
            seccomp_flag = subprocess.check_output(f'kubectl exec -n {namespace} {pod_name} -c {container_name} -- cat /proc/self/status | grep -i seccomp', shell=True)
        if seccomp_flag.split()[1] == b'1':
            logging.debug("Seccomp flag is set.")
            write_to_file(result_filename,"Flag2:Seccomp flag is set.")
        else:
            logging.debug("Seccomp flag is not set.")
            write_to_file(result_filename,"Flag2:Seccomp flag is not set.")

        if container_name is None:
            docker_sockets = subprocess.check_output(f'kubectl exec -n {namespace} {pod_name} -- find / -iname "docker.sock" 2>/dev/null', shell=True)
        else:
            docker_sockets = subprocess.check_output(f'kubectl exec -n {namespace} {pod_name} -c {container_name} -- find / -iname "docker.sock" 2>/dev/null', shell=True)
        logging.debug("Docker Sockets:")
        logging.debug(docker_sockets.decode())
        write_to_file(result_filename,"Docker Sockets:\n"+docker_sockets.decode())


        try:
            if container_name is None:
               readable_files = subprocess.check_output(f'kubectl exec -n {namespace} {pod_name} -- find / -type f -user root -not -perm -004 2>/dev/null | grep -v \'/proc\\|/sys\'', shell=True)
            else:
               readable_files = subprocess.check_output(f'kubectl exec -n {namespace} {pod_name} -c {container_name} -- find / -type f -user root -not -perm -004 2>/dev/null | grep -v \'/proc\\|/sys\'', shell=True)
            logging.debug("Readable files belonging to root and not world-readable:")
            logging.debug(readable_files.decode())
            write_to_file(result_filename,"Readable files belonging to root and not world-readable:\n\n"+readable_files.decode())
        except subprocess.CalledProcessError as e:
            logging.debug(f"Error occurred: {e}")
        
        try:
            if container_name is None:
                interesting_writable_files = subprocess.check_output(f'kubectl exec -n {namespace} {pod_name} -- find / -type f -perm -002 -not -perm -1000 2>/dev/null | grep -v \'/proc\\|/sys\'', shell=True)
            else:
                interesting_writable_files = subprocess.check_output(f'kubectl exec -n {namespace} {pod_name} -c {container_name} -- find / -type f -perm -002 -not -perm -1000 2>/dev/null | grep -v \'/proc\\|/sys\'', shell=True)
            logging.debug("Interesting writable files by group (world-writable but not executable by others):")
            logging.debug(interesting_writable_files.decode())
            write_to_file(result_filename,"Interesting writable files by group (world-writable but not executable by others):\n\n"+interesting_writable_files.decode())
        except subprocess.CalledProcessError as e:
            logging.debug(f"Error occurred: {e}")
        
        try:
            if container_name is None:
                shell_users = subprocess.check_output(f'kubectl exec -n {namespace} {pod_name} -- cat /etc/passwd 2>/dev/null', shell=True)
            else:
                shell_users = subprocess.check_output(f'kubectl exec -n {namespace} {pod_name} -c {container_name} -- cat /etc/passwd 2>/dev/null', shell=True)
            decoded_output = shell_users.decode().split('\n')

            valid_users = []
            for line in decoded_output:
                if re.match(r'^(?!#)[^:]*:.*:.*:.*:.*:(/bin/bash|/bin/sh|/bin/zsh)', line):
                    valid_users.append(line)

            if valid_users:
                logging.debug("Users with shell access:")
                logging.debug('\n'.join(valid_users))
                write_to_file(result_filename,"Users with shell access: "+"\n"+'\n'.join(valid_users)+"\n")
            else:
                logging.debug("No users with shell access found.")
                write_to_file(result_filename,"No users with shell access found.")

        except subprocess.CalledProcessError as e:
            logging.debug(f"Error occurred: {e}")

        if container_name is None:
            sensitive_mounts = subprocess.check_output(f'kubectl exec -n {namespace} {pod_name} -- mount | grep -E "/$|/root|/var|/var/run/docker.sock|/var/run/crio/crio.sock|/var/run/cri-dockerd.sock|/var/lib/kubelet|/var/lib/kubelet/pki|/var/lib/docker/overlay2|/etc|/etc/kubernetes|/etc/kubernetes/manifests|/home/admin"', shell=True)
        else:
            sensitive_mounts = subprocess.check_output(f'kubectl exec -n {namespace} {pod_name} -c {container_name} -- mount | grep -E "/$|/root|/var|/var/run/docker.sock|/var/run/crio/crio.sock|/var/run/cri-dockerd.sock|/var/lib/kubelet|/var/lib/kubelet/pki|/var/lib/docker/overlay2|/etc|/etc/kubernetes|/etc/kubernetes/manifests|/home/admin"', shell=True)

        if container_name is None:
            env_vars = subprocess.check_output(f'kubectl exec -n {namespace} {pod_name} -- env', shell=True)
        else:
            env_vars = subprocess.check_output(f'kubectl exec -n {namespace} {pod_name} -c {container_name} -- env', shell=True)
        env_vars = env_vars.decode().splitlines()
        sensitive_env_vars = []
        for var in env_vars:
            for sensitive_var in SENSITIVE_ENV_VARS:
                if re.search(fr'\b{re.escape(sensitive_var)}\b', var, re.IGNORECASE):
                    sensitive_env_vars.append(var)
        logging.debug("Sensitive Environment Variables:")
        logging.debug('\n'.join(sensitive_env_vars))
        write_to_file(result_filename,"Sensitive Environment Variables: "+"\n"+'\n'.join(sensitive_env_vars)+"\n")
        
        if container_name is None:
            cron_info = subprocess.check_output(f'kubectl exec -n {namespace} {pod_name} -- ls -alR /etc/cron* /var/spool/cron/crontabs /var/spool/anacron 2>/dev/null; cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/* /etc/incron.d/* /var/spool/incron/* 2>/dev/null | tr -d "\r" | grep -v "^#"', shell=True)
        else:
            cron_info = subprocess.check_output(f'kubectl exec -n {namespace} {pod_name} -c {container_name} -- ls -alR /etc/cron* /var/spool/cron/crontabs /var/spool/anacron 2>/dev/null; cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/* /etc/incron.d/* /var/spool/incron/* 2>/dev/null | tr -d "\r" | grep -v "^#"', shell=True)
        logging.debug("Cron Jobs:")
        logging.debug(cron_info.decode())
        write_to_file(result_filename,"Cron Jobs: "+cron_info.decode())

        if container_name is None:
            etc_passwd_status = subprocess.check_output(f'kubectl exec -n {namespace} {pod_name} -- [ -w /etc/passwd ] && echo "Writable by current user" || echo "Not Writable by current user"', shell=True)
        else:
            etc_passwd_status = subprocess.check_output(f'kubectl exec -n {namespace} {pod_name} -c {container_name} -- [ -w /etc/passwd ] && echo "Writable by current user" || echo "Not Writable by current user"', shell=True)
        logging.debug("Writable /etc/passwd Status:")
        logging.debug(etc_passwd_status.decode())
        write_to_file(result_filename,"Writable /etc/passwd Status: "+etc_passwd_status.decode())

    except subprocess.CalledProcessError as e:
        logging.debug(f"Error: {e}")

def check_network_connections(namespace, pod_name,result_file_path,container_name=None):
    try:
        if container_name==None:
            kubectl_command = (
                f"kubectl exec -n {namespace} {pod_name} -- "
                "sh -c 'echo \"Proto Local Address     Foreign Address PID/Program name\"; "
                "for protocol in tcp udp; do file=\"/proc/net/$protocol\"; "
                "while IFS=\" \" read -r sl local_address rem_address st rest uid timeout inode; do "
                "[ \"$sl\" = \"sl\" ] || [ \"$st\" != \"0A\" ] && continue; "
                "local_decoded=$(printf \"%%d.%%d.%%d.%%d:%%d\" \"$((0x$((local_address%%:)) & 0xFF))\" "
                "\"$(((0x$((local_address%%:)) >> 8) & 0xFF))\" \"$(((0x$((local_address%%:)) >> 16) & 0xFF))\" "
                "\"$(((0x$((local_address%%:)) >> 24) & 0xFF))\" \"$((0x$((local_address%%:)) #:))\"); "
                "rem_decoded=$(printf \"%%d.%%d.%%d.%%d:%%d\" \"$((0x$((rem_address%%:)) & 0xFF))\" "
                "\"$(((0x$((rem_address%%:)) >> 8) & 0xFF))\" \"$(((0x$((rem_address%%:)) >> 16) & 0xFF))\" "
                "\"$(((0x$((rem_address%%:)) >> 24) & 0xFF))\" \"$((0x$((rem_address%%:)) #:))\"); "
                "pid_program=$(find /proc -maxdepth 2 -name \"fd\" -type d -exec ls -l {} \\; 2>/dev/null | "
                "grep \"socket:\\[$inode\\]\" | awk -F/ \"{{print \$3}}\" | uniq); "
                "if [ -n \"$pid_program\" ]; then pid=$(echo \"$pid_program\" | cut -d\" \" -f1); "
                "program=$(ps -p \"$pid\" -o comm=); pid_program=\"$pid/$program\"; else pid_program=\"N/A\"; fi; "
                "echo \"$protocol    $local_decoded $rem_decoded $pid_program\"; done < \"$file\"; done'"
                )
        else:
            kubectl_command = (
                f"kubectl exec -n {namespace} {pod_name} -c {container_name} -- "
                "sh -c 'echo \"Proto Local Address     Foreign Address PID/Program name\"; "
                "for protocol in tcp udp; do file=\"/proc/net/$protocol\"; "
                "while IFS=\" \" read -r sl local_address rem_address st rest uid timeout inode; do "
                "[ \"$sl\" = \"sl\" ] || [ \"$st\" != \"0A\" ] && continue; "
                "local_decoded=$(printf \"%%d.%%d.%%d.%%d:%%d\" \"$((0x$((local_address%%:)) & 0xFF))\" "
                "\"$(((0x$((local_address%%:)) >> 8) & 0xFF))\" \"$(((0x$((local_address%%:)) >> 16) & 0xFF))\" "
                "\"$(((0x$((local_address%%:)) >> 24) & 0xFF))\" \"$((0x$((local_address%%:)) #:))\"); "
                "rem_decoded=$(printf \"%%d.%%d.%%d.%%d:%%d\" \"$((0x$((rem_address%%:)) & 0xFF))\" "
                "\"$(((0x$((rem_address%%:)) >> 8) & 0xFF))\" \"$(((0x$((rem_address%%:)) >> 16) & 0xFF))\" "
                "\"$(((0x$((rem_address%%:)) >> 24) & 0xFF))\" \"$((0x$((rem_address%%:)) #:))\"); "
                "pid_program=$(find /proc -maxdepth 2 -name \"fd\" -type d -exec ls -l {} \\; 2>/dev/null | "
                "grep \"socket:\\[$inode\\]\" | awk -F/ \"{{print \$3}}\" | uniq); "
                "if [ -n \"$pid_program\" ]; then pid=$(echo \"$pid_program\" | cut -d\" \" -f1); "
                "program=$(ps -p \"$pid\" -o comm=); pid_program=\"$pid/$program\"; else pid_program=\"N/A\"; fi; "
                "echo \"$protocol    $local_decoded $rem_decoded $pid_program\"; done < \"$file\"; done'"
                )


        process = subprocess.Popen(kubectl_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        #print(process)
        stdout, stderr = process.communicate()

        if process.returncode == 0:
            output = stdout.decode("utf-8")
            with open(result_file_path, "a") as result_file:
                result_file.write(output + "\n")
            return output.strip()
        else:
            error_message = stderr.decode("utf-8").strip()
            return f"Error: {error_message}"

    except Exception as e:
        return f"An error occurred: {str(e)}"


def analyze_pod_runtime(pod_name, namespace_name, result_file_path): 
    try:
        #kubectl_command = f"kubectl exec {pod_name} -n {namespace_name} -- sh -c 'echo -e \"Checking uid\\n\"; id; if command -v capsh >/dev/null 2>&1; then echo -e \"\\nChecking capabilities using capsh binary\\n\"; capsh --print; else echo -e \"\\nChecking capabilities using the traditional approach\\n\"; cat /proc/self/status | grep -i capprm; fi; echo -e \"\\nChecking if any binary inside the container has any capabilities\\n\"; getcap -r / 2>/dev/null; echo -e \"\\nChecking the processes running inside the container using ps binary\\n\"; if command -v ps >/dev/null 2>&1; then ps -ef; else ls -l /proc/*/exe; fi; echo -e \"\\nBelow results are for files which have suid bit set\\n\"; find / -perm /4000 2>/dev/null; echo -e \"\\nBelow are the files which have SGID bit set\\n\"; find / -perm /2000 2>/dev/null; echo -e \"\\nBelow are the sensitive information that are exposed in environment variables\\n\"; env | egrep -i \"pass|secret|token|key\"; echo -e \"\\nChecking mounted filesystems\\n\"; mount; echo -e \"\\nChecking ulimit \\n\"; ulimit;' > {result_file_path} 2>&1"
        #subprocess.run(kubectl_command, shell=True, check=True, executable="/bin/bash")
        #risky = check_risky_permissions(namespace_name, pod_name)
        #run_linux_exploit_suggester(namespace_name, pod_name)
        #check_extra_security(namespace_name, pod_name)
        #securityconfig = check_security_config(namespace_name, pod_name)
        #check_network_connections(namespace_name, pod_name, result_file_path)

        analyze_container_runtime(pod_name, namespace_name, result_file_path)
        pod_info = pod_name, namespace_name
        remove_binaries_from_pod(pod_info)
        #print("Runtime analysis is done [x]")
    except subprocess.CalledProcessError as e:
        logging.debug(f"Error occurred: {e}")

def get_service_account_from_pod(namespace, pod_name):
    file_name = f"{pod_name}_{namespace}.yaml"
    file_path = os.path.join("podresults", file_name)
    with open(file_path, 'r') as f:
        service_account_tokenname = yaml.safe_load(f)['spec']['serviceAccountName']
        logging.debug(service_account_tokenname)
    try:
         command = f"kubectl auth can-i  --list --namespace {namespace}  --as system:serviceaccount:{namespace}:{service_account_tokenname}"
         #print(command)
         service_account_name = subprocess.check_output(command, shell=True, text=True).strip()
         print(service_account_name)
         return service_account_name
    except: 
        logging.debug("Error getting service account token permissions")
        return None
    

def check_runtime_token(namespace_name, pod_name):
    cache_var = False
    try:
        token_command = f"kubectl exec -n {namespace_name} -it {pod_name} -- cat /var/run/secrets/kubernetes.io/serviceaccount/token"
        token_process = subprocess.run(token_command, shell=True, check=True, capture_output=True, text=True)
        token = token_process.stdout.strip()
        print("Output of token command: " + token)
        kubeconfig_command = f"kubectl config view"
        kubeconfig_process = subprocess.run(kubeconfig_command, shell=True, check=True, capture_output=True, text=True)
        kubeconfig = kubeconfig_process.stdout.strip()
        with open("./utilities/temp_conf.yaml", "w") as f:
            f.write(kubeconfig)
            
        kubeconfig_path = "./utilities/temp_conf.yaml"
        kubeconfig = yaml.safe_load(open(kubeconfig_path))

        if cache_var == False:
            kubeconfig.pop('users', None)
            cache_var = True 
        modified_content = yaml.dump(kubeconfig)

        with open("./utilities/temp_conf.yaml", "w") as f:
            f.write(modified_content)

        auth_command = [
            "kubectl", "auth", "can-i", "--list",
            f"--namespace={namespace_name}",
            f"--token={token}",
            f"--kubeconfig={kubeconfig_path}"
        ]

        auth_process = subprocess.run(auth_command, check=True, capture_output=True, text=True)
        print("auth_process output" + auth_process)

        if auth_process.returncode != 0:
            raise Exception(f"Error checking pods permissions: {auth_process.stderr.strip()}")

        return auth_process.stdout.strip()

    except subprocess.CalledProcessError as e:
        raise Exception(f"Error running subprocess: {e.stderr.strip()}")
    except Exception as e:
        raise Exception(f"Error: {str(e)}")

def check_risky_permissions(namespace, pod_name, result_file_path, container_name=None):
    try:
        service_account_name = get_service_account_from_pod(namespace, pod_name)
        #sa2 = check_runtime_token(namespace, pod_name)
        sa2 = get_service_account_from_pod(namespace, pod_name)
        logging.debug("Results for runtime SA: \n" + sa2)
        write_to_file(result_file_path, "Results for runtime SA: \n" + sa2)
        
        if container_name is None:
            pod_logs_command = f"kubectl logs {pod_name} -n {namespace} | egrep -i 'token:|token=|secret:|secret=|key:|key=|password=|password:' | head -n 100 && echo '...' && kubectl logs {pod_name} -n {namespace} | egrep -i 'token:|token=|secret:|secret=|key:|key=|password=|password:' | tail -n 100"
        else:
            pod_logs_command = f"kubectl logs {pod_name} -n {namespace} -c {container_name} | egrep -i 'token:|token=|secret:|secret=|key:|key=|password=|password:' | head -n 100 && echo '...' && kubectl logs {pod_name} -n {namespace} -c {container_name} | egrep -i 'token:|token=|secret:|secret=|key:|key=|password=|password:' | tail -n 100"
        pod_logs = subprocess.check_output(pod_logs_command, shell=True, text=True)
        if pod_logs:
            write_to_file(result_file_path, "\n Warning: Pod logs contain sensitive data: " + pod_logs)
            logging.debug("Warning: Pod logs contain sensitive data: " + pod_logs)
        else:
            write_to_file(result_file_path, "No sensitive data found in pod logs")
            logging.debug("No sensitive data found in pod logs")

        file_name2 = f"{pod_name}_{namespace}.yaml"
        file_path = os.path.join("podresults", file_name2)
        
        if os.path.exists(f"./namespace_scans/{namespace}.json"):
            os.remove(f"./namespace_scans/{namespace}.json")
        
        output_data = {}  # Dictionary to store the output data

        network_policies_command = f"kubectl get networkpolicies -n {namespace}"
        network_policies = subprocess.check_output(network_policies_command, shell=True, text=True)
        output_data["NetworkPolicies"] = network_policies if network_policies else "No Network Policies found"

        resource_quotas_command = f"kubectl describe namespace {namespace} | grep -vi 'Name\|labeles\|annotations\|status'"
        resource_quotas = subprocess.check_output(resource_quotas_command, shell=True, text=True)
        output_data["ResourceQuotas"] = resource_quotas
        psp_command = "kubectl get psp"
        scc_command = "kubectl get scc"

        try:
            psp_output = subprocess.check_output(psp_command, shell=True, stderr=subprocess.STDOUT, text=True)
            output_data["PSPs"] = psp_output
        except subprocess.CalledProcessError as e:
            output_data["PSPs"] = "No PSPs found"

        try:
            scc_output = subprocess.check_output(scc_command, shell=True, stderr=subprocess.STDOUT, text=True)
            output_data["SCCs"] = scc_output
        except subprocess.CalledProcessError as e:
            output_data["SCCs"] = "No SCCs found"

        write_to_file(f"./namespace_scans/{namespace}.json",json.dumps(output_data, indent=4))
        return json.dumps(output_data, indent=4)
    except Exception as e:
        print("An error occurred:", str(e))
        return None

def check_internet_connectivity(pod_name, namespace_name, result_file_path,containername=None):
    try:
        bash_check_command = f"kubectl exec {pod_name} -n {namespace_name} -- /bin/bash -c 'echo Hello'"
        bash_check_result = subprocess.run(bash_check_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        
        if containername is None:
            if bash_check_result.returncode == 0:
                internet_check_command = f"kubectl exec {pod_name} -n {namespace_name} -- /bin/bash -c '(echo > /dev/tcp/www.google.com/80) &>/dev/null; echo $?'"
            else:
                internet_check_command = f"kubectl exec {pod_name} -n {namespace_name} -- /bin/sh -c 'if openssl s_client -connect www.google.com:443 < /dev/null 2>&1 | grep -q \"CONNECTED\"; then echo 0; else echo 1; fi'"
        else:
            if bash_check_result.returncode == 0:
                internet_check_command = f"kubectl exec {pod_name} -n {namespace_name} -c {containername} -- /bin/bash -c '(echo > /dev/tcp/www.google.com/80) &>/dev/null; echo $?'"
            else:
                internet_check_command = f"kubectl exec {pod_name} -n {namespace_name} -c {containername} -- /bin/sh -c 'if openssl s_client -connect www.google.com:443 < /dev/null 2>&1 | grep -q \"CONNECTED\"; then echo 0; else echo 1; fi'"

        
        internet_check_result = subprocess.run(internet_check_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        #print(internet_check_command)
        #print(internet_check_result)
        #print(internet_check_result.returncode)
        if internet_check_result.returncode == 0:
            logging.debug("Internet is available.")
            with open(result_file_path, 'a') as result_file:
                result_file.write("Internet:Yes\n")

        else:
            logging.debug("No internet connectivity.")
            with open(result_file_path, 'a') as result_file:
                result_file.write("Internet:No\n")

    except Exception as e:
        logging.debug("Error running the internet connectivity check command:", str(e))
        

def check_tool_availability(pod_name, namespace_name, tool):
    try:
        command = f"kubectl exec -n {namespace_name} {pod_name} -- which {tool}"
        subprocess.run(command, shell=True, check=True,stdout=subprocess.PIPE)
        return True
    except subprocess.CalledProcessError:
        return False
  

    except subprocess.CalledProcessError as e:
        print(f"Error running tar check command: {e}")
    except Exception as e:
        logging.debug(f"An error occurred: {e}")


def copy_binaries_to_pod(pod_info, binaries_path):
    pod_name, namespace_name = pod_info
    
    try:
        read_only_check_command = f"kubectl get pod {pod_name} -n {namespace_name} -o=jsonpath='{{.spec.containers[0].securityContext.readOnlyRootFilesystem}}'"
        read_only_check_result = subprocess.run(read_only_check_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if read_only_check_result.stdout.strip() == "true":
            logging.debug(f"[x] Pod {pod_name} in namespace {namespace_name} is read-only. Skipping copying binaries.")
            return False
        else: 
            logging.debug(f"[x] Pod {pod_name} in namespace {namespace_name} is Writeable.")
        if check_tool_availability(pod_name, namespace_name, "tar"):
            logging.debug(f"Tar is present in pod {pod_name} in namespace {namespace_name}. Copying Binaries.")
            copy_command = f"kubectl cp {binaries_path} {namespace_name}/{pod_name}:/tmp/binaries"
            subprocess.run(copy_command, shell=True, check=True)
            logging.debug(f"Successfully copied binaries to {pod_name} in namespace {namespace_name}")
            return True
        else:
            logging.debug(f"Tar is not available in pod {pod_name} in namespace {namespace_name}. Checking for Internet Connectivity.")
            if check_internet_connectivity(pod_name, namespace_name,"./abcd") == "Internet is not available.":
                logging.debug(f"Internet is not available in pod {pod_name} in namespace {namespace_name}. Skipping copying binaries.")
                return False
            else:
                logging.debug(f"Internet is available in pod {pod_name} in namespace {namespace_name}. Downloading Binaries.")
                if check_tool_availability(pod_name, namespace_name, "wget"):
                    for file_url in file_urls:
                        first_part, file_name = file_url.split("/main/")
                        download_command = f"kubectl exec -n {namespace_name} {pod_name} -- sh -c  'mkdir /tmp/binaries; wget -O /tmp/binaries/{file_name} {file_url};chmod +x /tmp/binaries/*'"
                        subprocess.run(download_command, shell=True, check=True)
                        logging.debug(f"Downloaded {file_name} using wget")
                elif check_tool_availability(pod_name, namespace_name, "curl"):
                    for file_url in file_urls:
                        first_part, file_name = file_url.split("/main/")
                        download_command = f"kubectl exec -n {namespace_name} {pod_name} -- sh -c 'curl -o --create-dirs /tmp/binaries/{file_name} {file_url}; chmod +x /tmp/binaries/*"
                        subprocess.run(download_command, shell=True, check=True)
                        logging.debug(f"Downloaded {file_name} using curl")
                else:
                    for file_url in file_urls:
                        first_Part, file_name = file_url.split("/main/")
                        download_command = f"kubectl exec -n {namespace_name} {pod_name} -- python -c 'import requests; response = requests.get(\"{file_url}\"); open(\"/tmp/binaries/{file_name}\", \"wb\").write(response.content)'"
                        subprocess.run(download_command, shell=True, check=True)
                        logging.debug(f"Downloaded {file_name}")
        
                    subprocess.run(download_command, shell=True, check=True)
                    logging.debug(f"Binaries downloaded successfully in pod {pod_name} in namespace {namespace_name}")
    
    except subprocess.CalledProcessError as e:
        logging.debug(f"Error copying binaries to {pod_name} in namespace {namespace_name}: {e}")

def copy_binaries_to_pods(binaries_path):
    try:
        with open('./utilities/temp_resultpods.txt', 'r') as input_file:
            pod_infos = [line.strip().split(':') for line in input_file]
        
        with concurrent.futures.ThreadPoolExecutor() as executor:
            futures = [executor.submit(copy_binaries_to_pod, pod_info, binaries_path) for pod_info in pod_infos]
            concurrent.futures.wait(futures)
    except Exception as e:
        logging.debug(f"Error occurred: {e}")

def remove_binaries_from_pod(pod_info):
    pod_name, namespace_name = pod_info
    try:
        remove_command = f"kubectl exec {pod_name} -n {namespace_name} -- rm -r /tmp/binaries"
        subprocess.run(remove_command, shell=True, check=True)
        logging.debug(f"Successfully removed binaries from {pod_name} in namespace {namespace_name}")
    except subprocess.CalledProcessError as e:
        logging.debug(f"Error removing binaries from {pod_name} in namespace {namespace_name}: {e}")

def remove_binaries_from_pods():
    try:
        with open('temp_resultpods.txt', 'r') as input_file:
            pod_infos = [line.strip().split(':') for line in input_file]

        with concurrent.futures.ThreadPoolExecutor() as executor:
            futures = [executor.submit(remove_binaries_from_pod, pod_info) for pod_info in pod_infos]
            concurrent.futures.wait(futures)
    except Exception as e:
        logging.debug(f"Error occurred: {e}")
    

def get_pod_yaml_files(input_directory):
    yaml_files = []
    for filename in os.listdir(input_directory):
        if filename.endswith('.yaml'):
            yaml_files.append(os.path.join(input_directory, filename))
    return yaml_files


def download_binaries_from_remote_server(pod_name, namespace_name):

    try:
        command = "kubectl exec " + str(pod_name) + " -n " + str(namespace_name) + " -- bash -c 'function __curl() { read -r proto server path <<<\"$(printf '\\''%s'\\'' \"${1//// }\")\"; if [ \"$proto\" != \"http:\" ]; then printf >&2 \"sorry, %s supports only http\\n\" \"${FUNCNAME[0]}\"; return 1; fi; DOC=/${path// }; HOST=${server//:*}; PORT=${server//*:}; [ \"${HOST}\" = \"${PORT}\" ] && PORT=80; exec 3<>/dev/tcp/${HOST}/$PORT; printf '\\''GET %s HTTP/1.0\\r\\nHost: %s\\r\\n\\r\\n'\\'' \"${DOC}\" \"${HOST}\" >&3; (while read -r line; do [ \"$line\" = $'\\''\\r'\\'' ] && break; done && cat) <&3; exec 3>&-; }; __curl http://google.com'" 
        subprocess.run(command, shell=True, check=True)
        logging.debug(f"Successfully downloaded binaries from remote source to {pod_name} in namespace {namespace_name}")
    except subprocess.CalledProcessError as e:
        logging.debug(f"Error downloading binaries from remote source to {pod_name} in namespace {namespace_name}: {e}")
    
def check_security_config(namespace, pod_name, result_f,container_name=None):
    try:
        if container_name==None:
            kubectl_command_output = subprocess.check_output(['kubectl', 'exec', '-it', '-n', namespace, pod_name, '--', 'cat', '/proc/self/attr/current'], stderr=subprocess.STDOUT)
        else:
            kubectl_command_output = subprocess.check_output(['kubectl', 'exec', '-it', '-n', namespace, pod_name, '-c', container_name, '--', 'cat', '/proc/self/attr/current'], stderr=subprocess.STDOUT)
        output_str = kubectl_command_output.decode('utf-8').strip()
        
        if output_str == "unconfined":
            logging.debug("SELinux or AppArmor is not configured.")
            write_to_file(result_f, "Config: SELinux or AppArmor is not configured.\n")
        else:
            logging.debug(f"SELinux or AppArmor is configured.")
            write_to_file(result_f, f"Config: SELinux or AppArmor is configured.\n")
    except subprocess.CalledProcessError as e:
        logging.debug(f"Failed to retrieve security configuration: {e.output.decode('utf-8')}")
        write_to_file(result_f, f"Failed to retrieve security configuration: {e.output.decode('utf-8')}\n")

def run_sast_on_directory(input_directory, output_directory,nslist):
    os.makedirs(output_directory, exist_ok=True)
    yaml_files = get_pod_yaml_files(input_directory)
    logging.debug("The yaml files are :"+str(yaml_files))


    for input_file in yaml_files:
        output_file = os.path.join(output_directory, os.path.basename(input_file) + "_audit.txt")
        f = parse_pod_yaml(input_file)
        print("Starting Static Analysis\n")
        r = check_security_context(f,output_file)
        print("Static Analysis has been completed\n")
        logging.debug(r)
        


def check_kubectl_installed():
    try:
        subprocess.run(["kubectl", "--help"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
        return True
    except subprocess.CalledProcessError:
        return False

def run_on_all_namespaces():
    cmd = "kubectl get namespaces | grep -v 'kube-node\|kube-public\|kube-system'"
    result = subprocess.run(
        cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
    )
    
    if result.returncode != 0:
        print("Error running kubectl get namespaces")
        sys.exit(1)
    else:
        namespace_list = []
        lines = result.stdout.splitlines()
        for line in lines[1:]:
            namespace_name = line.split()[0]
            namespace_list.append(namespace_name)
        
        return namespace_list       

def install_kubectl():
    print("kubectl is not installed. Please install it to continue.")
    sys.exit(1)

def driver_code(args):
    if args.command == "all-namespaces":
        if check_kubectl_installed():
            print("[X] KubePwn has started running on all namespaces.")
            [os.remove(os.path.join('./audit_results', f)) for f in os.listdir('./audit_results')]
            [os.remove(os.path.join('./runtimeanalysis', f)) for f in os.listdir('./runtimeanalysis')]
            [os.remove(os.path.join('./namespace_scans', f)) for f in os.listdir('./namespace_scans')]
            ns = run_on_all_namespaces()
            run_kubectl_get_pods(ns)
            selective_unique_pods('./utilities/temp_resultpods.txt')
        else:
            install_kubectl()
    elif args.command == "list":
        if check_kubectl_installed():
            if args.list:
                filename = args.list
                [os.remove(os.path.join('./audit_results', f)) for f in os.listdir('./audit_results')]
                [os.remove(os.path.join('./runtimeanalysis', f)) for f in os.listdir('./runtimeanalysis')]
                [os.remove(os.path.join('./namespace_scans', f)) for f in os.listdir('./namespace_scans')]
                print(f"Running on list of namespaces specified from file: {filename}")
                ns = get_namespaces_from_file(filename)
                run_kubectl_get_pods(ns)
                selective_unique_pods('./utilities/temp_resultpods.txt')
            else:
                logging.debug("Please provide a filename for the selected namespace operation.")
                sys.exit(1)
    elif args.command == "single":
        args.pod_name = args.pod_name.strip()
        [os.remove(os.path.join('./audit_results', f)) for f in os.listdir('./audit_results')]
        [os.remove(os.path.join('./runtimeanalysis', f)) for f in os.listdir('./runtimeanalysis')]
        [os.remove(os.path.join('./namespace_scans', f)) for f in os.listdir('./namespace_scans')]
        result_file_path = os.path.join("runtimeanalysis", f"{args.namespace}_{args.pod_name}_analysis.txt")
        pod_info = args.pod_name, args.namespace
        copy_binaries_to_pod(pod_info, binaries_path)
        kubectl_command = f"kubectl get pod {args.pod_name} -n {args.namespace} -o yaml"
        try:
            result = subprocess.run(
            kubectl_command,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
            )

            if result.returncode == 0:
               fname = f"{args.pod_name}_{args.namespace}"
               output_path = f"podresults/{fname}.yaml"
               with open(output_path, "w") as output_file:
                    output_file.write(result.stdout)
                    logging.debug(f"Pod YAML saved to {output_path}")
               yml_stat = parse_pod_yaml(output_path)
               analyze_pod_runtime(args.pod_name, args.namespace, result_file_path)
               print("Starting Static Analysis for "+str(args.pod_name)+" in namespace "+str(args.namespace)+ "\n")
               print("debug before sc:")
               check_security_context(yml_stat,"./audit_results"+f"/{args.namespace}_{args.pod_name}_analysis.txt")
               print("debug after sc:")
               print("Static Analysis has been completed for "+str(args.pod_name)+" in namespace "+str(args.namespace) + "\n")
               podinfo = args.pod_name, args.namespace
               remove_binaries_from_pod(podinfo)
               print("[x] KubePWN completed successfully.")
        except Exception as e:
            logging.debug(f"Error running kubectl get pod {args.pod_name} -n {args.namespace} -o yaml: {e}")

def get_namespaces_from_file(file_path):
    try:
        with open(file_path, 'r') as file:
            namespaces = file.read().splitlines()
        return namespaces
    except Exception as e:
        logging.debug(f"Error reading namespaces from file: {e}")
        return []

def run_kubectl_get_pods(namespaces):
    try:
        with open('./utilities/temp_resultpods.txt', 'w') as output_file:
            for namespace in namespaces:
                cmd = f"kubectl get pods -n {namespace} --field-selector=status.phase=Running -o custom-columns=NAME:.metadata.name --no-headers"
                result = subprocess.run(
                    cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
                )
                
                if result.returncode != 0:
                    logging.debug(f"Error running kubectl get pods for namespace {namespace}")
                else:
                    names = [line.strip() for line in result.stdout.split('\n') if line.strip()]
                    for name in names:
                        output_file.write(f"{name}:{namespace}\n")
                    if len(names) > 0:
                        logging.debug(f"Found {len(names)} pods in namespace {namespace}")
    except Exception as e:
        logging.debug(f"Error running kubectl commands: {e}")


def selective_unique_pods(fname):
    unique_combinations = set()
    [os.remove(os.path.join('./audit_results', f)) for f in os.listdir('./audit_results')]
    copy_binaries_to_pods(binaries_path)
    with open(fname) as f:
        content = f.readlines()
        content = [x.strip() for x in content]
    for namespaces in content:
        pod_name, namespace_name = namespaces.split(':')
        if (pod_name, namespace_name) not in unique_combinations:
            unique_combinations.add((pod_name, namespace_name))
            logging.debug(unique_combinations)
            kubectl_command = f"kubectl get pod {pod_name} -n {namespace_name} -o yaml"

            try:
                result = subprocess.run(
                    kubectl_command,
                    shell=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True
                )

                if result.returncode == 0:
                    fname = f"{pod_name}_{namespace_name}"
                    output_path = f"podresults/{fname}.yaml"
                    with open(output_path, "w") as output_file:
                        output_file.write(result.stdout)
                    logging.debug(f"Pod YAML saved to {output_path}")
                    yml_stat = parse_pod_yaml(output_path)
                    print("Starting Static Analysis for "+str(pod_name)+ " in namespace "+str(namespace_name) + "\n")
                    check_security_context(yml_stat,"./audit_results"+f"/{namespace_name}_{pod_name}_analysis.txt")
                    print("Static Analysis has been completed for "+str(pod_name)+" in namespace "+str(namespace_name) + "\n")
                else:
                    print(f"Error running kubectl command: {result.stderr}")
            except Exception as e:
                logging.debug(f"An error occurred: {e}")
            result_file_path = os.path.join("runtimeanalysis", f"{namespace_name}_{pod_name}_analysis.txt")
            copy_binaries_to_pod((pod_name, namespace_name), binaries_path)
            analyze_pod_runtime(pod_name, namespace_name, result_file_path)
    remove_binaries_from_pods()

    print("KubePwn Completed Execution [X]")
    




    
def main():
    parser = argparse.ArgumentParser(description="KubePwn - Kubernetes Security Audit Tool v1 (Beta)")
    parser.add_argument("--all-namespaces", action="store_true", help="Run on all namespaces (format: ./main.py --all-namespaces)")
    parser.add_argument("--list", help="Run on a specific list of namespaces (format: ./main.py --list file.txt)")
    parser.add_argument("--single", nargs=2, metavar=("NAMESPACE", "POD"), help="Run on a single namespace and pod (format: ./main.py --single demo-1 pod-1)")
    parser.add_argument('--verbose', action='store_true', help='enable verbose mode to view the results in CLI/to debug.')

    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    if args.all_namespaces and args.list:
        print("Please choose either --all-namespaces, --list, or --single, not multiple options.")
        sys.exit(1)
    elif args.single and args.list:
        print("Please choose either --all-namespaces, --list, or --single, not multiple options.")
        sys.exit(1)
    elif args.single and args.all_namespaces:
        print("Please choose either --all-namespaces, --list, or --single, not multiple options.")
        sys.exit(1)
    elif args.all_namespaces:
        driver_code(argparse.Namespace(command="all-namespaces"))
        all_mode=True
    elif args.list:
        if args.list:
            driver_code(argparse.Namespace(command="list", list=args.list))
        else:
            print("Please provide a filename for the --list operation.")
            sys.exit(1)
    elif args.single:
        namespace, pod_name = args.single
        driver_code(argparse.Namespace(command="single", namespace=namespace, pod_name=pod_name))
    else:
        print("Please provide either --all-namespaces, --list, or --single flag. Use --help to access the helpmenu.")
        sys.exit(1)


def run_flask_app():
    web_ui_path = os.path.join(os.getcwd(), "web-ui")

    if os.path.exists(web_ui_path):
        try:
            os.chdir(web_ui_path)

            activate_script_path = os.path.join("env", "bin", "activate")
            activate_command = f"source {activate_script_path}"

            flask_run_command = "flask run"

            subprocess.run(activate_command, shell=True, executable="/bin/bash")
            subprocess.run(flask_run_command, shell=True, executable="/bin/bash")

        except Exception as e:
            print(f"Error: {e}")
    else:
        print("Error: 'web-ui' folder not found in the current directory.")

def banner():
   RED = "\33[91m"
   BLUE = "\33[94m"
   GREEN = "\033[32m"
   YELLOW = "\033[93m"
   PURPLE = '\033[0;35m' 
   CYAN = "\033[36m"
   END = "\033[0m"
   banner = f""" {BLUE}
_  __    _         _____      ___  _ 
 | |/ /  _| |__  ___| _ \ \    / / \| |
 | ' < || | '_ \/ -_)  _/\ \/\/ /| .` |
 |_|\_\_,_|_.__/\___|_|   \_/\_/ |_|\_|

{GREEN} Kubernetes Security Audit Tool v1 {CYAN}[Beta] \n {END} """
   print(banner)

if __name__ == "__main__":
    banner()
    main()
    run_flask_app()

