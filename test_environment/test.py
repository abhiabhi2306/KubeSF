import subprocess
import time
import yaml

def run_kubectl(command):
    try:
        subprocess.run(command, shell=True, check=True)
    except subprocess.CalledProcessError as e:
        print(f"Error running kubectl command: {e}")
        exit(1)

def sleep(tm):
    time.sleep(tm)

def create_namespaces(namespace_prefix, num_namespaces):
    for i in range(1, num_namespaces + 1):
        namespace_name = f"{namespace_prefix}-{i}"
        create_ns_command = f"kubectl create ns {namespace_name}"
        run_kubectl(create_ns_command)
        sleep(2)

def create_service_accounts(sa_prefix, num_service_accounts, namespace_list):
    for namespace in namespace_list:
        for i in range(1, num_service_accounts + 1):
            sa_name = f"{sa_prefix}-{i}-sa"
            create_sa_command = f"kubectl create sa {sa_name} -n {namespace}"
            run_kubectl(create_sa_command)

def create_roles(role_prefix, num_roles, namespace_list):
    for i in range(1, num_roles + 1):
        role_name = f"{role_prefix}-{i}"
        for namespace in namespace_list:
            create_role_command = f"kubectl create role {role_name} --verb=* --resource=* -n {namespace}"
            run_kubectl(create_role_command)

def create_role_bindings(rb_prefix, num_role_bindings, role_list, sa_list, namespace_list):
    if not isinstance(namespace_list, list):
        raise ValueError("namespace_list should be a list of namespaces")

    num_namespaces = len(namespace_list)

    if num_namespaces == 0:
        raise ValueError("namespace_list should not be empty")

    for i in range(1, num_role_bindings + 1):
        rb_name = f"{rb_prefix}-{i}"
        role_name = role_list[i % len(role_list)]
        namespace_name = namespace_list[i % num_namespaces]
        sa_name = sa_list[i % len(sa_list)]
        sa_name = f"{namespace_name}:{sa_name}"
        create_rb_command = f"kubectl create rolebinding {rb_name} --role {role_name} --serviceaccount={sa_name} -n {namespace_name}"
        run_kubectl(create_rb_command)

def create_pods_from_yaml(namespace_prefix, num_namespaces, yaml_file, sa_prefix, num_service_accounts, num_pods_per_namespace):
    sa_list = [f"{sa_prefix}-{i}-sa" for i in range(1, num_service_accounts + 1)]

    for i in range(1, num_namespaces + 1):
        namespace_name = f"{namespace_prefix}-{i}"
        check_namespace_command = f"kubectl get ns {namespace_name} --output=jsonpath={{.metadata.name}}"
        try:
            subprocess.run(check_namespace_command, shell=True, check=True)
        except subprocess.CalledProcessError:
            create_namespace_command = f"kubectl create ns {namespace_name}"
            run_kubectl(create_namespace_command)

        for j in range(1, num_pods_per_namespace + 1):
            pod_name = f"{namespace_prefix}-{i}-pod-{j}"
            sa_name = sa_list[(i - 1) % num_service_accounts]
            with open(yaml_file, 'r') as f:
                yaml_data = yaml.safe_load(f)
                yaml_data['metadata']['name'] = pod_name
                yaml_data['metadata']['namespace'] = namespace_name
                yaml_data['spec']['serviceAccountName'] = sa_name
            with open("temp.yaml", "w") as f:
                yaml.dump(yaml_data, f)
            create_pod_command = f"kubectl create -f temp.yaml"
            run_kubectl(create_pod_command)

namespace_prefix = "demo"
num_namespaces = 5
num_pods_per_namespace = 5
sa_prefix = "demo"
num_service_accounts = 2
role_prefix = "demo-role"
num_roles = 2
rb_prefix = "demo-rolebinding"
num_role_bindings = 2

create_namespaces(namespace_prefix, num_namespaces)

namespace_list = [f"{namespace_prefix}-{i}" for i in range(1, num_namespaces + 1)]

create_service_accounts(sa_prefix, num_service_accounts, namespace_list)

demo_yaml_file = "demo.yaml"

create_roles(role_prefix, num_roles, namespace_list)

sa_list = [f"{sa_prefix}-{i}-sa" for i in range(1, num_service_accounts + 1)]

role_list = [f"{role_prefix}-{i}" for i in range(1, num_roles + 1)]

create_role_bindings(rb_prefix, num_role_bindings, role_list, sa_list, namespace_list)

create_pods_from_yaml(namespace_prefix, num_namespaces, demo_yaml_file, sa_prefix, num_service_accounts, num_pods_per_namespace)

print("Kubernetes environment created successfully.")
