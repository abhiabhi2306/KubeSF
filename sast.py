import yaml
import re

flag = 0


def search_seccomp_profile(data,output_file):
    if isinstance(data, dict):
        for key, value in data.items():
            if key == "seccompProfile":
                if value:
                    pass_message = "[PASS] seccompProfile has been configured in the YAML file."
                    append_to_file(output_file, pass_message)
                else:
                    warning_message = "[Warning] seccompProfile is present in the YAML file, but it is not configured."
                    append_to_file(output_file, warning_message)
            elif isinstance(value, (dict, list)):
                search_seccomp_profile(value)
    elif isinstance(data, list):
        for item in data:
            search_seccomp_profile(item)


def check_image_tags(yaml_data, output_file):
    try:
        data = yaml.safe_load(yaml_data)
        containers = data.get('spec', {}).get('containers', [])
        for container in containers:
            image = container.get('image', '')
            image_name, tag = image.rsplit(':', 1) if ':' in image else (image, None)
            if not tag:
                #print(f"[Warning] Image '{image_name}' does not have a version tag set.")
                append_to_file(output_file, f"[Warning] Image '{image_name}' does not have a version tag set.")
            elif tag.lower() == 'latest':
                #print(f"[Warning] Image '{image}' is using 'latest' tag.")
                append_to_file(output_file, f"[Warning] Image '{image}' is using 'latest' tag.")
            else:
                #print(f"[Pass] Image '{image}' tag is properly set.")
                append_to_file(output_file, f"[Pass] Image '{image}' tag is properly set.")
    except Exception as e:
        print(f"Error: {e}")
        append_to_file(output_file, f"Error: {e}")



def determine_resource_type_from_generate_name(yaml_data, output_file=None):
    try:
        yaml_content = yaml.safe_load(yaml_data)
        metadata = yaml_content.get('metadata', {})
        generate_name = metadata.get('generateName')
        labels = metadata.get('labels', {})
        pod_template_hash = labels.get('pod-template-hash')

        if generate_name:
            if pod_template_hash:
                message = f"[PASS] The resource type is a Deployment."
                resource_type = 'Deployment'
            else:
                message = f"[PASS] The resource type is likely a ReplicaSet."
                resource_type = 'ReplicaSet'
        else:
            message = f"[Warning] The resource is likely a Pod."
            resource_type = 'Pod'

        #print(message)
        if output_file is not None:
            append_to_file(output_file, message)
        return resource_type

    except yaml.YAMLError as exc:
        print(exc)
        return exc
    except Exception as exc:
        print(exc)
        return exc

def detect_secret_handling(pod_data, output_file):
    try:
        yaml_content = yaml.safe_load(pod_data)
        for pod in yaml_content.get('items', []):
            pod_name = pod.get('metadata', {}).get('name')
            containers = pod.get('spec', {}).get('containers', [])
            if not containers:
                #print(f"[Warning] Pod '{pod_name}' does not have any containers defined.")
                append_to_file(output_file, f"[Warning] Secret Mounting check failed as '{pod_name}' does not have any containers defined.")
                continue
            for container in containers:
                env_vars = container.get('env', [])
                for env_var in env_vars:
                    env_name = env_var.get('name')
                    secret_key_ref = env_var.get('valueFrom', {}).get('secretKeyRef')
                    volume_mounts = container.get('volumeMounts', [])
                    if not volume_mounts:
                        #print(f"[Warning] Pod '{pod_name}' does not have any volumes defined.")
                        append_to_file(output_file, f"[Warning] Secret Mounting check failed as '{pod_name}' does not have any volumes defined.")
                        continue
                    for volume_mount in volume_mounts:
                        if volume_mount.get('mountPath'):
                            #print(f"[PASS] Access to the secret data for Pod '{pod_name}' is done through a Volume.")
                            append_to_file(output_file, f"[PASS] Access to the secret data for Pod '{pod_name}' is done through a Volume.")
                        elif secret_key_ref:
                            secret_name = secret_key_ref.get('name')
                            secret_key = secret_key_ref.get('key')
                            msg1 = f"Pod '{pod_name}': Environment variable '{env_name}' is sourced from Kubernetes Secret '{secret_name}' using key '{secret_key}'."
                            #print(f"[Warning] {msg1}")
                            append_to_file(output_file, f"[Warning] {msg1}")
                        else:
                            msg2 = f"Pod '{pod_name}': Environment variable '{env_name}' is not sourced from a Kubernetes Secret."
                            #print(f"[PASS] {msg2}")
                            append_to_file(output_file, f"[Warning] {msg2}")
    except yaml.YAMLError as exc:
        print(exc)

def parse_pod_yaml(yaml_file_path):
    with open(yaml_file_path, 'r') as file:
        try:
            pod_data = yaml.safe_load(file)
            return pod_data
        except yaml.YAMLError as exc:
            print(f"Error parsing YAML file: {exc}")
            return None

def append_to_file(output_file, data):
    with open(output_file, 'a') as file:
        file.write("\n")
        file.write(data)

def check_security_context(pod_data,output_file):
    containers = pod_data.get("spec", {}).get("containers", [])
    for container in containers:
        security_context = container.get("securityContext", {})
        
        if security_context.get("allowPrivilegeEscalation", True):
            #print(f"[Warning] allowPrivilegeeEscalation is set to true for container \"{container['name']}\". Failing to set this to false may result in elevation of privileges when exploited.")
            append_to_file(output_file, f"[Warning] allowPrivilegeeEscalation is set to true for container \"{container['name']}\". Failing to set this to false may result in elevation of privileges when exploited.")
        else:
            #print(f"[PASS] allowPrivilegeEscalation has been properly set for \"{container['name']}\".")
            append_to_file(output_file, f"[PASS] allowPrivilegeEscalation has been properly set for \"{container['name']}\".")

        #if security_context.get("privileged", True):
        #    print(f"[Warning] Container '{container['name']}' is running in privileged mode. Failing to set this to false may result in container breakout/escape.")
        #elif security_context.get("privileged", False):
        #    print(f"[PASS] privileged is set to false for container '{container['name']}'.")
        #else:
        #    print(f"[Warning] privileged is not set to false for container '{container['name']}'. As per best security practices it is recommended to explicitly set it to false")
        
        privileged = security_context.get("privileged")
        #print(privileged)

        if privileged == True:
            #print(f"[Warning] Container '{container['name']}' is running in privileged mode. Failing to set this to false may result in container breakout/escape.")
            append_to_file(output_file, f"[Warning] Container '{container['name']}' is running in privileged mode. Failing to set this to false may result in container breakout/escape.")
        elif privileged == False:
            #print(f"[PASS] privileged is set to false for container \"{container['name']}\".")
            append_to_file(output_file, f"[PASS] privileged is set to false for container \"{container['name']}\".")
        else:
            #print(f"[Warning] privileged is not set to false for container \"{container['name']}\". As per best security practices it is recommended to explicitly set privileged to false")
            append_to_file(output_file, f"[Warning] privileged is not set to false for container \"{container['name']}\". As per best security practices it is recommended to explicitly set privileged to false")

        #runAsNonRoot = security_context.get("runAsNonRoot")
        if security_context.get("runAsNonRoot"):
            #print (f"[PASS] runAsNonRoot is set to true for Container \"{container['name']}'.")
            append_to_file(output_file, f"[PASS] runAsNonRoot is set to true for Container \"{container['name']}'.")
        else:
            #print (f"[Warning] runAsNonRoot is set to false for Container \"{container['name']}\".")
            append_to_file(output_file, f"[Warning] runAsNonRoot is set to false for Container \"{container['name']}\".")

        capabilities = security_context.get("capabilities", {})
        if capabilities.get("drop", []) != ["ALL"]:
            #print(f"[Warning] Drop ALL capabilities not set for container \"{container['name']}\". As per best security practices it is recommended to drop all capabilities and add only the required ones.")
            append_to_file(output_file, f"[Warning] Drop ALL capabilities not set for container \"{container['name']}\". As per best security practices it is recommended to drop all capabilities and add only the required ones.")
            if capabilities.get("add", 1):
                #print("Following additional capabilities are added:")
                #print(capabilities.get("add", []))
                append_to_file(output_file, f"Following additional capabilities are added:")
                append_to_file(output_file, f"{capabilities.get('add', [])}")
        else:
            #print(f"[PASS] Drop ALL capabilities has been set for container \"{container['name']}\".")
            append_to_file(output_file, f"[PASS] Drop ALL capabilities has been set for container \"{container['name']}\".")
            if capabilities.get("add", 1):
                #print("Following additional capabilities are added:")
                #print(capabilities.get("add", []))
                append_to_file(output_file, f"Following additional capabilities are added:")
                append_to_file(output_file, f"{capabilities.get('add', [])}")
        
        #if security_context.get("seccompProfile", {}) == {}:
            #print(f"[Warning] seccompProfile has not been configured for the container \"{container['name']}\". Failing to configure seccompProfile may result in invoking dangerous system calls when exploited.")
            #append_to_file(output_file, f"[Warning] seccompProfile has not been configured for the container \"{container['name']}\". Failing to configure seccompProfile may result in invoking dangerous system calls when exploited.")
        #else:
            #print(f"[PASS] seccompProfile has been configured for the container \"{container['name']}\".")
           # append_to_file(output_file, f"[PASS] seccompProfile has been configured for the container \"{container['name']}\".")
        
        if security_context.get("seLinuxOptions", {}) == {}:
            #print(f"[Warning] seLinux has not been configured for the container \"{container['name']}\". Failing to configure seLinux may lead to permissive access control.")
            append_to_file(output_file, f"[Warning] seLinux has not been configured for the container \"{container['name']}\". Failing to configure seLinux may lead to permissive access control.")
        else:
            #print(f"[PASS] seLinux has been configured for the container \"{container['name']}\".")
            append_to_file(output_file, f"[PASS] seLinux has been configured for the container \"{container['name']}\".")
        
        resources = container.get("resources", {})
        if not resources.get("limits") and not resources.get("requests"):
            #print(f"[Warning] Limits and requests are not configured for the container \"{container['name']}\".")
            append_to_file(output_file, f"[Warning] Limits and requests are not configured for the container \"{container['name']}\".")
        elif not resources.get("limits"):
            #print(f"[Warning] Limits has not been configured for the container \"{container['name']}\".")
            append_to_file(output_file, f"[Warning] Limits has not been configured for the container \"{container['name']}\".")
        else:
            #print(f"[PASS] Limits and requests are configured for the container \"{container['name']}\".")
            append_to_file(output_file, f"[PASS] Limits and requests are configured for the container \"{container['name']}\".")
        
        run_as_user = security_context.get("runAsUser", 0)
        run_as_group = security_context.get("runAsGroup", 0)
        if run_as_user <= 10000:
            #print(f"[Warning] runAsUser is not greater than or equal to 10000 for container \"{container['name']}\". As per best security practices it is recommended to set runAsUser value above 10000")
            append_to_file(output_file, f"[Warning] runAsUser is not greater than or equal to 10000 for container \"{container['name']}\". As per best security practices it is recommended to set runAsUser value above 10000")
        else:
            #print(f"[PASS] runAsUser is properly set for container \"{container['name']}\".")
            append_to_file(output_file, f"[PASS] runAsUser is properly set for container \"{container['name']}\".")

        if run_as_group <= 10000:
            #print(f"[Warning] runAsGroup is not greater than or equal to 10000 for container \"{container['name']}\". As per best secirity practices it is recommended to set runAsGroup value above 10000.")
            append_to_file(output_file, f"[Warning] runAsGroup is not greater than or equal to 10000 for container \"{container['name']}\". As per best secirity practices it is recommended to set runAsGroup value above 10000.")
        else:
            #print(f"[PASS] runAsGroup is properly set for container \"{container['name']}\".")
            append_to_file(output_file, f"[PASS] runAsGroup is properly set for container \"{container['name']}\".")


        if not security_context.get("readOnlyRootFilesystem", False):
            #print(f"[Warning] readOnlyRootFilesystem is set to false for container \"{container['name']}\".")
            append_to_file(output_file, f"[Warning] readOnlyRootFilesystem is set to false for container \"{container['name']}\".")
        else:
            #print(f"[PASS] readOnlyRootFilesystem is set to true for container \"{container['name']}\".")
            append_to_file(output_file, f"[PASS] readOnlyRootFilesystem is set to true for container \"{container['name']}\".")
        
    automount_token = pod_data.get("spec", {}).get("automountServiceAccountToken", [])
    if automount_token == False:
        #print("[PASS] automountServiceAccountToken is set to false.")
        append_to_file(output_file, "[PASS] automountServiceAccountToken is set to false.")
    else:
        #print("[Warning] automountServiceAccountToken is not set to false. Explicitly not setting this value to false will auto mount the service account token and may lead to container breakout when the token is configured with risky permissions.")
        append_to_file(output_file, "[Warning] automountServiceAccountToken is not set to false. Explicitly not setting this value to false will auto mount the service account token and may lead to container breakout when the token is configured with risky permissions.")
    
    volumes = pod_data.get("spec", {}).get("volumes", [])
    riskyflag = False
    for volume in volumes:
        if volume.get("hostPath") or volume.get("hostIPC") or volume.get("hostNetwork"):
            #print("[Warning] HostPath, HostIPC, or HostNetwork is used in volumes.")
            append_to_file(output_file, "[Warning] HostPath, HostIPC, or HostNetwork is used in volumes.")
            break
        else:
            #print("[PASS] Risky volumes not used.")\
            if riskyFlag == False:
                append_to_file(output_file, "[PASS] Risky volumes not used.")
                riskyflag = True

    
    annotations = pod_data.get("metadata", {}).get("annotations", [])
    armorflag = False
    if annotations is None or annotations == []:
        #print("[Warning] Apparmor is not configured for the pod")
        append_to_file(output_file, "[Warning] Apparmor is not configured for the pod")
    else:
        for key in annotations:
            if "apparmor" in key:
                #print("[PASS] AppArmor is configured for the pod.")
                append_to_file(output_file, "[PASS] AppArmor is configured for the pod.")
                break
            else:
                #print("[Warning] AppArmor is not configured for the pod.")
                if armorflag == False:
                    append_to_file(output_file, "[Warning] AppArmor is not configured for the pod.")
                    armorflag = True
    
    public_registries = ["docker.io", "quay.io"]  # Add more public registries if needed

    containers = pod_data.get("spec", {}).get("containers", [])
    for container in containers:
        image = container.get("image", "")
        #registry = image.split("/")[0]  # Extract the registry from the image URL
    
        #if registry in public_registries:
        #    print(f"[Warning] Container '{container['name']}' uses an image stored in a public registry ({registry}).")
        #    append_to_file(output_file, f"[Warning] Container '{container['name']}' uses an image stored in a public registry ({registry}).")
        #else:
        #    print(f"[PASS] Container '{container['name']}' uses an image stored in a private registry.")
        #    append_to_file(output_file, f"[PASS] Container '{container['name']}' uses an image stored in a private registry.")

        if any(repo in image for repo in public_registries):
            #print("[Warning] Image is available in the public repository")
            append_to_file(output_file, "[Warning] Image is available in the public repository.")

        else:
        # Checking if the image name matches certain common patterns
            common_patterns = [r"^\w+$", r"^\w+:\w+$", r"^\w+:\d+\.\d+\.\d+$"]
            if any(re.match(pattern, image) for pattern in common_patterns):
                #print("[Warning] Image is available in the public repository")
                append_to_file(output_file, "[Warning] Image is available in the public repository.")
            else:
                #print("[PASS] Image is not avaiable in the public repository")
                append_to_file(output_file, "[PASS] Image is not avaiable in the public repository.")

    yaml_data = yaml.dump(pod_data, default_flow_style=False)
    detect_secret_handling(yaml_data,output_file)
    check_image_tags(yaml_data,output_file)
    determine_resource_type_from_generate_name(yaml_data,output_file)
    search_seccomp_profile(yaml_data,output_file)


