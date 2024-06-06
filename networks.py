import subprocess
import json

def check_network_policies(namespace):
    try:
        # Run kubectl get networkpolicies command and capture output as a JSON string
        output = subprocess.check_output(["kubectl", "get", "networkpolicies", "-n", namespace, "-o", "json"])
        network_policies = json.loads(output.decode('utf-8'))
        namespace_selector_labels = None
        pod_selector = None

        for policy in network_policies.get('items', []):
            policy_name = policy.get('metadata', {}).get('name', 'Unknown Policy')
            ingress_ports = policy.get('spec', {}).get('ingress', [{}])[0].get('ports', [])
            egress_ports = policy.get('spec', {}).get('egress', [{}])[0].get('ports', [])
            pod_selector = policy.get('spec', {}).get('podSelector', {}).get('matchLabels', {})
            from_selectors = policy.get('spec', {}).get('ingress', [{}])[0].get('from', [])
            namespace_selector = next((selector for selector in from_selectors if selector.get("namespaceSelector")), None)
          
            print(f"Policy Name:   '{policy_name}'")
            print("\n Ingress Review: \n")
            if ingress_ports:
                print(f"  - Allowing Ingress Traffic From Ports: {ingress_ports}")
                ingress = True
            else:
                print("  - Ingress ports are not defined.")
                ingress = False
            if pod_selector:
                print(f"  - PodSelector: {pod_selector}")
                pselector = True
            else:
                print("  - PodSelector is not defined.")
                pselector = False
            if namespace_selector:
               namespace_selector_labels = namespace_selector.get("namespaceSelector", {}).get("matchLabels", {})
               print(f"  - NamespaceSelector: {namespace_selector_labels}")
               nselector = True
            else:
               print("  - NamespaceSelector is not defined.")
               print("---")
               nselector = False

            print("\n Egress Review: \n")
            if egress_ports:
                print(f"  - Allowing Egress Traffic To Ports: {egress_ports}")
                egress = True
            else:
                print("  - Egress ports are not defined.")
                egress = False
            if pod_selector:
                print(f"  - PodSelector: {pod_selector}")
                pselector = True
            else:
                print("  - PodSelector is not defined.")
                pselector = False
            if namespace_selector:
                namespace_selector_labels = namespace_selector.get("namespaceSelector", {}).get("matchLabels", {})
                print(f"  - NamespaceSelector: {namespace_selector_labels}")
                nselector = True
            else:
                print("  - NamespaceSelector is not defined.")
                nselector = False

            return ingress, egress, pselector, nselector,ingress_ports, egress_ports, pod_selector, namespace_selector_labels
    except subprocess.CalledProcessError as e:
        print(f"Error checking network policies: {e.output.decode('utf-8')}")
        print("---")
# Specify the namespace you want to check
namespace = "demo-2"

# Call the function to check network policies for the specified namespace
check_network_policies(namespace)
