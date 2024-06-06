import re

def extract_prefix(pod_name):
    # Extract prefix by removing the last set of characters
    return re.sub(r'-\d{5}$', '', pod_name)

def is_valid_pod_name(pod_name):
    # Check if the last set contains exactly 5 digits
    last_set = pod_name.split('-')[-1]
    return len(last_set) == 5 and last_set.isdigit()

def find_non_duplicate_pods(pods):
    non_duplicates = set()
    duplicates = set()
    seen_prefixes = set()

    for pod in pods:
        prefix = extract_prefix(pod)
        if prefix in seen_prefixes and is_valid_pod_name(pod):
            duplicates.add(pod)
        elif is_valid_pod_name(pod):
            # If pod has valid last set and is not a duplicate, add it to non-duplicates
            non_duplicates.add(pod)
        seen_prefixes.add(prefix)

    return list(non_duplicates), list(duplicates)

# Example usage
pods = ["Pod-1", "Pod-2", "Pod-1-ae345-24kj8", "Pod-1-ae345-f531k", "Pod-1-ae345-2b1ke"]
non_duplicates, duplicates = find_non_duplicate_pods(pods)
print("Non-Duplicate Pods:")
print(non_duplicates)
print("Duplicate Pods:")
print(duplicates)