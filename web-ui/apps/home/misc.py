import re


import re



def uid(file_content):
    pattern = r'uid=(\d+|\d+\(root\)) gid=(\d+|\d+\(root\))(?: groups=([\d,]+(?:\(\w+\))?(?:,[\d]+(?:\(\w+\))?)*))?'
    pattern2 = r'uid=(\d+)\((\w+)\) gid=(\d+)\((\w+)\) groups=([^\n]+)'
    
    match = re.search(pattern, file_content)
    match2 = re.search(pattern2, file_content)

    if match:
        uid = match.group(1).replace('(root)', '') if match.group(1) else None
        gid = match.group(2).replace('(root)', '') if match.group(2) else None
        groups = match.group(3).split(',') if match.group(3) else []
        uid_line = match.group(0)
    elif match2:
        uid = match2.group(1)
        uid_username = match2.group(2)
        gid = match2.group(3)
        gid_groupname = match2.group(4)
        groups = match2.group(5).split(',') if match2.group(5) else []
        uid_line = match2.group(0)
    else:
        uid_line = "Couldn't retrieve UID, GID, and Groups"
        uid = None
        gid = None
        groups = None

    print(uid_line)
    return uid_line, uid, gid, groups

def cap_trad_way(file_content):
    start_marker = "Checking capsh permissions in traditional way"
    end_marker = "Checking if any binary inside the container has any capabilities"
    pattern = rf'{re.escape(start_marker)}\n(.*?){re.escape(end_marker)}'
    match = re.search(pattern, file_content, re.DOTALL)
    extracted_lines = []
    new_l = []
    
    if match:
        extracted_content = match.group(1)
        for line in extracted_content.splitlines():
            if line.strip():
                extracted_lines.append(line.strip())
        new_l.append(extracted_lines[1])
        return new_l
    else:
        print("Pattern not found.")
        return None


def binaries_with_cap(file_content):
    pattern = r'Checking if any binary inside the container has any capabilities\n(.*?)(?=\n-e)'
    match = re.search(pattern, file_content, re.DOTALL)
    cap_binaries = []
    if match:
        extracted_lines = match.group(1)
        for line in extracted_lines.splitlines():
            if line.strip():
                cap_binaries.append(line.strip())
            if len(cap_binaries) > 0:
                return cap_binaries
            else:
                return None

    else:
        print("Pattern not found.")
        return None

def capsh_check(file_content):
    try:
        pattern = r'Checking capabilities using capsh binary(.*?)\-e'
        matches = re.findall(pattern, file_content, re.DOTALL)
        #print(matches)
        if matches:
            pattern2 = r'Current:\s(.*?)(?=\s|$)'
            current_values = re.findall(pattern2, matches[0])[0].split(',')
            data = matches[0]
            #print(current_values)
            return data, current_values
        else:
            print("Pattern not found.")
            return None
    except:
        return None,None

def check_internet_status(file_content):
    pattern = re.compile(r'Internet:(Yes|No)', re.IGNORECASE)
    match = pattern.search(file_content)
    
    if match and match.group(1).lower() == 'yes':
        print("Internet is available bro")
        return True
    else:
        print("Internet is not available bro")
        return False

def extract_docker_sockets(input_text):
    pattern = re.compile(r'Docker Sockets:(.*?)(Readable files belonging to root and not world-readable:|$)', re.DOTALL)
    match = pattern.search(input_text)
    
    if match:
        extracted_content = match.group(1).strip()
        return extracted_content if any(c.isalpha() for c in extracted_content) else None
    else:
        return None



