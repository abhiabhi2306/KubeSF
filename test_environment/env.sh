#!/bin/bash

# Define the namespaces
namespaces=("demo-1" "demo-2" "demo-3")

# Create namespaces
for ns in "${namespaces[@]}"; do
    kubectl create namespace "$ns"
done

# Create service accounts and roles
for ns in "${namespaces[@]}"; do
    # Create service accounts
    kubectl create sa sa-1 -n "$ns"
    kubectl create sa sa-2 -n "$ns"

    # Create roles
    kubectl create role role-1 --verb=* --resource=* -n "$ns"
    kubectl create role role-2 --verb=create,update,delete,get,list --resource=pods,deployments,replicasets -n "$ns"
done

# Create role bindings
for ns in "${namespaces[@]}"; do
    kubectl create rolebinding rolebinding-1 --role=role-1 --serviceaccount="$ns":sa-1 -n "$ns"
    kubectl create rolebinding rolebinding-2 --role=role-2 --serviceaccount="$ns":sa-2 -n "$ns"
done

# Create pods
for ns in "${namespaces[@]}"; do
    for i in {1..5}; do
        if [ $i -eq 1 ]; then
            sa="sa-1"
        elif [ $i -eq 2 ]; then
            sa="sa-2"
        else
            sa="default"
        fi

        cat <<EOF | kubectl apply -n "$ns" -f -
apiVersion: v1
kind: Pod
metadata:
  name: pod-$i
  labels:
    app: my-app
spec:
  containers:
  - name: my-container
    image: nginx
  serviceAccountName: $sa
EOF
    done
done

echo "Env Created!"