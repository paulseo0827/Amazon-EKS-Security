

CERT=`cat ~/.kube/config |grep certificate |cut -f2 -d: | sed 's/^ //'`
NAME=`cat ~/.kube/config  | grep "\- name:" |cut -f3 -d" "`
SERVER=`cat ~/.kube/config |grep "server:" |cut -f6 -d " "`

touch guardduty/anonymous-kubeconfig
echo "apiVersion: v1">>guardduty/anonymous-kubeconfig
echo "clusters:" >>guardduty/anonymous-kubeconfig
echo "- cluster:" >>guardduty/anonymous-kubeconfig
echo "    certificate-authority-data: $CERT" >>guardduty/anonymous-kubeconfig
echo "    server: $SERVER" >>guardduty/anonymous-kubeconfig
echo "  name: $NAME" >>guardduty/anonymous-kubeconfig
echo "contexts:">>guardduty/anonymous-kubeconfig
echo "- context:">>guardduty/anonymous-kubeconfig
echo "    cluster: $NAME">>guardduty/anonymous-kubeconfig
echo "    user: $NAME" >>guardduty/anonymous-kubeconfig
echo "  name: $NAME" >>guardduty/anonymous-kubeconfig
echo "current-context: $NAME" >>guardduty/anonymous-kubeconfig
echo "kind: Config">>guardduty/anonymous-kubeconfig
echo "preferences: {}">>guardduty/anonymous-kubeconfig

kubectl apply -f guardduty/anonymous.yaml 

kubectl apply -f guardduty/elevate.yaml

kubectl apply -f guardduty/k8-dashboard.yaml

kubectl apply -f guardduty/expose_k8s_dashboard.yaml

kubectl apply -f guardduty/pod_with_sensitive_mount.yaml

/usr/local/bin/kubectl run --image=nginx restricted-namespace-pod -n kube-system
sleep 10

POD_ID=`/usr/local/bin/kubectl get pod -n kube-system | grep "restricted-namespace-pod" | cut -f1 -d " "`
/usr/local/bin/kubectl exec -it $POD_ID sh -n kube-system <<'EOT'
date
EOT
