# Amazon-EKS-Security


1. AWS Cloud9 기동
- AWS Console의 Services에서 Cloud9를 입력하고, 하단에 Cloud9를 선택합니다.
![image](https://user-images.githubusercontent.com/25558369/181396773-09cf60b0-3990-4c80-a9a5-695835e30e95.png)
- "Create environment"를 선택합니다.
![image](https://user-images.githubusercontent.com/25558369/181396916-2b50d3d7-ad6e-488c-b0c8-0b3cf2820767.png)
- Name에 "eks-security-workshop"를 입력하고, "Next step" 버튼을 선택합니다.
![image](https://user-images.githubusercontent.com/25558369/181397157-c788e94d-f546-4a08-81cf-61c52368a46b.png)
- Instance type에 t3.small를 선택하고, "Next step" 버튼을 선택합니다.
![image](https://user-images.githubusercontent.com/25558369/181397442-9291ad7e-32c7-41a9-bdb6-3602911d8774.png)
- 다음 화면에서 리뷰를 하고 문제가 없으면 "Create environment" 버튼을 선택합니다.
![image](https://user-images.githubusercontent.com/25558369/181397575-b2b5e3ba-0ae1-474b-8e4e-917b03388dd1.png)


2. 실습 환경 설정
- 아래 URL를 클릭하여 IAM Role를 생성합니다.

https://console.aws.amazon.com/iam/home#/roles$new?step=review&commonUseCase=EC2%2BEC2&selectedUseCase=EC2&policies=arn:aws:iam::aws:policy%2FAdministratorAccess&roleName=eks-security-workshop-admin
- "Next" 버튼을 선택합니다.
![image](https://user-images.githubusercontent.com/25558369/181398390-5c35ca86-db64-456e-81f3-7a0edc14ac3d.png)
- "AdministratorAccess"가 선택된 것을 확인하고 "Next" 버튼을 선택합니다.
![image](https://user-images.githubusercontent.com/25558369/181398479-4c659a51-b720-44ac-b2b4-6f26c904a72e.png)
- "Next" 버튼을 선택합니다.
![image](https://user-images.githubusercontent.com/25558369/181398633-93f370f2-d9c8-4c8b-9100-8f4145606c64.png)
- "Create role" 버튼을 선택합니다.
![image](https://user-images.githubusercontent.com/25558369/181398732-af599cdd-833e-4e62-a137-2bc78612cb6e.png)
- Cloud9에 "T"로 보이는 버튼을 선택하여 "Managed EC2 Instance"를 선택합니다.. ("T"는 현재 접속하고 있는 IAM Role의 맨 앞자리 입니다.)
![image](https://user-images.githubusercontent.com/25558369/181399086-9d03212a-5ab8-4cd7-bad6-043f29a29acf.png)
- Cloud9 EC2 인스턴스를 선택한 상태에서, 위에 Action 버튼을 클릭하고, Security 항목에 "Modify IAM role"를 선택합니다..
![image](https://user-images.githubusercontent.com/25558369/181399254-dc59a33c-240e-421e-b991-463fb489256f.png)
- 위에서 생성한 "eks-security-workshop-admin" IAM Role를 선택하고, "Update IAM role" 버튼을 선택합니다..
![image](https://user-images.githubusercontent.com/25558369/181399979-ab09f5d4-941a-40ff-8e02-798958f8e792.png)
- 실습에 사용하는 소스를 가져옵니다.
```
git clone https://github.com/paulseo0827/Amazon-EKS-Security.git
```
![image](https://user-images.githubusercontent.com/25558369/181400225-8b8039c2-e673-4b7d-9623-2e010d26ac80.png)
- 작업에 필요한 툴(kubectl, eksctl, kustomize, aws-cli 등)을 설치하고, 실습에 필요한 설정 작업을 합니다.
```
cd Amazon-EKS-Security
./0_install.sh 
```
- Cloud9의 디스크 사이즈를 50G로 증설합니다.
```
./1_disk_resize.sh
```
![image](https://user-images.githubusercontent.com/25558369/181401440-f0a407bc-5a51-41a7-94b5-07ae172797c1.png)


3. Amazon EKS Cluster 생성
- eksctl 툴을 이용해서 Amzon EKS Cluster (Control Plane + Date Plane)를 생성합니다. 해당 작업은 약 20~30분정도 소요됩니다.
```
eksctl create cluster -f eks-security-workshop.yaml
```
![image](https://user-images.githubusercontent.com/25558369/181402293-73dfdc44-b5b7-4ea0-ad5c-e6f28626718e.png)
![image](https://user-images.githubusercontent.com/25558369/181411686-57a19642-5e86-4a3b-bfb1-2d28f1a4da67.png)

- 작업이 완료되면 worker node 정보를 제대로 가져오는지 확인합니다.
```
kubectl get node
```
![image](https://user-images.githubusercontent.com/25558369/181411732-7e6f9ca3-7341-4e50-a860-aff97a661c60.png)
- 실습을 위해서 Worker Node의 IAM Role에 S3FullAccess IAM Policy를 붙입니다.
```
ROLE_NAME=$(aws cloudformation  list-stack-resources --stack-name eksctl-security-workshop-nodegroup-managed-ng01 | jq -r '.StackResourceSummaries[].PhysicalResourceId' | grep Role)
aws iam attach-role-policy --role-name $ROLE_NAME --policy-arn arn:aws:iam::aws:policy/AmazonS3FullAccess
```
- AWS Console의 Services에서 eks 입력하고, 하단에 Elastic Kuberntes Service를 선택합니다.
![image](https://user-images.githubusercontent.com/25558369/181411945-ceef8e81-b9f5-4cf3-98e9-0ed714c0b7da.png)
- 생성된 security-workshop EKS Cluster를 선택합니다.
![image](https://user-images.githubusercontent.com/25558369/181412406-d0f05d59-d2ea-47b9-97bf-a2fb2c3799e1.png)
- 외부에서 Amazon EKS에 접근하는 곳을 제한하는 설정을 합니다. Cloud9에서만 접근 가능하게 할 것 입니다. 하단 탭에서 Networking를 선택하고, 오른쪽에 "Manage networking" 버튼을 선택합니다.
![image](https://user-images.githubusercontent.com/25558369/181412588-a192954d-fc46-4265-884a-c8e6db953710.png)
- "Advanced settings" 를 선택하여, CIDR block에 Cloud9 의 Public IP 정보를 입력합니다. 그리고 "Save changes" 버튼을 선택합니다. Cloud9의 Public IP는 EC2 Console에서 확인할 수 있습니다. 만약 Cloud9의 Public IP가 바뀌면, 바뀐 IP로 정보를 바꿔주시기 바랍니다.
![image](https://user-images.githubusercontent.com/25558369/181412825-3222581e-7d9d-4ad2-928e-39ebc6e6107e.png)
- Cluster name 에 "security-workshop" 를 입력하고 Confirm 버튼을 선택합니다.
![image](https://user-images.githubusercontent.com/25558369/181413323-bbf88184-b8c0-4838-9f42-e9c791198417.png)


4. Amazon GuardDuty 기능 활성화
- AWS Console의 Services에서 guardduty를 입력하고, 하단에 GuardDuty를 선택합니다.
![image](https://user-images.githubusercontent.com/25558369/181403056-c46c7afb-aaa8-442f-a492-61284be3a2c3.png)
- "Get Started" 버튼을 선택합니.
![image](https://user-images.githubusercontent.com/25558369/181403093-9e4a6c3f-9a51-4ece-af45-1f110cfe553f.png)
- "Enable GuardDuty" 버튼을 선택해서, GuardDuty 기능을 활성화 합니다.
![image](https://user-images.githubusercontent.com/25558369/181403145-26339e62-e5d8-4da4-a0c3-2e43eb4e67d7.png)


5. Amazon Inspector 기능 활성화
- AWS Console의 Services에서 inspector 입력하고, 하단에 Inspector를 선택합니다.
![image](https://user-images.githubusercontent.com/25558369/181414179-b778fa06-cebd-4c78-ba7b-e581c1b51d58.png)
- "Get Started" 버튼을 선택합니다.
![image](https://user-images.githubusercontent.com/25558369/181414300-3111ffe3-a6e5-4fb5-aebd-b559c9fc2cd0.png)
- "Enable Inspector" 버튼을 선택합니다.
![image](https://user-images.githubusercontent.com/25558369/181414387-44339fbb-6ed8-42e0-9ff9-072e046046bb.png)


6. Amazon ECR Container Image Scan 기능 테스트
- AWS에서 제공하는 Container Image scan 기능을 알아보도록 하겠습니다. 예제로는 2022년 3월말 Spring 프레임워크 취약점을 가지고 확인해보겠습니다. (https://www.ahnlab.com/kr/site/securityinfo/asec/asecView.do?groupLevel=001&groupCode=VNI002&seq=31635)
- Spring 프레임워크 취약점을 테스트를 위해서 해당 git repo를 가져옵니다.
```
cd ~/environment
git clone https://github.com/paulseo0827/Spring4Shell-POC.git
cd Spring4Shell-POC
```
- Lint 툴(https://github.com/hadolint/hadolint)를 이용하여 Dockerfile를 최적화를 합니다. ADD 부분을 COPY로, apt를 apt-get 으로 수정합니다.
```
hadolint Dockerfile 
vi Dockerfile
```
![image](https://user-images.githubusercontent.com/25558369/181462509-8a9ea72a-0df6-4674-a9e2-9dead0c4b844.png)
- Spring 프레임워크 취약점을 가진 이미지를 빌드합니다.
```
docker build --tag spring4shell:latest .
docker images
```
![image](https://user-images.githubusercontent.com/25558369/181415431-9367daf4-dfa4-46cd-affd-77a413f18843.png)
- 첫번째로, Amazon ECR에서 제공하는 Basic scanning 기능을 확인해봅니다. 아래 명령어로 Scan 설정이 Basic인지, 만약 Enhanced 이면 Basic으로 설정을 변경합니다.
```
aws ecr get-registry-scanning-configuration
aws ecr put-registry-scanning-configuration --scan-type BASIC
```
![image](https://user-images.githubusercontent.com/25558369/181417712-838b4d33-b062-4cf4-9f3f-af0d97bcea45.png)
- 위에 빌드한 이미지를 ECR에 저장하기 위해서 repository 를 생성하고, ECR login를 합니다.
```
aws ecr create-repository --repository-name spring4shell --image-scanning-configuration scanOnPush=true
aws ecr get-login-password --region ap-northeast-2 | docker login --username AWS --password-stdin $ACCOUNT_ID.dkr.ecr.ap-northeast-2.amazonaws.com 
```
![image](https://user-images.githubusercontent.com/25558369/181416263-04992e8e-42ab-479f-a9b0-83a63a544185.png)
- 빌드한 spring4shell 이미지를 ECR로 푸쉬니다.
```
docker tag spring4shell:latest $ACCOUNT_ID.dkr.ecr.ap-northeast-2.amazonaws.com/spring4shell:latest
docker push $ACCOUNT_ID.dkr.ecr.ap-northeast-2.amazonaws.com/spring4shell:latest
```
![image](https://user-images.githubusercontent.com/25558369/181416577-b7f41d60-0e64-40b2-ac14-63bb948a4418.png)
- Amazon ECR Console(AWS Console에 Services에서 Elastic Container Registry 를 선택합니다.)에 spring4shell repository 로 들어가서, Vulnerabilities 항목을 확인해봅니다. 
![image](https://user-images.githubusercontent.com/25558369/181416840-133f34ba-f824-4389-989d-23320b6c2cb3.png)
- 현재 결과에는 Critical이 3개, High가 12개 나왔고, 결과에 CVE-2022-22965(https://nvd.nist.gov/vuln/detail/cve-2022-22965) 를 찾을 수 없습니다.
![image](https://user-images.githubusercontent.com/25558369/181418071-b666e95b-0c82-4e53-9636-8b1a327bb2e8.png)
- 두번째로, Amazon ECR에서 제공하는 Enhanced scanning 기능을 확인해봅니다. Enhanced scanning 설정은 Inspector를 이용하여 결과를 확인할 수 있습니다.
```
aws ecr put-registry-scanning-configuration --scan-type ENHANCED
aws ecr get-registry-scanning-configuration
```
![image](https://user-images.githubusercontent.com/25558369/181418801-55b56737-5121-4d4f-ae5a-30a0bf3190f1.png)
- 기존 ECR repository 를 지우고, 다시 생성하여 spring4shell 이미지를 올립니다. 
```
aws ecr delete-repository --repository-name spring4shell --force
aws ecr create-repository --repository-name spring4shell --image-scanning-configuration scanOnPush=true
docker push $ACCOUNT_ID.dkr.ecr.ap-northeast-2.amazonaws.com/spring4shell:latest
```
![image](https://user-images.githubusercontent.com/25558369/181419573-e991972d-ce7c-4698-8a00-5686bf2c8934.png)
- ECR repository 에 Vulnerabilities 항목들을 보면 결과로 Critical 16개, High 24개를 확인할 수 있고, CVE-2022-22965가 있는 것을 확인할 수 있습니다.
![image](https://user-images.githubusercontent.com/25558369/181420103-ccd8f5b8-7ef0-402f-b406-e87c594d3979.png)
- Inspector 서비스에서도 Findings 에 "By container image"에 아래 그림과 같은 결과를 확인할 수 있습니다. (Inspector에 결과가 나오는데 수 분이 걸릴 수 있습니다.)
![image](https://user-images.githubusercontent.com/25558369/181420673-f22987d0-b608-43e9-9443-5040965b646b.png)


7. Amazon GuardDuty로 EKS 보안 확인
- GuardDuty를 이용하여 EKS Audit Log를 기준으로 권한이나 보안 관련 문제들을 쉽게 찾을 수 있습니다.
```
cd ~/environment/Amazon-EKS-Security/
./2_guardduty.sh 
kubectl get pods --kubeconfig guardduty/anonymous-kubeconfig
Username는 testuser 를 입력
Password는 testpasswd 를 입력
```
![image](https://user-images.githubusercontent.com/25558369/181424886-4223aa75-767a-49b3-bd0e-c8da4dd74330.png)
- 명령어 수행 이후 GuardDuty 에서 아래와 같이 Finding이 있는 것을 확인할 수 있습니다. 각각 Finding를 하나씩 확인하고 해결해보겠습니다.
![image](https://user-images.githubusercontent.com/25558369/181425117-3fcbc9a0-a2f3-45c4-a3d8-45f83d403088.png)
- 각 Finding 을 해결하는 방법은 아래 workshop과 문서 참고해주시기 바랍니다.

https://catalog.workshops.aws/guardduty/en-US/module11/mod11-2-remediation
https://docs.aws.amazon.com/ko_kr/guardduty/latest/ug/guardduty_finding-types-kubernetes.html


8. Instance metadata 설정
- EC2를 생성할 때, 기본적으로 EC2 Instance Metadata Service(IMDS)를 v1 와 v2를 같이 상요할 수 있게 설정이 됩니다. EC2에서 curl명령어로 Instance Metadata에 접근이 가능하다면, Container가 올라가 있는 Pod에서도 접근이 가능합니다. 이 부분을 IMDSv2로 설정할 수 있는 실습을 하겠습니다. 우선 kube-system에 있는 restricted-namespace-pod pod에서 metadata 에 접근해서 IAM Role의 credentials(AccessKey, SecretAccessKey, Token) 정보를 가져오는 것을 확인합니다.
```
aws cloudformation  list-stack-resources --stack-name eksctl-security-workshop-nodegroup-managed-ng01 | jq -r '.StackResourceSummaries[].PhysicalResourceId' | grep Role
kubectl -n kube-system exec -it restricted-namespace-pod -- /bin/sh
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/eksctl-security-workshop-nodegrou-NodeInstanceRole-QBU9FVSOHZEQ
```
![image](https://user-images.githubusercontent.com/25558369/181430433-7d538392-9612-4aec-a504-cde343b63b85.png)
- IMDS에 접근하는 설정을 v2로 하기 위해서, 인스턴스 리스트 확인과 각 인스턴스에 HttpTokens 설정이 optional(v1 or v2 동시 사용가능) 인 것을 확인합니다.
```
aws ec2 describe-instances | jq -r '.Reservations[].Instances[].InstanceId'
aws ec2 describe-instances --instance-ids i-0eace57965836216d | jq -r '.Reservations[].Instances[].MetadataOptions'
```
![image](https://user-images.githubusercontent.com/25558369/181432810-01c23a01-461e-45ba-9969-de8bd1dd71e9.png)
- 각각 인스턴스의 HttoTokens 정보를 required (IDMSv2)로 변경을 합니다.
```
aws ec2 modify-instance-metadata-options --instance-id i-0eace57965836216d --http-tokens required --http-endpoint enabled
aws ec2 modify-instance-metadata-options --instance-id i-0e2b6b09c4343b45e --http-tokens required --http-endpoint enabled
aws ec2 modify-instance-metadata-options --instance-id i-0b8e95d29144ac592 --http-tokens required --http-endpoint enabled
aws ec2 modify-instance-metadata-options --instance-id i-07df9bf65fe7a8200 --http-tokens required --http-endpoint enabled 
```
![image](https://user-images.githubusercontent.com/25558369/181433223-fb4c6c11-6e5a-449f-853f-5f6c7bae1d9c.png)
- 변경 후, kube-system의 restricted-namespace-pod pod에 접속하여, metadata 호출이 안되는지 확인을 합니다.
```
aws cloudformation  list-stack-resources --stack-name eksctl-security-workshop-nodegroup-managed-ng01 | jq -r '.StackResourceSummaries[].PhysicalResourceId' | grep Role
kubectl -n kube-system exec -it restricted-namespace-pod -- /bin/sh
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/eksctl-security-workshop-nodegrou-NodeInstanceRole-QBU9FVSOHZEQ
```
![image](https://user-images.githubusercontent.com/25558369/181433529-14e71fdb-a675-4df4-b7c3-e80de6addb3e.png)
- 해당 설정은 AWS Config에 ec2-imdsv2-check 를 이용해서, 각 EC2의 IMDS 버전을 확인할 수 있으니 참고해주시기 바랍니다.

https://docs.aws.amazon.com/config/latest/developerguide/ec2-imdsv2-check.html


9. Amazon EKS에 배포된 워크로드가 문제가 없는지 Polaris By Fairwinds 를 이용하여 확인
- Microservice 어플리케이션 배포를 한다.
```
cd ~/environment/Amazon-EKS-Security/
./4_microservice.sh
kubectl -n microservice get pod,svc
```
![image](https://user-images.githubusercontent.com/25558369/181448318-ae0d4338-698a-432c-a091-10fbde18e995.png)
- 
```
cd ~/environment/Amazon-EKS-Security/
./3_polaris.sh
```
![image](https://user-images.githubusercontent.com/25558369/181437996-66489695-29d6-49c5-8e59-3e500a524d66.png)
- Polaris 에 LoadBalancer 정보를 조회해서, 그 URL로 접속을 하면 아래 캡처화면과 같은 사이트에 접속할 수 있습니다.
```
kubectl -n polaris get svc
```
![image](https://user-images.githubusercontent.com/25558369/181451540-97dc741d-4f99-40de-a6e7-67fad74b1cc4.png)
- 하단에 microservice namespace에 cartservice 내용을 확인해봅니다. 
![image](https://user-images.githubusercontent.com/25558369/181452008-66f7d628-50df-4c32-9cd7-aa2ce3323e94.png)
- X로 표시되어 있는 부분을 체크표시로 되게 설정을 적용해보겠습니다.
```
cd ~/environment/Amazon-EKS-Security/
kubectl -n microservice apply -f cartservice.yaml 
kubectl -n microservice get pod
```
![image](https://user-images.githubusercontent.com/25558369/181457420-8f5e6688-69d3-42fe-b4f7-92a4c785fe2e.png)


10. Kubernetes Forensics
- 
```
```

11. Falco
- 
```
```

12. OPA

13. 자원 삭제
- 
```
```





