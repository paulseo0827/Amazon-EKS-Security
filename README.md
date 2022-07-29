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

여기서 나온 IAM Role 정보를 하단에 curl 명령어에 넣습니다.

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

여기서 나온 IAM Role 정보를 하단에 curl 명령어에 넣습니다.

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

./3_microservice.sh

kubectl -n microservice get pod,svc
```
![image](https://user-images.githubusercontent.com/25558369/181448318-ae0d4338-698a-432c-a091-10fbde18e995.png)
- 
```
cd ~/environment/Amazon-EKS-Security/

./4_polaris.sh
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
- Pod에 해킹 의심이 있어서 분석이 필요할 때, Pod 
- kube-forensics를 이용하면 클러스터 관리자가 실행 중인 Pod 및 모든 컨테이너의 현재 상태 정보를 덤프를 생성할 수 있고, 덤프 이용하여 보안 전문가가 포렌식 분석을 수행할 수 있습니다. kube-forensics 를 설치해서 microservice 에 cartservice pod 의 덤프를 생성하는 작업을 해보도록 하겠습니디ㅏ.
```
cd ~/environment/Amazon-EKS-Security

git clone https://github.com/keikoproj/kube-forensics.git

cd kube-forensics

make deploy
```
![image](https://user-images.githubusercontent.com/25558369/181697351-89727a7d-37ef-4ff4-acdc-a7474bbd5a10.png)
- kube-forensics에서 생성한 덤프를 저장하기 위해서 S3 bucket 를 생성합니다.
```
aws s3 mb s3://kube-forensics-$AWS_REGION-$ACCOUNT_ID
```
![image](https://user-images.githubusercontent.com/25558369/181698972-64ff54cc-28b9-4420-aa33-c91abd988853.png)
- forensics_v1alpha1_podcheckpoint yaml 파일에 포렌식하고 하는 Pod 정보 (microservice namespace에 cartservice pod 가 대상입니다)와 덤프를 저장할 S3 버킷 정보를 입력하고 yaml 파일을 apply 합니다.
```
vi config/samples/forensics_v1alpha1_podcheckpoint.yaml

Forensics 대상의 Pod 이름과 Namespace 정보를 수정하고, Forensics 정보가 저장 될 s3 버킷 정보를 변경합니다.

cat config/samples/forensics_v1alpha1_podcheckpoint.yaml

kubectl apply -f ./config/samples/forensics_v1alpha1_podcheckpoint.yaml

kubectl get -n forensics-system PodCheckpoint
```
![image](https://user-images.githubusercontent.com/25558369/181699647-6adf0484-53f0-4e91-8d96-6bca58f867fc.png)
- 덤프 생성이 제대로 되고 있는지 확인을 합니다.
```
kubectl describe PodCheckpoint -n forensics-system podcheckpoint-sample
```
![image](https://user-images.githubusercontent.com/25558369/181699721-c7f417b6-dd5b-416d-9b73-e3550498102d.png)
- S3 버킷에 microservice namespace에 cartservice pod 의 덤프를 확인합니다.
```
aws s3 ls s3://kube-forensics-$AWS_REGION-$ACCOUNT_ID/forensics/ --recursive
```
![image](https://user-images.githubusercontent.com/25558369/181699953-1ea6b6e8-9ad7-4a4f-bcec-a0acb34918f2.png)


11. Falco
- 향후 지원 예정


12. OPA
- 향후 지원 예정


13. Network Policy
- 향후 지원 예정


14. Pod Security Group
- microservice namespace에 배포된 Redis (redis-cart deployment)를 Elasticache Redis 로 변경 작업을 하면서, Redis 와 통신을 하는 Pod(cartservice)에 Pod Security Group 를 적용합니다. 먼저 Elasticache Redis 생성을 위해서 Security Group 생성 작업을 합니다.
```
cd ~/environment/Amazon-EKS-Security/

export VPC_ID=$(aws eks describe-cluster --name security-workshop --query "cluster.resourcesVpcConfig.vpcId" --output text)

aws ec2 create-security-group --description 'Elasticache Redis SG' --group-name 'Elasticache_Redis_SG' --vpc-id ${VPC_ID}

export REDIS_SG=$(aws ec2 describe-security-groups --filters Name=group-name,Values=Elasticache_Redis_SG Name=vpc-id,Values=${VPC_ID} --query "SecurityGroups[0].GroupId" --output text)

aws ec2 create-security-group --description 'Cartservice Pod SG' --group-name 'Cartservice_Pod_SG' --vpc-id ${VPC_ID}

export POD_SG=$(aws ec2 describe-security-groups --filters Name=group-name,Values=Cartservice_Pod_SG Name=vpc-id,Values=${VPC_ID} --query "SecurityGroups[0].GroupId" --output text)

export NODE_GROUP_SG=$(aws ec2 describe-security-groups --filters Name=tag:Name,Values=eks-cluster-sg-security-workshop-* Name=vpc-id,Values=${VPC_ID} --query "SecurityGroups[0].GroupId" --output text)

```
![image](https://user-images.githubusercontent.com/25558369/181585633-da845a69-f8dc-4917-b229-21524e5e2657.png)
![image](https://user-images.githubusercontent.com/25558369/181586009-d2c26f4a-45b4-4582-9acf-8113287e8714.png)
![image](https://user-images.githubusercontent.com/25558369/181586066-88e62a6a-8056-47bb-ba99-fa438f4c0055.png)
- DNS resolution를 위해 Pod는 Worker Node와 TCP/UDP 53 port로 통신이 필요합니다. Worker Node 의 Security Group 에 Inbound로 Pod가 통신될 수 있게 TCP/UDP 53포트를 입력합니다. 그리고, Pod에서 내부 VPC에 있는 자원들의 요청이 정상적으로 들어올 수 있도록 VPC CIDR 값을 Inbound에 추가합니다.
```
aws ec2 authorize-security-group-ingress --group-id ${NODE_GROUP_SG} --protocol tcp --port 53 --source-group ${POD_SG}

aws ec2 authorize-security-group-ingress --group-id ${NODE_GROUP_SG} --protocol udp --port 53 --source-group ${POD_SG}

aws ec2 authorize-security-group-ingress --group-id ${REDIS_SG} --protocol tcp --port 6379 --source-group ${POD_SG}

aws ec2 authorize-security-group-ingress --group-id ${POD_SG} --protocol tcp --port 7070 --cidr '192.168.0.0/8'
```
![image](https://user-images.githubusercontent.com/25558369/181586161-40ec1f0f-58fc-47c1-9922-b26691cf06bc.png)
![image](https://user-images.githubusercontent.com/25558369/181648268-9e7664dd-220d-45ae-9fd4-c8766a523755.png)
- VPC Private Subnet 정보로 Elasticache Redis 의 Subnet Group 를 생성합니다.
```
export PRIVATE_SUBNETS_ID=$(aws ec2 describe-subnets --filters "Name=vpc-id,Values=$VPC_ID" "Name=tag:Name,Values=eksctl-security-workshop-cluster/SubnetPrivate*" --query 'Subnets[*].SubnetId' --output json | jq -c .)

aws elasticache create-cache-subnet-group --cache-subnet-group-name rediscart --cache-subnet-group-description "rediscart" --subnet-ids ${PRIVATE_SUBNETS_ID}
```
![image](https://user-images.githubusercontent.com/25558369/181586785-39553616-8949-40ee-93c8-e882918717bf.png)
![image](https://user-images.githubusercontent.com/25558369/181585190-fe20e547-d5f3-4fc5-9fa5-6eda7bc381d3.png)
- redis-cart 이름을h Elasticache Redis 생성을 합니다. 해당 작업은 약 5분 내외로 시간 소요가 됩니다.
```
aws elasticache create-cache-cluster --cache-cluster-id redis-cart --cache-node-type cache.r5.large --engine redis --num-cache-nodes 1 --cache-parameter-group default.redis6.x --cache-subnet-group-name rediscart --security-group-ids ${REDIS_SG}
```
![image](https://user-images.githubusercontent.com/25558369/181584985-547407a6-e133-4677-8b13-a86ed6bb3c80.png)
- Pod Security Group 적용을 위해서, Worker Node IAM Role에 AmazonEKSVPCResourceController Policy 를 추가합니다. 그리고, CNI Plugin이 Pod의 ENI를 컨트롤 할 수 있도록 aws-node daemonset 에 설정 작업을 합니다.
```
aws iam attach-role-policy --policy-arn arn:aws:iam::aws:policy/AmazonEKSVPCResourceController --role-name ${ROLE_NAME}

kubectl set env daemonset aws-node -n kube-system ENABLE_PREFIX_DELEGATION=true

kubectl -n kube-system set env daemonset aws-node ENABLE_POD_ENI=true

kubectl -n kube-system rollout status ds aws-node
```
![image](https://user-images.githubusercontent.com/25558369/181587870-5a9026a5-985f-4e99-b968-022dfb246272.png)
- cartservice Deployment (Pod)에 Security Group Policy 적용을 위한 yaml 파일을 생성합니다.
```
cat << EoF > ~/environment/Amazon-EKS-Security/sg-policy.yaml
apiVersion: vpcresources.k8s.aws/v1beta1
kind: SecurityGroupPolicy
metadata:
  name: allow-redis-access
spec:
  podSelector:
    matchLabels:
      app: cartservice
  securityGroups:
    groupIds:
      - ${POD_SG}
EoF
```
![image](https://user-images.githubusercontent.com/25558369/181588024-c52a7ae2-43bc-4e26-a517-61325a2fd03f.png)
- Security Group Policy 를 적용하고, 정상적으로 적용이 되었는지 확인을 합니다.
```
kubectl -n microservice apply -f sg-policy.yaml

kubectl -n microservice describe securitygrouppolicy
```
![image](https://user-images.githubusercontent.com/25558369/181588226-7a724ae3-3c13-4fdc-a594-451b4cf46ec0.png)
- Elasticache Redis Endpoint 정보를 cartservice-podsg.yaml 에 입력을 하고, cartservice deployment 의 Redis 설정을 redis-cart pod 에서 Elasticache Redis 로 설정 변경을 합니다. 변경 이후에 redis-cart deployment 를 삭제합니다.
```
REDIS_ADDRESS=$(aws elasticache describe-cache-clusters --show-cache-node-info | jq -r '.CacheClusters[].CacheNodes[].Endpoint.Address')

sed -i s%CHANGEME%$REDIS_ADDRESS:6379% cartservice-podsg.yaml 

kubectl -n microservice apply -f cartservice-podsg.yaml 

kubectl -n microservice delete deploy redis-cart
```
![image](https://user-images.githubusercontent.com/25558369/181592097-a0f6fbd4-c3f0-4dbc-8da2-cde08a8fa385.png)
- microservice LoadBalancer 주소로 들어가서 정상적으로 서비스가 되고 있는지 확인합니다.
```
kubectl -n microservice get svc frontend-external
```
![image](https://user-images.githubusercontent.com/25558369/181650827-ff30b99c-f3b7-4bb7-898b-208940056640.png)


15. 자원 삭제
- kube-forensics 에서 사용한 S3 버킷을 삭제합니다.
```
aws s3 rb s3://kube-forensics-$AWS_REGION-$ACCOUNT_ID --force
```
![image](https://user-images.githubusercontent.com/25558369/181702336-093681be-c719-48fc-b9b5-7ab7007b0bfc.png)
- GuardDuty 를 중지합니다. 명령어 수행 이후, AWS Console 에 GuardDuty 에 아래와 같은 화면이 뜨는지 확인합니다.
```
GUARDDUTY_DETECTORID=$(aws guardduty list-detectors | jq -r '.DetectorIds[]')

aws guardduty delete-detector --detector-id $GUARDDUTY_DETECTORID

```
![image](https://user-images.githubusercontent.com/25558369/181703131-0eb2a552-287e-46dc-bc6b-ec11234e0228.png)
- Inspector 를 중지합니다. 명령어 수행 이후, AWS Console 에 Inspector 에 아래와 같은 화면이 뜨는지 확인합니다.
```
aws inspector2 disable --resource-types EC2 ECR
```
![image](https://user-images.githubusercontent.com/25558369/181704066-20588d13-870e-4fcd-b859-03a5b01ec900.png)
![image](https://user-images.githubusercontent.com/25558369/181704180-58bb83da-c284-4264-96ce-5829e7089819.png)
- spring4shell 컨테이너 이미지를 저장하고 있는 ECR Repository 를 삭제합니다.
```
aws ecr delete-repository --repository-name spring4shell --force
```
![image](https://user-images.githubusercontent.com/25558369/181704569-00be2dce-141b-4fad-8a24-10f4ff7a5b11.png)
- Elasticache Redis 를 삭제합니다.
```
aws elasticache delete-cache-cluster --cache-cluster-id redis-cart
```
![image](https://user-images.githubusercontent.com/25558369/181705026-59fb8ce5-cd10-46db-a703-bd8d8e6beb6e.png)


- 실습에 사용하였던 IAM Policy 2개를 Worker Node IAM Role에서 제거합니다.
```
ROLE_NAME=$(aws cloudformation  list-stack-resources --stack-name eksctl-security-workshop-nodegroup-managed-ng01 | jq -r '.StackResourceSummaries[].PhysicalResourceId' | grep Role)

aws iam detach-role-policy --role-name $ROLE_NAME --policy-arn arn:aws:iam::aws:policy/AmazonS3FullAccess

aws iam detach-role-policy --role-name $ROLE_NAME --policy-arn arn:aws:iam::aws:policy/AmazonEKSVPCResourceController
```
![image](https://user-images.githubusercontent.com/25558369/181706181-603b6ba6-0877-4924-8698-0cf1883220bb.png)
- 실습에 사용하였던 Security Group 2개를 제거합니다.
```
export VPC_ID=$(aws eks describe-cluster --name security-workshop --query "cluster.resourcesVpcConfig.vpcId" --output text)

export REDIS_SG=$(aws ec2 describe-security-groups --filters Name=group-name,Values=Elasticache_Redis_SG Name=vpc-id,Values=${VPC_ID} --query "SecurityGroups[0].GroupId" --output text)

export POD_SG=$(aws ec2 describe-security-groups --filters Name=group-name,Values=Cartservice_Pod_SG Name=vpc-id,Values=${VPC_ID} --query "SecurityGroups[0].GroupId" --output text)
```
- Amazon EKS Cluster를 삭제합니다.
```
eksctl delete cluster --name security-workshop
```
![image](https://user-images.githubusercontent.com/25558369/181708471-5432783e-cc4b-4565-a5c2-1b195a223bc8.png)
- AWS Console에 CloudFormation으로 가서 EKS 관련 Template 이 삭제가 되었는지 확인합니다. 아래 화면과 같이 삭제가 안되면 강제로 삭제 작업을 수행합니다.
![image](https://user-images.githubusercontent.com/25558369/181712127-1fad8f93-6810-4504-9e64-93c4a9b13bf9.png)
![image](https://user-images.githubusercontent.com/25558369/181712174-f2d7e1d4-96af-493a-be14-fcb5f5670712.png)
- VPC Console 에서 남아있는 VPC를 삭제합니다.
![image](https://user-images.githubusercontent.com/25558369/181712390-d005372b-55b5-4cba-ad08-ab74488ede57.png)
- Amazon EKS Cluster Log가 저장되어있는 CloudWatch Log group 를 삭제합니다. 
```
aws logs delete-log-group --log-group-name /aws/eks/security-workshop/cluster
```
![image](https://user-images.githubusercontent.com/25558369/181713097-f1fee776-7eb2-4fdc-924b-0022bb44506d.png)
- Cloud9 를 삭제합니다. 만약, 삭제가 제대로 안된다면, AWS Console 에 Cloud9 에 직접가서 삭제를 합니다.
```
CLOUD9_ENVIRONMENTID=$(aws cloud9 list-environments | jq -r '.environmentIds[]')

aws cloud9 delete-environment --environment-id $CLOUD9_ENVIRONMENTID
```
![image](https://user-images.githubusercontent.com/25558369/181713697-1f89b67e-a4d8-45e7-8035-40f23898e2ab.png)

