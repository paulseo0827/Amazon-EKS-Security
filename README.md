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
- 실습에 사용하는 소스를 clone 작업합니다..
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

6. Amazon ECR Scan 기능 테스트

- ㅇ
```
cd ~/environment
git clone https://github.com/paulseo0827/Spring4Shell-POC.git
cd Spring4Shell-POC
docker build --tag spring4shell:latest .
docker images
```
![image](https://user-images.githubusercontent.com/25558369/181415431-9367daf4-dfa4-46cd-affd-77a413f18843.png)
- 위에 빌드한 이미지를 ECR 에 저장하기 위해서 repository 를 생성하고, ECR login를 한다.
```
aws ecr create-repository --repository-name spring4shell --image-scanning-configuration scanOnPush=true
aws ecr get-login-password --region ap-northeast-2 | docker login --username AWS --password-stdin $ACCOUNT_ID.dkr.ecr.ap-northeast-2.amazonaws.com 
```


7. 
