# Amazon-EKS-Security


1. AWS Cloud9 기동
- AWS Console의 Services에서 Cloud9를 입력하고, 하단에 Cloud9를 선택한다.
![image](https://user-images.githubusercontent.com/25558369/181396773-09cf60b0-3990-4c80-a9a5-695835e30e95.png)
- "Create environment"를 선택한다.
![image](https://user-images.githubusercontent.com/25558369/181396916-2b50d3d7-ad6e-488c-b0c8-0b3cf2820767.png)
- Name에 "eks-security-workshop"를 입력하고, "Next step" 버튼을 선택한다.
![image](https://user-images.githubusercontent.com/25558369/181397157-c788e94d-f546-4a08-81cf-61c52368a46b.png)
- Instance type에 t3.small를 선택하고, "Next step" 버튼을 선택한다.
![image](https://user-images.githubusercontent.com/25558369/181397442-9291ad7e-32c7-41a9-bdb6-3602911d8774.png)
- 다음 화면에서 리뷰를 하고 문제가 없으면 "Create environment" 버튼을 선택한다.
![image](https://user-images.githubusercontent.com/25558369/181397575-b2b5e3ba-0ae1-474b-8e4e-917b03388dd1.png)

2. 실습 환경 설정
- 아래 URL를 클릭하여 IAM Role를 생성한다.

https://console.aws.amazon.com/iam/home#/roles$new?step=review&commonUseCase=EC2%2BEC2&selectedUseCase=EC2&policies=arn:aws:iam::aws:policy%2FAdministratorAccess&roleName=eks-security-workshop-admin
- "Next" 버튼을 선택한다.
![image](https://user-images.githubusercontent.com/25558369/181398390-5c35ca86-db64-456e-81f3-7a0edc14ac3d.png)
- "AdministratorAccess"가 선택된 것을 확인하고 "Next" 버튼을 선택한다.
![image](https://user-images.githubusercontent.com/25558369/181398479-4c659a51-b720-44ac-b2b4-6f26c904a72e.png)
- "Next" 버튼을 선택한다.
![image](https://user-images.githubusercontent.com/25558369/181398633-93f370f2-d9c8-4c8b-9100-8f4145606c64.png)
- "Create role" 버튼을 선택한다.
![image](https://user-images.githubusercontent.com/25558369/181398732-af599cdd-833e-4e62-a137-2bc78612cb6e.png)
- Cloud9에 "T"로 보이는 버튼을 선택하여 "Managed EC2 Instance"를 선택한다. ("T"는 현재 접속하고 있는 IAM Role의 맨 앞자리 입니다.)
![image](https://user-images.githubusercontent.com/25558369/181399086-9d03212a-5ab8-4cd7-bad6-043f29a29acf.png)
- Cloud9 EC2 인스턴스를 선택한 상태에서, 위에 Action 버튼을 클릭하고, Security 항목에 "Modify IAM role"를 선택한다.
![image](https://user-images.githubusercontent.com/25558369/181399254-dc59a33c-240e-421e-b991-463fb489256f.png)
- 위에서 생성한 "eks-security-workshop-admin" IAM Role를 선택하고, "Update IAM role" 버튼을 선택한다.
![image](https://user-images.githubusercontent.com/25558369/181399979-ab09f5d4-941a-40ff-8e02-798958f8e792.png)
- 실습에 사용하는 소스를 clone 작업한다.
```
git clone https://github.com/paulseo0827/Amazon-EKS-Security.git
```
![image](https://user-images.githubusercontent.com/25558369/181400225-8b8039c2-e673-4b7d-9623-2e010d26ac80.png)
- 작업에 필요한 툴(kubectl, eksctl, kustomize, aws-cli 등)을 설치하고, 실습에 필요한 설정 작업을 합니다.
```
cd Amazon-EKS-Security
./0_install.sh 
```
- Cloud9의 디스크 사이즈를 50G로 증설한다.
```
./1_disk_resize.sh
```
![image](https://user-images.githubusercontent.com/25558369/181401440-f0a407bc-5a51-41a7-94b5-07ae172797c1.png)


3. Amazon EKS Cluster 생성
- eksctl 툴을 이용해서 Amzon EKS Cluster (Control Plane + Date Plane)를 생성한다. 해당 작업은 약 20~30분정도 소요됩니다.
```
eksctl create cluster -f eks-security-workshop.yaml
```
![image](https://user-images.githubusercontent.com/25558369/181402293-73dfdc44-b5b7-4ea0-ad5c-e6f28626718e.png)

- 작업이 완료되면 worker node 정보를 제대로 가져오는지 확인한다.
```
kubectl get node
```

- 실습을 위해서 Worker Node의 IAM Role에 S3FullAccess IAM Policy를 붙입니다.
```
ROLE_NAME=$(aws cloudformation  list-stack-resources --stack-name eksctl-security-workshop-nodegroup-managed-ng01 | jq -r '.StackResourceSummaries[].PhysicalResourceId' | grep Role)
aws iam attach-role-policy --role-name $ROLE_NAME --policy-arn arn:aws:iam::aws:policy/AmazonS3FullAccess
```


4. 
![image](https://user-images.githubusercontent.com/25558369/181402927-a8f85278-122e-4c91-a8af-cb86fba8b5d8.png)

![image](https://user-images.githubusercontent.com/25558369/181402980-542d957c-5f13-479d-9c62-8b668b80288f.png)

5. Amazon GuardDuty 기능 활성화
- AWS Console의 Services에서 guardduty를 입력하고, 하단에 GuardDuty를 선택한다.
![image](https://user-images.githubusercontent.com/25558369/181403056-c46c7afb-aaa8-442f-a492-61284be3a2c3.png)
- "Get Started" 버튼을 선택한다.
![image](https://user-images.githubusercontent.com/25558369/181403093-9e4a6c3f-9a51-4ece-af45-1f110cfe553f.png)
- "Enable GuardDuty" 버튼을 선택해서, GuardDuty 기능을 활성화 한다.
![image](https://user-images.githubusercontent.com/25558369/181403145-26339e62-e5d8-4da4-a0c3-2e43eb4e67d7.png)


6. 

7. 
