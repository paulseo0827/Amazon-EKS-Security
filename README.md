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
- 
