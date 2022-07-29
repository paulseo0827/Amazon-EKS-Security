helm repo add fairwinds-stable https://charts.fairwinds.com/stable
helm upgrade --install polaris fairwinds-stable/polaris --namespace polaris --create-namespace --set dashboard.service.type=LoadBalancer
