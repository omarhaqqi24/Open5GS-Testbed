new=$2
old=$1

sed -i "s/$old/$new/" ./open5gs/open5gs-k3s-calico/00-foundation/mongod-external.yaml
sed -i "s/$old/$new/" ./open5gs/open5gs-k3s-calico/deployment-summary/deployment_20251119_004150.txt
sed -i "s/$old/$new/" ./open5gs/open5gs-k3s-calico/verify-mongodb.sh
sed -i "s/$old/$new/" ./open5gs/open5gs-k3s-calico/03-session-mgmt/amf.yaml
sed -i "s/$old/$new/" ./ueransim/configs/open5gs-gnb-k3s.yaml
sed -i "s/$old/$new/" ./ueransim/configs/open5gs-ue-urllc.yaml
sed -i "s/$old/$new/" ./ueransim/configs/open5gs-gnb-native.yaml
sed -i "s/$old/$new/" ./ueransim/configs/open5gs-ue-embb.yaml
sed -i "s/$old/$new/" ./ueransim/configs/open5gs-ue-mmtc.yaml