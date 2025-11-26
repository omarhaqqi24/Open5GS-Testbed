# Open5GS-Testbed
- Muhammad Omar Haqqi
- Dzaky Rezandi
- Christoper Jonathan

## Installation dan Setup
### MongoDB Installation
https://www.mongodb.com/docs/v8.0/tutorial/install-mongodb-on-debian/
```
sudo apt-get install gnupg curl

curl -fsSL https://www.mongodb.org/static/pgp/server-8.0.asc | sudo gpg -o /usr/share/keyrings/mongodb-server-8.0.gpg --dearmor

echo "deb [ signed-by=/usr/share/keyrings/mongodb-server-8.0.gpg ] http://repo.mongodb.org/apt/debian bookworm/mongodb-org/8.0 main" | sudo tee /etc/apt/sources.list.d/mongodb-org-8.0.list

sudo apt-get update

sudo apt-get install -y mongodb-org
```

Memulai MongoDB
```
sudo systemctl start mongod
```
Mengizinkan auto-start saat booting
```
sudo systemctl enable mongod
```
Cek status MongoDB
```
sudo systemctl status mongod
```
Mengatur <b>bindIP</b> menjadi 0.0.0.0
```
sudo nano /etc/mongod.conf

# ubah bagian ini:
# # network interfaces
# net:
#   port: 27017
#   bindIp: 0.0.0.0
```
Restart MongoDB
```
sudo systemctl restart mongod
```

## Open5GS K3S Calico Installation
Clone Github:
```
git clone https://github.com/omarhaqqi24/Open5GS-Testbed.git
```

Karena di sini menggunakan Kali Linux di Host Lokal, maka saya menambahkan script cg-ip.sh untuk mengubah IP di beberapa file instalasi dan konfigurasi Open5GS:

cg-ip.sh:
```
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
```

Cara menggunakan:
```
sudo ./cg-ip.sh <IP Lama\> <IP baru\>
```

### Penyesuaian Dockerfile
Agar terverifikasi saat uji IP static, saya mengubah Dockerfile dengan menambahkan beberapa instalasi ke container:
```
RUN apt-get update && \
    apt-get install -y --no-install-recommends software-properties-common gnupg && \
    add-apt-repository ppa:open5gs/latest && \
    apt-get update && \
    apt-get install -y --no-install-recommends \
        open5gs-amf \
        open5gs-common \
        gosu \
        ca-certificates \

        #Tambahkan 4 baris ini

        netbase \
        iputils-ping \
        curl \
        dnsutils && \

    mkdir -p /var/log/open5gs /etc/open5gs/tls /etc/open5gs/custom /var/run/open5gs && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*
```
### Persiapan Sistem
```
# Update system
sudo apt-get update
sudo apt-get upgrade -y

# Install dependencies
sudo apt-get install -y \
    curl \
    git \
    iptables \
    iptables-persistent \
    net-tools \
    iputils-ping \
    traceroute \
    tcpdump \
    wireshark \
    wireshark-common

# Create log directories
sudo mkdir -p /mnt/data/open5gs-logs
sudo chmod 777 /mnt/data/open5gs-logs
```
### Setup K3s Environment dengan Calico
```
cd ~/Open5GS-Testbed/open5gs/open5gs-k3s-calico

\# Make script executable
chmod +x setup-k3s-environment-calico.sh

\# Run setup
sudo ./setup-k3s-environment-calico.sh
```
#### Verifikasi K3S Installation
```
# Check K3s status
sudo systemctl status k3s

# Check nodes
kubectl get nodes

# Expected output:
# NAME        STATUS   ROLES           AGE   VERSION
# <hostname>  Ready    control-plane   Xm    v1.2X.X
```
### Buil dan Import Container Images
```
# Make script executable
chmod +x build-import-containers.sh

# Build Open5GS images
sudo ./build-import-containers.sh

# Verifikasi image
sudo k3s crictl images
```

### Deploy Open5GS ke K3s
```
# Make script executable
chmod +x deploy-k3s-calico.sh

# Deploy
sudo ./deploy-k3s-calico.sh

# Monitor deployment (di terminal baru)
kubectl get pods -n open5gs -w
```
Cek running pod (Output yang diharapkan):
```
└─$ kubectl get pods -n open5gs   
NAME     READY   STATUS    RESTARTS      AGE
amf-0    1/1     Running   1 (30m ago)   6h26m
ausf-0   1/1     Running   1 (30m ago)   6h25m
nrf-0    1/1     Running   1 (30m ago)   6h26m
nssf-0   1/1     Running   1 (30m ago)   6h25m
pcf-0    1/1     Running   1 (30m ago)   6h26m
scp-0    1/1     Running   1 (30m ago)   6h26m
smf-0    1/1     Running   1 (30m ago)   6h26m
udm-0    1/1     Running   1 (30m ago)   6h25m
udr-0    1/1     Running   1 (30m ago)   6h25m
upf-0    1/1     Running   1 (30m ago)   6h25m
```
## Verifikasi Deployment
### Cek Status Semua NF
```
# List semua pods dengan detail
kubectl get pods -n open5gs -o wide

# Check logs untuk NF tertentu
kubectl logs -n open5gs amf-0
kubectl logs -n open5gs ausf-0
kubectl logs -n open5gs nrf-0
kubectl logs -n open5gs nssf-0
kubectl logs -n open5gs pcf-0
kubectl logs -n open5gs scp-0
kubectl logs -n open5gs smf-0
kubectl logs -n open5gs udm-0
kubectl logs -n open5gs udr-0
kubectl logs -n open5gs upf-0
```
Ouput yang diharapkan:
```
└─$ kubectl get pods -n open5gs -o wide
NAME     READY   STATUS    RESTARTS      AGE     IP            NODE   NOMINATED NODE   READINESS GATES
amf-0    1/1     Running   1 (33m ago)   6h29m   10.10.0.5     omar   <none>           <none>
ausf-0   1/1     Running   1 (33m ago)   6h29m   10.10.0.11    omar   <none>           <none>
nrf-0    1/1     Running   1 (33m ago)   6h30m   10.10.0.10    omar   <none>           <none>
nssf-0   1/1     Running   1 (33m ago)   6h29m   10.10.0.14    omar   <none>           <none>
pcf-0    1/1     Running   1 (33m ago)   6h29m   10.10.0.13    omar   <none>           <none>
scp-0    1/1     Running   1 (33m ago)   6h30m   10.10.0.200   omar   <none>           <none>
smf-0    1/1     Running   1 (33m ago)   6h29m   10.10.0.4     omar   <none>           <none>
udm-0    1/1     Running   1 (33m ago)   6h29m   10.10.0.12    omar   <none>           <none>
udr-0    1/1     Running   1 (33m ago)   6h29m   10.10.0.20    omar   <none>           <none>
upf-0    1/1     Running   1 (33m ago)   6h29m   10.10.0.7     omar   <none>           <none>


└─$ kubectl logs -n open5gs amf-0
Defaulted container "amf" out of: amf, wait-for-dependency (init)
Open5GS daemon v2.7.6

11/25 23:31:35.787: [app] INFO: Configuration: '/etc/open5gs/amf.yaml' (../lib/app/ogs-init.c:144)
11/25 23:31:35.787: [app] INFO: File Logging: '/var/log/open5gs/amf.log' (../lib/app/ogs-init.c:147)
11/25 23:31:35.787: [app] INFO: LOG-LEVEL: 'info' (../lib/app/ogs-init.c:150)
11/25 23:31:35.799: [sbi] INFO: Setup NF EndPoint(addr) [10.10.0.10:7777] (../lib/sbi/context.c:459)
11/25 23:31:35.799: [sbi] INFO: Setup NF EndPoint(addr) [10.10.0.200:7777] (../lib/sbi/context.c:507)
11/25 23:31:35.799: [metrics] INFO: metrics_server() [http://0.0.0.0]:9090 (../lib/metrics/prometheus/context.c:300)
11/25 23:31:35.799: [sbi] INFO: NF Service [namf-comm] (../lib/sbi/context.c:1994)
11/25 23:31:35.807: [sbi] INFO: nghttp2_server() [http://10.10.0.5]:7777 (../lib/sbi/nghttp2-server.c:439)
11/25 23:31:35.814: [amf] INFO: ngap_server() [10.10.0.5]:38412 (../src/amf/ngap-sctp.c:61)
11/25 23:31:35.814: [sctp] INFO: AMF initialize...done (../src/amf/app.c:33)
11/25 23:31:35.820: [sbi] INFO: [e21b459a-ca56-41f0-bdd7-3f6bbeb14ea8] NF registered [Heartbeat:10s] (../lib/sbi/nf-sm.c:295)
11/25 23:31:35.825: [sbi] INFO: Setup NF EndPoint(addr) [10.10.0.10:7777] (../lib/sbi/nnrf-handler.c:955)
11/25 23:31:35.825: [sbi] INFO: [e21fbf62-ca56-41f0-a0e9-edb2bbec6bdf] Subscription created until 2025-11-26T23:31:35.821570+00:00 [duration:86400000000,validity:86400.000000,patch:43200.000000] (../lib/sbi/nnrf-handler.c:874)
11/25 23:31:35.826: [sbi] INFO: Setup NF EndPoint(addr) [10.10.0.10:7777] (../lib/sbi/nnrf-handler.c:955)
11/25 23:31:35.826: [sbi] INFO: [e21fd9ac-ca56-41f0-a0e9-edb2bbec6bdf] Subscription created until 2025-11-26T23:31:35.822232+00:00 [duration:86400000000,validity:86400.000000,patch:43200.000000] (../lib/sbi/nnrf-handler.c:874)
```

### Cek Static IP Assignment
```
# Run verification script
sudo ./verify-static-ips.sh
```
Output yang diharapkan:
```
└─$ sudo ./verify-static-ips.sh
[sudo] password for aq: 
================================================
  Open5GS Calico Static IP Verification
================================================

Checking Calico installation...
✓ Calico is installed (1 node(s))

Checking Open5GS namespace...
✓ Namespace 'open5gs' exists

Checking Calico IPPool...
✓ IPPool 'open5gs-pool' exists
  CIDR: 10.10.0.0/24

Checking pod static IP assignments...
✓ nssf-0: 10.10.0.14 (Running)
✓ amf-0: 10.10.0.5 (Running)
✓ pcf-0: 10.10.0.13 (Running)
✓ udr-0: 10.10.0.20 (Running)
✓ ausf-0: 10.10.0.11 (Running)
✓ nrf-0: 10.10.0.10 (Running)
✓ udm-0: 10.10.0.12 (Running)
✓ upf-0: 10.10.0.7 (Running)
✓ smf-0: 10.10.0.4 (Running)
✓ scp-0: 10.10.0.200 (Running)

Checking ConfigMaps...
✓ All 10 ConfigMaps present

Verifying static IP usage in configs...
✓ NRF config uses static IP (10.10.0.10)
✓ AMF config uses static IP (10.10.0.5)

Testing pod connectivity...
✓ SCP can ping NRF (10.10.0.10)
⚠ SCP cannot reach NRF HTTP (may not be ready)

Checking NF registrations...
✓ 8 NF(s) registered with NRF

================================================
✓ All checks passed!
  Static IP deployment is ready
================================================

Useful commands:
  View all pods:     kubectl get pods -n open5gs -o wide
  Check NRF logs:    kubectl logs -n open5gs nrf-0
  Test NRF API:      kubectl exec -n open5gs nrf-0 -- curl http://10.10.0.10:7777/nnrf-nfm/v1/nf-instances
  View IPPool:       kubectl get ippool open5gs-pool -o yaml
```

### Verifikasi MongoDB Connectivity
```
# Run MongoDB verification
sudo ./verify-mongodb.sh
```
Output yang diharapkan:
```
└─$ sudo ./verify-mongodb.sh
=== MongoDB Connectivity Test ===

Testing connection to: mongodb://10.200.239.3:27017/open5gs

Test 1: Network connectivity to 10.200.239.3:27017
✓ Port 27017 is reachable

Test 2: MongoDB authentication
Using 'mongosh' client...
{
  db: 'open5gs',
  collections: Long('3'),
  views: Long('0'),
  objects: Long('3'),
  avgObjSize: 765,
  dataSize: 2295,
  storageSize: 90112,
  indexes: Long('6'),
  indexSize: 184320,
  totalSize: 274432,
  scaleFactor: Long('1'),
  fsUsedSize: 53737484288,
  fsTotalSize: 65865187328,
  ok: 1
}

Test 3: Testing from within K3s cluster...
If you don't see a command prompt, try pressing enter.
warning: couldn't attach to pod/mongodb-test, falling back to streaming logs: Internal error occurred: unable to upgrade connection: container mongodb-test not found in pod mongodb-test_open5gs
MongoDB connection successful!
{
	"db" : "open5gs",
	"collections" : NumberLong(3),
	"views" : NumberLong(0),
	"objects" : NumberLong(3),
	"avgObjSize" : 765,
	"dataSize" : 2295,
	"storageSize" : 90112,
	"indexes" : NumberLong(6),
	"indexSize" : 184320,
	"totalSize" : 274432,
	"scaleFactor" : NumberLong(1),
	"fsUsedSize" : 53737787392,
	"fsTotalSize" : 65865187328,
	"ok" : 1
}
pod "mongodb-test" deleted
✓ MongoDB is accessible from within K3s cluster

=== Checking pod logs for MongoDB errors ===

PCF pod logs:
No errors found or pod not ready

UDR pod logs:
No errors found or pod not ready
```

## Tugas 1: Konektivitas Dasar
### Persiapkan UERANSIM pada host eksternal
```
# Di mesin yang berbeda dari K3s (atau terminal baru dengan user biasa):
cd ~/Open5GS-Testbed/ueransim
```
Modifikasi gNB config untuk connect ke K3s AMF
```
# Ubah AMF address di open5gs-gnb-k3s.yaml:
#
# amfConfigs:
#   - address: <K3s_HOST_IP>  # IP address dari K3s cluster
#     port: 38412
```
### Start gNB Simulator
```
# Terminal 1 - gNB
cd ~/Open5GS-Testbed/ueransim
./build/nr-gnb -c configs/open5gs-gnb-k3s.yaml
```
Expected output:
```
└─$ ./build/nr-gnb -c configs/open5gs-gnb-k3s.yaml
UERANSIM v3.2.7
[2025-11-26 07:14:22.702] [sctp] [info] Trying to establish SCTP connection... (10.200.239.3:38412)
[2025-11-26 07:14:22.736] [sctp] [info] SCTP connection established (10.200.239.3:38412)
[2025-11-26 07:14:22.736] [sctp] [debug] SCTP association setup ascId[3]
[2025-11-26 07:14:22.737] [ngap] [debug] Sending NG Setup Request
[2025-11-26 07:14:22.743] [ngap] [debug] NG Setup Response received
[2025-11-26 07:14:22.743] [ngap] [info] NG Setup procedure is successful
```
### Start UE Simulator
```
# Terminal 2 - UE
cd ~/Open5GS-Testbed/ueransim
sudo ./build/nr-ue -c configs/open5gs-ue-embb.yaml
```
Expected output:
```
└─$ sudo ./build/nr-ue -c configs/open5gs-ue-embb.yaml
[sudo] password for aq: 
UERANSIM v3.2.7
[2025-11-26 07:15:01.983] [nas] [info] UE switches to state [MM-DEREGISTERED/PLMN-SEARCH]
[2025-11-26 07:15:01.983] [rrc] [debug] New signal detected for cell[1], total [1] cells in coverage
[2025-11-26 07:15:01.984] [nas] [info] Selected plmn[001/01]
[2025-11-26 07:15:01.984] [rrc] [info] Selected cell plmn[001/01] tac[1] category[SUITABLE]
[2025-11-26 07:15:01.984] [nas] [info] UE switches to state [MM-DEREGISTERED/PS]
[2025-11-26 07:15:01.984] [nas] [info] UE switches to state [MM-DEREGISTERED/NORMAL-SERVICE]
[2025-11-26 07:15:01.984] [nas] [debug] Initial registration required due to [MM-DEREG-NORMAL-SERVICE]
[2025-11-26 07:15:01.984] [nas] [debug] UAC access attempt is allowed for identity[0], category[MO_sig]
[2025-11-26 07:15:01.984] [nas] [debug] Sending Initial Registration
[2025-11-26 07:15:01.985] [nas] [info] UE switches to state [MM-REGISTER-INITIATED]
[2025-11-26 07:15:01.985] [rrc] [debug] Sending RRC Setup Request
[2025-11-26 07:15:01.986] [rrc] [info] RRC connection established
[2025-11-26 07:15:01.986] [rrc] [info] UE switches to state [RRC-CONNECTED]
[2025-11-26 07:15:01.986] [nas] [info] UE switches to state [CM-CONNECTED]
[2025-11-26 07:15:02.006] [nas] [debug] Authentication Request received
[2025-11-26 07:15:02.006] [nas] [debug] Received SQN [000000000101]
[2025-11-26 07:15:02.006] [nas] [debug] SQN-MS [000000000000]
[2025-11-26 07:15:02.026] [nas] [debug] Security Mode Command received
[2025-11-26 07:15:02.026] [nas] [debug] Selected integrity[2] ciphering[0]
[2025-11-26 07:15:02.064] [nas] [debug] Registration accept received
[2025-11-26 07:15:02.064] [nas] [info] UE switches to state [MM-REGISTERED/NORMAL-SERVICE]
[2025-11-26 07:15:02.064] [nas] [debug] Sending Registration Complete
[2025-11-26 07:15:02.064] [nas] [info] Initial Registration is successful
[2025-11-26 07:15:02.064] [nas] [debug] Sending PDU Session Establishment Request
[2025-11-26 07:15:02.068] [nas] [debug] UAC access attempt is allowed for identity[0], category[MO_sig]
[2025-11-26 07:15:02.270] [nas] [debug] Configuration Update Command received
[2025-11-26 07:15:02.350] [nas] [debug] PDU Session Establishment Accept received
[2025-11-26 07:15:02.350] [nas] [info] PDU Session establishment is successful PSI[1]
[2025-11-26 07:15:02.421] [app] [info] Connection setup for PDU session[1] is successful, TUN interface[uesimtun0, 10.45.0.2] is up.
```
### Test Basic Connectivity
```
# Terminal 3 - Testing
# Test UE TUN interface
ip addr show uesimtun0

# Test gateway connectivity (UE -> UPF)
ping -I uesimtun0 -c 4 10.45.0.1

# Test internet connectivity
ping -I uesimtun0 -c 4 8.8.8.8

# Test DNS resolution
nslookup google.com 8.8.8.8

# Test HTTP/HTTPS
curl --interface uesimtun0 -I https://www.google.com
```
Expected Output
```
┌──(aq㉿omar)-[~/Open5GS/Open5GS-Testbed]
└─$ ip addr show uesimtun0
27: uesimtun0: <POINTOPOINT,PROMISC,NOTRAILERS,UP,LOWER_UP> mtu 1400 qdisc fq_codel state UNKNOWN group default qlen 500
    link/none 
    inet 10.45.0.2/24 scope global uesimtun0
       valid_lft forever preferred_lft forever
    inet6 fe80::b0cb:eb0f:cf5a:fd69/64 scope link stable-privacy proto kernel_ll 
       valid_lft forever preferred_lft forever
                                                                                                                              
┌──(aq㉿omar)-[~/Open5GS/Open5GS-Testbed]
└─$ ping -I uesimtun0 -c 4 10.45.0.2
PING 10.45.0.2 (10.45.0.2) from 10.45.0.2 uesimtun0: 56(84) bytes of data.
64 bytes from 10.45.0.2: icmp_seq=1 ttl=64 time=0.142 ms
64 bytes from 10.45.0.2: icmp_seq=2 ttl=64 time=0.057 ms
64 bytes from 10.45.0.2: icmp_seq=3 ttl=64 time=0.113 ms
64 bytes from 10.45.0.2: icmp_seq=4 ttl=64 time=0.107 ms

--- 10.45.0.2 ping statistics ---
4 packets transmitted, 4 received, 0% packet loss, time 3054ms
rtt min/avg/max/mdev = 0.057/0.104/0.142/0.030 ms
                                                                                                                              
┌──(aq㉿omar)-[~/Open5GS/Open5GS-Testbed]
└─$ ping -I uesimtun0 -c 4 8.8.8.8
PING 8.8.8.8 (8.8.8.8) from 10.45.0.2 uesimtun0: 56(84) bytes of data.
64 bytes from 8.8.8.8: icmp_seq=1 ttl=112 time=444 ms
64 bytes from 8.8.8.8: icmp_seq=2 ttl=112 time=59.0 ms
64 bytes from 8.8.8.8: icmp_seq=3 ttl=112 time=90.7 ms
64 bytes from 8.8.8.8: icmp_seq=4 ttl=112 time=205 ms

--- 8.8.8.8 ping statistics ---
4 packets transmitted, 4 received, 0% packet loss, time 3004ms
rtt min/avg/max/mdev = 59.011/199.719/443.927/151.121 ms
                                                                                                                              
┌──(aq㉿omar)-[~/Open5GS/Open5GS-Testbed]
└─$ nslookup google.com 8.8.8.8
Server:		8.8.8.8
Address:	8.8.8.8#53

Non-authoritative answer:
Name:	google.com
Address: 74.125.130.102
Name:	google.com
Address: 74.125.130.139
Name:	google.com
Address: 74.125.130.100
Name:	google.com
Address: 74.125.130.101
Name:	google.com
Address: 74.125.130.138
Name:	google.com
Address: 74.125.130.113
Name:	google.com
Address: 2404:6800:4003:c0f::8a
Name:	google.com
Address: 2404:6800:4003:c0f::66
Name:	google.com
Address: 2404:6800:4003:c0f::65
Name:	google.com
Address: 2404:6800:4003:c0f::64

                                                                                                                              
┌──(aq㉿omar)-[~/Open5GS/Open5GS-Testbed]
└─$ curl --interface uesimtun0 -I https://www.google.com
HTTP/2 200 
content-type: text/html; charset=ISO-8859-1
content-security-policy-report-only: object-src 'none';base-uri 'self';script-src 'nonce-wBKr1i-aOTN5erSJ7fva5Q' 'strict-dynamic' 'report-sample' 'unsafe-eval' 'unsafe-inline' https: http:;report-uri https://csp.withgoogle.com/csp/gws/other-hp
accept-ch: Sec-CH-Prefers-Color-Scheme
p3p: CP="This is not a P3P policy! See g.co/p3phelp for more info."
date: Wed, 26 Nov 2025 00:17:37 GMT
server: gws
x-xss-protection: 0
x-frame-options: SAMEORIGIN
expires: Wed, 26 Nov 2025 00:17:37 GMT
cache-control: private
set-cookie: AEC=AaJma5uSV9MK0XU-gcZpSKjyqZhqoJ8C5gWheUAk9G0pVAtTfMQjZs2MSgU; expires=Mon, 25-May-2026 00:17:37 GMT; path=/; domain=.google.com; Secure; HttpOnly; SameSite=lax
set-cookie: NID=526=h6uQyZ-_yIlzSvKKakyCvkw5eWNIsRMg14_7T4hAlR5U1_NKCJZO0RlU8A6DQZYLy-xQDLAVCxWyEuNYrwgnsa-cj0WQL3b1JiA1z5AerwnJLDK0akq9goR8zScRvNfGalgUNhv7bTAmLTzL0w7hkSjK7KwqJfhNUeqCXu9RHl6A2k2z_SNAjsIuOLTJCXyg1QihY9Nl5YrwWQdCZyahaHvWRt-Q; expires=Thu, 28-May-2026 00:17:37 GMT; path=/; domain=.google.com; HttpOnly
alt-svc: h3=":443"; ma=2592000,h3-29=":443"; ma=2592000
```

# Dokumentasi Hasil
## Tugas 1: Konektivitas Dasar

**Tanggal**: 17 Novermber 2025
**Nama**: Muhammad Omar Haqqi
**Status K3s**: WORKING

### gNB Registration
- Status: SUCCESS
- Time taken: 3 ms
- AMF Connection: ESTABLISHED

### UE Registration
- Status: SUCCESS
- Time taken: 54 ms
- IMSI: 001011000000001
- TUN Interface: uesimtun0
- IP Address: 10.45.0.2

### Connectivity Tests
| Test | Result | RTT (ms) |
|------|--------|----------|
| UPF Gateway (10.45.0.1) | ✓ PASS | 0.835 |
| Internet (8.8.8.8) | ✓ PASS | 27.254 |
| DNS Resolution | ✓ PASS | - |
| HTTP/HTTPS | ✓ PASS | - |

### Issues Encountered
- Saat laptop direstart atau dinyalakan lagi setelah dimatikan IP laptop akan berubah dan harus diatur ulang. Saya coba aktifkan interface tailscale0 agar dapat gunakan IP public dari tailscale yang tidak ganti-ganti tapi error (container tidak bisa update dan download dependensi saat build).
- Agak bingung menyesuaikan IMSI di MongoDB dan open5gs-ue-embb.yaml
- Sempat tidak bisa terkoneksi container ke MongoDB-nya
- Tes verify_statics_ips.sh menggunakan ping sementara di container tidak diinstall ping

### Resolution
- Belum teratasi
- Masukkan data subscriber melalui WebUI
- Mengubah mongod.conf jadi IPBind nya ke 0.0.0.0 bukan ke 127.0.0.1.
- Dockerfile semua container saya tambahkan command linux untuk install ping dan curl

# Troubleshooting
## Deploy gagal
Restart Restart MongoDB
```
sudo systemctl restart mongod
```
## Verifikasi MongoDB yang ke-3 gagal
Masuk ke MongoDB Shell di terminal yang berbeda
```
mongosh
```
