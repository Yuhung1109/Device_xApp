# Installation guide
## How to compile IND-Box
sudo gcc main.c device_table.c device_arp_table.c -o IND-Box -lpcap -lnet -lcjson -lpthread
## How to compile OAI gNB
https://hackmd.io/@Yuhung11/Deploy_OAI

# Build 3GPP Network
## Run 5GC
## RUN OAI-CU
## RUN OAI-DU

## How to run multi-ue in a pc
Create another network namespace for ue2
```
ip netns delete ueNameSpace2
ip link delete v-eth1
ip netns add ueNameSpace2
ip link add v-eth1 type veth peer name v-ue2
ip link set v-ue2 netns ueNameSpace2
ip addr add 10.200.1.1/24 dev v-eth1  
ip link set v-eth1 up  
iptables -t nat -A POSTROUTING -s 10.200.1.0/255.255.255.0 -o <interface of DU> -j MASQUERADE  
iptables -A FORWARD -i <interface of DU> -o v-eth1 -j ACCEPT  
iptables -A FORWARD -o <interface of DU> -i v-eth1 -j ACCEPT 
ip netns exec ueNameSpace2 ip link set dev lo up   
ip netns exec ueNameSpace2 ip addr add 10.200.1.2/24 dev v-ue2
ip netns exec ueNameSpace2 ip link set v-ue2 up 
```
## RUN OAI UE1 & UE2
network namespace1 is same as OAI link above
network namespace2 is below
```
ip netns exec ueNameSpace2 bash
add ue2.conf for ue2
execute OAI UE2 as OAI link written above, but you need to update IP from 127.0.0.1 to 10.200.1.1
```

# Run Non-3GPP network
## RUN IND-Box(For IND-Type2)
```
Sudo ./IND-Box
```

## Set up GRE Tunnel in CPE(UE)
Network namespace1
```
sudo ip link add gre1 type gretap local 10.60.0.1 remote 10.60.0.99
sudo ip link set gre1 up

sudo ip link add v-gre type veth peer name v-gre2
sudo ip link set v-gre2 netns ueNameSpace2
sudo ip link set v-gre up
```
Network namespace2
```
ip netns exec ueNameSpace2 bash
ip link add gre2 type gretap local 10.60.0.2 remote 10.60.0.99
ip link set gre2 up
ip link set v-gre2 up
brctl addbr br-gre
brctl addif br-gre v-gre2
brctl addif br-gre gre2
ifconfig br-gre up
```

## Build VM & Set up Network
create two VM to simulate Non-3GPP Device
Set up network
VM1 -> gre1
VM2 -> gre2