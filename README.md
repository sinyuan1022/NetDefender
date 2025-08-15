# System environment
Ryu Server: Ubuntu22.04<br>
Ryu Python: Python3.9<br>
Snort Server: Ubuntu22.04<br>
Snort Python: Python3.9+

## !!! # is for comments
## !!!Ryu server must be completed first
## Please connect to the internet before installing the two servers
# network environment
<img width="1019" height="637" alt="image" src="https://github.com/user-attachments/assets/3c2be482-1a8f-49ce-82ce-e933007d856f" />

# Ryu server
```bash
sudo -s

apt install git -y
git clone https://github.com/sinyuan1022/NetDefender.git
cd ./NetDefender/ryu/

bash ./ryu_install.sh
```
# Snort server
```bash
sudo -s

apt install git -y
git clone https://github.com/sinyuan1022/NetDefender.git
cd ./NetDefender/snort/

bash ./snort_install.sh
```
## Single server combines the Ryu server and the Snort server into a single server
# singel server
```bash
sudo -s

apt install git -y
git clone https://github.com/sinyuan1022/NetDefender.git
cd ./NetDefender/

bash ./singel.sh
```
