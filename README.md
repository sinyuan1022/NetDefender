# System environment
Ryu Server: Ubuntu22.04<br>
Ryu Python: Python3.9<br>
Snort Server: Ubuntu22.04<br>
Snort Python: Python3.9+

## !!! # is for comments
# Ryu server
```bash
sudo -s

apt install git -y
git clone https://github.com/sinyuan1022/NetDefender.git
cd ./NetDefender/ryu/

bash ./ryu_install.bash
```
# Snort server
```bash
sudo -s

apt install git -y
git clone https://github.com/sinyuan1022/NetDefender.git
cd ./NetDefender/snort/

bash ./snort_install.bash
```
