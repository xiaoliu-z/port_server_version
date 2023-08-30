wget https://dl.google.com/go/go1.21.0.linux-amd64.tar.gz
tar -zxvf go1.21.0.linux-amd64.tar.gz -C /usr/local

/etc/profile

export GOROOT=/usr/local/go
export PATH=$PATH:$GOROOT/bin

nano ~/.profile
source ~/.profile

nano ~/.bashrc
source ~/.bashrc
