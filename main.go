wget https://dl.google.com/go/go1.21.0.linux-amd64.tar.gz
tar -zxvf go1.21.0.linux-amd64.tar.gz -C /usr/local
export GOROOT=/usr/local/go
export PATH=$PATH:$GOROOT/bin
