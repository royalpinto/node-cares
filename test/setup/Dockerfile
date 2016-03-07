FROM    centos:centos6

# Enable Extra Packages for Enterprise Linux (EPEL) for CentOS
RUN     yum install -y epel-release

# Install Node.js and npm
RUN     yum install -y nodejs npm

RUN	npm install native-dns

# Install app dependencies
COPY dummydns.js /src/dummydns.js
COPY dnsentries.js /src/dnsentries.js


EXPOSE  8080


CMD ["node", "/src/dummydns.js"]

