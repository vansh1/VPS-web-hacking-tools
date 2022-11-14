#!/bin/bash -i
#Check if the script is executed with root privileges
if [ "$EUID" -ne 0 ]
  then echo -e ${RED}"Please execute this script with root privileges !"
  exit
fi

#Creating tools directory if not exist
source ./.env && mkdir -p $TOOLS_DIRECTORY;
clear;

ENVIRONMENT () {
	echo -e ${BLUE}"[ENVIRONMENT]" ${RED}"Packages required installation in progress ...";
	#Check Operating System
	OS=$(lsb_release -i 2> /dev/null | sed 's/:\t/:/' | cut -d ':' -f 2-)
	if [ "$OS" == "Debian" ] || [ "$OS" == "Linuxmint" ]; then
		#Specific Debian
		#chromium
		apt-get update -y > /dev/null 2>&1;
		apt-get install chromium python python3 python3-pip unzip make gcc libpcap-dev curl build-essential libcurl4-openssl-dev libxml2 libxml2-dev libxslt1-dev ruby-dev ruby libgmp-dev zlib1g-dev -y > /dev/null 2>&1;
		cd /tmp && curl https://bootstrap.pypa.io/pip/2.7/get-pip.py --output get-pip.py > /dev/null 2>&1 && python2 get-pip.py > /dev/null 2>&1;
	elif [ "$OS" == "Ubuntu" ]; then
		#Specific Ubuntu
		#Specificity : chromium-browser replace chromium
        apt-get update -y > /dev/null 2>&1
        apt-get install chromium-browser python python3 python3-pip unzip make gcc libpcap-dev curl build-essential libcurl4-openssl-dev libxml2 libxml2-dev libxslt1-dev ruby-dev ruby libgmp-dev zlib1g-dev -y > /dev/null 2>&1;
        cd /tmp && curl https://bootstrap.pypa.io/pip/2.7/get-pip.py --output get-pip.py > /dev/null 2>&1 && python2 get-pip.py > /dev/null 2>&1;
	elif [ "$OS" == "Kali" ]; then
		#Specific Kali Linux
		#Specificity : no package name with "python"
        apt-get update -y > /dev/null 2>&1;
        apt-get install chromium python3 python3-pip unzip make gcc libpcap-dev curl build-essential libcurl4-openssl-dev libxml2 libxml2-dev libxslt1-dev ruby-dev ruby libgmp-dev zlib1g-dev -y > /dev/null 2>&1;
        cd /tmp && curl https://bootstrap.pypa.io/pip/2.7/get-pip.py --output get-pip.py > /dev/null 2>&1 && python2 get-pip.py > /dev/null 2>&1;
        pip install -U setuptools > /dev/null 2>&1;
        #Needed for NoSQLMap
        pip install couchdb pbkdf2 pymongo ipcalc > /dev/null 2>&1;    
	else
        echo "OS unrecognized. Please check the compatibility with your system.";
        echo "End of the script";
        exit;
	fi
unset OS
	#Bash colors
	sed -i '/^#.*force_color_prompt/s/^#//' ~/.bashrc && source ~/.bashrc
	echo -e ${BLUE}"[ENVIRONMENT]" ${GREEN}"Packages required installation is done !"; echo "";
	#Generic fot both OS - Golang environment
	echo -e ${BLUE}"[ENVIRONMENT]" ${RED}"Golang environment installation in progress ...";
	cd /tmp && curl -O https://dl.google.com/go/go$GOVER.linux-amd64.tar.gz > /dev/null 2>&1 && tar xvf go$GOVER.linux-amd64.tar.gz > /dev/null 2>&1 && mv go /usr/local && echo "export PATH=$PATH:/usr/local/go/bin" >> ~/.bashrc && source ~/.bashrc;
	echo -e ${BLUE}"[ENVIRONMENT]" ${GREEN}"Golang environment installation is done !"; echo "";
}

SUBDOMAINS_ENUMERATION () {
	#Subfinder
	echo -e ${BLUE}"[SUBDOMAINS ENUMERATION]" ${RED}"Subfinder installation in progress ...";
	GO111MODULE=on go get -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder > /dev/null 2>&1 && ln -s ~/go/bin/subfinder /usr/local/bin/;
	echo -e ${BLUE}"[SUBDOMAINS ENUMERATION]" ${GREEN}"Subfinder installation is done !"; echo "";
	#Assetfinder
	echo -e ${BLUE}"[SUBDOMAINS ENUMERATION]" ${RED}"Assetfinder installation in progress ...";
	go get -u github.com/tomnomnom/assetfinder > /dev/null 2>&1 && ln -s ~/go/bin/assetfinder /usr/local/bin/;
	echo -e ${BLUE}"[SUBDOMAINS ENUMERATION]" ${GREEN}"Assetfinder installation is done !"; echo "";
	#Findomain
	echo -e ${BLUE}"[SUBDOMAINS ENUMERATION]" ${RED}"Findomain installation in progress ...";
	cd /tmp && wget https://github.com/Edu4rdSHL/findomain/releases/latest/download/findomain-linux > /dev/null 2>&1 && chmod +x findomain-linux && mv ./findomain-linux /usr/local/bin/findomain;
	echo -e ${BLUE}"[SUBDOMAINS ENUMERATION]" ${GREEN}"Findomain installation is done !"; echo "";
	#Github-subdomains
	echo -e ${BLUE}"[SUBDOMAINS ENUMERATION]" ${RED}"Github-subdomains installation in progress ...";
	go get -u github.com/gwen001/github-subdomains > /dev/null 2>&1 && ln -s ~/go/bin/github-subdomains /usr/local/bin/;
	echo -e ${BLUE}"[SUBDOMAINS ENUMERATION]" ${GREEN}"Github-subdomains installation is done !"; echo "";
	#Amass
	echo -e ${BLUE}"[SUBDOMAINS ENUMERATION]" ${RED}"Amass installation in progress ...";
	cd /tmp && wget https://github.com/OWASP/Amass/releases/download/v$AMASSVER/amass_linux_amd64.zip > /dev/null 2>&1 && unzip amass_linux_amd64.zip > /dev/null 2>&1 && mv amass_linux_amd64/amass /usr/local/bin/;
	echo -e ${BLUE}"[SUBDOMAINS ENUMERATION]" ${GREEN}"Amass installation is done !"; echo "";
}

DNS_RESOLVER () {
	#PureDNS
	echo -e ${BLUE}"[DNS RESOLVER]" ${RED}"PureDNS installation in progress ...";
	GO111MODULE=on go get github.com/d3mondev/puredns/v2 > /dev/null 2>&1 && ln -s ~/go/bin/puredns /usr/local/bin;
	echo -e ${BLUE}"[DNS RESOLVER]" ${GREEN}"PureDNS installation is done !"; echo "";
}

VISUAL_RECON () {
	#Aquatone
	echo -e ${BLUE}"[VISUAL RECON]" ${RED}"Aquatone installation in progress ...";
	cd /tmp && wget https://github.com/michenriksen/aquatone/releases/download/v$AQUATONEVER/aquatone_linux_amd64_$AQUATONEVER.zip > /dev/null 2>&1 && unzip aquatone_linux_amd64_$AQUATONEVER.zip > /dev/null 2>&1 && mv aquatone /usr/local/bin/;
	echo -e ${BLUE}"[VISUAL RECON]" ${GREEN}"Aquatone installation is done !"; echo "";
	#Gowitness
	echo -e ${BLUE}"[VISUAL RECON]" ${RED}"Gowitness installation in progress ...";
	cd /tmp && wget https://github.com/sensepost/gowitness/releases/download/$GOWITNESSVER/gowitness-$GOWITNESSVER-linux-amd64 > /dev/null 2>&1 && mv gowitness-$GOWITNESSVER-linux-amd64 /usr/local/bin/gowitness && chmod +x /usr/local/bin/gowitness;
	echo -e ${BLUE}"[VISUAL RECON]" ${GREEN}"Gowitness installation is done !"; echo "";
}

HTTP_PROBE () {
	#httpx
	echo -e ${BLUE}"[HTTP PROBE]" ${RED}"httpx installation in progress ...";
	GO111MODULE=on go get -v github.com/projectdiscovery/httpx/cmd/httpx > /dev/null 2>&1 && ln -s ~/go/bin/httpx /usr/local/bin/;
	echo -e ${BLUE}"[HTTP PROBE]" ${GREEN}"Httpx installation is done !"; echo "";
	#httprobe
	echo -e ${BLUE}"[HTTP PROBE]" ${RED}"httprobe installation in progress ...";
	go get -u github.com/tomnomnom/httprobe > /dev/null 2>&1 && ln -s ~/go/bin/httprobe /usr/local/bin/;
	echo -e ${BLUE}"[HTTP PROBE]" ${GREEN}"httprobe installation is done !"; echo "";
}

NETWORK_SCANNER () {
	#Nmap
	echo -e ${BLUE}"[NETWORK SCANNER]" ${RED}"Nmap installation in progress ...";
	apt-get install nmap -y > /dev/null 2>&1;
	echo -e ${BLUE}"[NETWORK SCANNER]" ${GREEN}"Nmap installation is done !"; echo "";
}

HTTP_PARAMETER () {
	#Arjun
	echo -e ${BLUE}"[HTTP PARAMETER DISCOVERY]" ${RED}"Arjun installation in progress ...";
	pip3 install arjun > /dev/null 2>&1;
	echo -e ${BLUE}"[HTTP PARAMETER DISCOVERY]" ${GREEN}"Arjun installation is done !"; echo "";
}

FUZZING_TOOLS () {
	#ffuf
	echo -e ${BLUE}"[FUZZING TOOLS]" ${RED}"ffuf installation in progress ...";
	go get -u github.com/ffuf/ffuf > /dev/null 2>&1 && ln -s ~/go/bin/ffuf /usr/local/bin/;
	echo -e ${BLUE}"[FUZZING TOOLS]" ${GREEN}"ffuf installation is done !"; echo "";
}

WORDLISTS () {
	#SecLists
	echo -e ${BLUE}"[WORDLISTS]" ${RED}"SecLists installation in progress ...";
	cd $TOOLS_DIRECTORY && git clone https://github.com/danielmiessler/SecLists.git > /dev/null 2>&1;
	echo -e ${BLUE}"[WORDLISTS]" ${GREEN}"SecLists installation is done !"; echo "";
}

VULNS_SQLI () {
	#SQLmap
	echo -e ${BLUE}"[VULNERABILITY - SQL Injection]" ${RED}"SQLMap installation in progress ...";
	apt-get install -y sqlmap > /dev/null 2>&1
	echo -e ${BLUE}"[VULNERABILITY - SQL Injection]" ${GREEN}"SQLMap installation is done !"; echo "";
}

CMS_SCANNER () {
	#WPScan
	echo -e ${BLUE}"[CMS SCANNER]" ${RED}"WPScan  installation in progress ...";
	gem install wpscan > /dev/null 2>&1;
	echo -e ${BLUE}"[CMS SCANNER]" ${GREEN}"WPScan installation is done !"; echo "";
}

VULNS_SCANNER () {
	#Nuclei + nuclei templates
	echo -e ${BLUE}"[VULNERABILITY SCANNER]" ${RED}"Nuclei installation in progress ...";
	GO111MODULE=on go get -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei > /dev/null 2>&1 && ln -s ~/go/bin/nuclei /usr/local/bin/;
	nuclei -update-templates > /dev/null 2>&1;
	echo -e ${BLUE}"[VULNERABILITY SCANNER]" ${GREEN}"Nuclei installation is done !"; echo "";
	#Nikto
	echo -e ${BLUE}"[VULNERABILITY SCANNER]" ${RED}"Nikto installation in progress ...";
	apt-get install -y nikto > /dev/null 2>&1;
	echo -e ${BLUE}"[VULNERABILITY SCANNER]" ${GREEN}"Nikto installation is done !"; echo "";
}

JS_HUNTING () {
	#Linkfinder
	echo -e ${BLUE}"[JS FILES HUNTING]" ${RED}"Linkfinder installation in progress ...";
	cd $TOOLS_DIRECTORY && git clone https://github.com/GerbenJavado/LinkFinder.git > /dev/null 2>&1 && cd LinkFinder && pip3 install -r requirements.txt > /dev/null 2>&1 && python3 setup.py install > /dev/null 2>&1;
	echo -e ${BLUE}"[JS FILES HUNTING]" ${GREEN}"Linkfinder installation is done !"; echo "";
	#SecretFinder
	echo -e ${BLUE}"[JS FILES HUNTING]" ${RED}"SecretFinder installation in progress ...";
	cd $TOOLS_DIRECTORY && git clone https://github.com/m4ll0k/SecretFinder.git > /dev/null 2>&1 && cd SecretFinder && pip3 install -r requirements.txt > /dev/null 2>&1;
	echo -e ${BLUE}"[JS FILES HUNTING]" ${GREEN}"SecretFinder installation is done !"; echo "";
	#subjs
	echo -e ${BLUE}"[JS FILES HUNTING]" ${RED}"subjs installation in progress ...";
	go get -u github.com/lc/subjs > /dev/null 2>&1 && ln -s ~/go/bin/subjs /usr/local/bin/;
	echo -e ${BLUE}"[JS FILES HUNTING]" ${GREEN}"subjs installation is done !"; echo "";
}

SENSITIVE_FINDING() {
	#DumpsterDiver
	echo -e ${BLUE}"[SENSITIVE FINDING TOOLS]" ${RED}"gitGraber installation in progress ...";
	cd $TOOLS_DIRECTORY && git clone https://github.com/securing/DumpsterDiver.git > /dev/null 2>&1 && cd DumpsterDiver && pip3 install -r requirements.txt > /dev/null 2>&1;
	echo -e ${BLUE}"[SENSITIVE FINDING TOOLS]" ${GREEN}"gitGraber installation is done !"; echo "";
	#EarlyBird
	echo -e ${BLUE}"[SENSITIVE FINDING TOOLS]" ${RED}"EarlyBird installation in progress ...";
	cd $TOOLS_DIRECTORY && git clone https://github.com/americanexpress/earlybird.git > /dev/null 2>&1 && cd earlybird && ./build.sh > /dev/null 2>&1 && ./install.sh > /dev/null 2>&1;
	echo -e ${BLUE}"[SENSITIVE FINDING TOOLS]" ${GREEN}"EarlyBird installation is done !"; echo "";
	#Ripgrep
	echo -e ${BLUE}"[SENSITIVE FINDING TOOLS]" ${RED}"Ripgrep installation in progress ...";
	apt-get install -y ripgrep > /dev/null 2>&1
	echo -e ${BLUE}"[SENSITIVE FINDING TOOLS]" ${GREEN}"Ripgrep installation is done !" ${RESTORE}; echo "";
}

USEFUL_TOOLS () {
	#getallurls
	echo -e ${BLUE}"[USEFUL TOOLS]" ${RED}"getallurls installation in progress ...";
	GO111MODULE=on go get -u -v github.com/lc/gau > /dev/null 2>&1 && ln -s ~/go/bin/gau /usr/local/bin/;
	echo -e ${BLUE}"[USEFUL TOOLS]" ${GREEN}"getallurls installation is done !"; echo "";
	#unfurl
	echo -e ${BLUE}"[USEFUL TOOLS]" ${RED}"unfurl installation in progress ...";
	go get -u github.com/tomnomnom/unfurl > /dev/null 2>&1 && ln -s ~/go/bin/unfurl /usr/local/bin/;
	echo -e ${BLUE}"[USEFUL TOOLS]" ${GREEN}"unfurl installation is done !"; echo "";
	#anew
	echo -e ${BLUE}"[USEFUL TOOLS]" ${RED}"anew installation in progress ...";
	go get -u github.com/tomnomnom/anew > /dev/null 2>&1 && ln -s ~/go/bin/anew /usr/local/bin/;
	echo -e ${BLUE}"[USEFUL TOOLS]" ${GREEN}"anew installation is done !"; echo "";
	#qsreplace
	echo -e ${BLUE}"[USEFUL TOOLS]" ${RED}"qsreplace installation in progress ...";
	go get -u github.com/tomnomnom/qsreplace > /dev/null 2>&1 && ln -s ~/go/bin/qsreplace /usr/local/bin/;
	echo -e ${BLUE}"[USEFUL TOOLS]" ${GREEN}"qsreplace installation is done !"; echo "";
	#Interlace
	echo -e ${BLUE}"[USEFUL TOOLS]" ${RED}"Interlace installation in progress ...";
	cd $TOOLS_DIRECTORY && git clone https://github.com/codingo/Interlace.git > /dev/null 2>&1 && cd Interlace && python3 setup.py install > /dev/null 2>&1;
	echo -e ${BLUE}"[USEFUL TOOLS]" ${GREEN}"Interlace installation is done !"; echo "";
	#Uro
	echo -e ${BLUE}"[USEFUL TOOLS]" ${RED}"Uro installation in progress ...";
	pip3 install uro > /dev/null 2>&1;
	echo -e ${BLUE}"[USEFUL TOOLS]" ${GREEN}"Uro installation is done !" ${RESTORE}; echo "";
}

ENVIRONMENT && SUBDOMAINS_ENUMERATION && DNS_RESOLVER && VISUAL_RECON && HTTP_PROBE && NETWORK_SCANNER && HTTP_PARAMETER && FUZZING_TOOLS && WORDLISTS && VULNS_SQLI && CMS_SCANNER && VULNS_SCANNER && JS_HUNTING  && SENSITIVE_FINDING && USEFUL_TOOLS;
