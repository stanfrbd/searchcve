#!/usr/bin/env bash

### Variables d'environnement du projet... 

ENVVIRTUEL_NOM="env-virtuel"
ENVVIRTUEL_CHEMIN="./$ENVVIRTUEL_NOM"
ENVVIRTUEL_PAQUETS="requests beautifulsoup4"

### Fonctions support 

function searchcve () { 
	python3 searchcve.py --url $1	
}

### Installation de l'environnement virtuel... 

sudo apt update &>/dev/null && sudo apt install -y python3 python3-virtualenv &>/dev/null 

[ -d $ENVVIRTUEL_CHEMIN ] || virtualenv $ENVVIRTUEL_NOM

source "./$ENVVIRTUEL_NOM/bin/activate" 

for paquet in $ENVVIRTUEL_PAQUETS
do 
	[ -z "$( pip3 list | grep $paquet )" ] && pip3 install $paquet 
done 

### Tests locaux... 

searchcve https://us-cert.cisa.gov/ncas/alerts/aa21-209a
# searchcve https://www.kennasecurity.com/blog/top-vulnerabilities-of-the-decade/
# searchcve https://arstechnica.com/gadgets/2021/07/feds-list-the-top-30-most-exploited-vulnerabilities-many-are-years-old/
# searchcve https://nvd.nist.gov/ 

