# PythonIDS 

Ethical Hacking Class Project: Python IDS 


## Setup

* Install dependencies 
    * wireshark
        * mac: brew cask install wireshark
        * Debian: sudo apt install wireshark
    * `pip3 install -r requirements.txt`


* Ensure the IP in ids_responder.py is correct
* Ensure the interface in ids.py is correct
* Run ids.py

## Pandoc compiliation
`pandoc project2.md -o project.pdf --from markdown --template eisvogel --listing --toc`
