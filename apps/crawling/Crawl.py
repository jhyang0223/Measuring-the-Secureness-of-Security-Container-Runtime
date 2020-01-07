import requests
from bs4 import BeautifulSoup

if __name__ == "__main__":
    #get html file of cve data (mitre)
    dataSet = requests.get("https://cve.mitre.org/data/downloads/allitems.html")
    
    print(dataSet.content)

    soup = BeautifulSoup(dataSet.content, 'html.parser')

        


