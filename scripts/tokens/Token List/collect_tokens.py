from bs4 import BeautifulSoup
import json

f = open('tokens.txt', 'r')

soup = BeautifulSoup(f, 'html.parser')
tokens = {}
for link in soup.find_all('a'):
	if link.get('href')[:9] == '/token/0x':
		tokens[str(link.get('href')).split('/')[-1]] = str(link).split('>')[-2].split('<')[0]
	
with open('tokens.json', 'w') as f:
	f.write(json.dumps(tokens, indent=4))