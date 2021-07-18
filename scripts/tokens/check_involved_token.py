import json
from tqdm import tqdm

with open('displacement_results.json', 'r') as f:
	lines = f.readlines()
	
with open('tokens.json', 'r') as f:
	tokens = json.loads(f.read())

with open('results.csv', 'a') as f:
	f.write('Transaction, Token Contract, Token Address\n')
	
for line in tqdm(lines):
	line = json.loads(line)
	for token in tokens:
		if token[2:] in (line['victim_transaction']['input'] or line['victim_transaction']['to']):
			with open('results.csv', 'a') as f:
				f.write(line['victim_transaction']['hash'] + ', ' + token + ', ' + tokens[token] + '\n')
			
