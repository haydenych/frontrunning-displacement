from http import client
from tqdm import tqdm
from settings import *

import os
import requests
import sha3
import json
import pandas as pd

def get_transaction_trace(tx):
	data = json.dumps({'jsonrpc':'2.0', 'id': 1, 'method': 'debug_traceTransaction', 'params': [tx, {'tracer': 'callTracer'}]})
	headers = {'Content-Type': 'application/json'}

	connection = client.HTTPConnection('api.archivenode.io', 80)
	connection.request('POST', '/' + ARCHIVENODE_API_KEY + '/erigon', data, headers)
	return json.loads(connection.getresponse().read())

def get_contracts(transaction_hashes):
	contracts = {}
	if os.path.isfile('contracts_cast.json'):
		try:
			with open('contracts_cast.json', 'r') as f: 
				contracts = json.loads(f.read())
		except:
			contracts = {}
	
	for tx in tqdm(transaction_hashes, desc='getting contracts... '):
		if tx not in contracts.keys():
			response = get_transaction_trace(tx)
			contracts[tx] = response['result']
	
	with open('contracts_cast.json', 'w') as f:
		f.write(json.dumps(contracts, indent=4))
	
	return contracts

def get_components(components, type):
	s = '('
	
	for c in components:
		if 'components' in c.keys():
			s += get_components(c['components'], c['type'])
		else:
			s += c['type']
			
		s += ','
		
	if s[-1] == ',':
		s = s[:-1]
		
	s += ')'
	if type == 'tuple[]':
		s += '[]'
	
	return s

def get_function_header(func):
	s = func['name'] + '('
	
	for param in func['inputs']:
		if 'components' in param.keys():
			s += get_components(param['components'], param['type'])
		else:
			s += param['type']
			
		s += ','
	
	if s[-1] == ',':
		s = s[:-1]
		
	s += ')'
	return s


def _get_attacked_function(KECCAK256_hash, contract_abi):
	for func in contract_abi:
		if func['type'] in ['constructor', 'fallback', 'receive']:
			continue
		
		s = get_function_header(func)
		if sha3.keccak_256(s.encode('utf-8')).hexdigest()[:8] == KECCAK256_hash:
			return s
			
	return ''


def analyze_cast(data):
	num_entries = int(data[200:264], 16)
	targets = []
	datas = []
	attacked_functions = []
	
	for i in range(num_entries):
		targets.append('0x' + data[264 + 64 * i : 328 + 64 * i][24:64])
		
		start_pos = 8 + 64 * (5 + num_entries)
		offset = int(data[start_pos + 64 * i : start_pos + 64 * (i + 1)], 16) * 2
		datas.append(data[start_pos + offset + 64 : start_pos + offset + 64 + (int(data[start_pos + offset : start_pos + offset + 64], 16) * 2)])
	
	
	for i in range(num_entries):
		response = requests.get("https://api.etherscan.io/api?module=contract&action=getabi&address="+targets[i]+"&apikey="+ETHERSCAN_API_KEY).json()
		if response['status'] == '1' and response['message'] == 'OK':
			KECCAK256_hash = datas[i][:8]
			function_header = _get_attacked_function(KECCAK256_hash, json.loads(response['result']))
			attacked_function = function_header.split('(')[0]
			attacked_functions.append(attacked_function)
		
	return num_entries, targets, attacked_functions
		
	
	
	
	print(attacked_functions)
	print()
	# print(targets)
	
def get_source_code(attacked_contract):
	# Get source code of attacked contract
	response = requests.get("https://api.etherscan.io/api?module=contract&action=getsourcecode&address="+attacked_contract+"&apikey="+ETHERSCAN_API_KEY).json()
	if response['status'] == '1' and response['message'] == 'OK':
		result = response['result'][0]['SourceCode']
		if result != '':	# Contract source code verified
			if result[0] != '{':
				contract_source_code = result
				if not os.path.isfile('attacked_contract_source_code/' + attacked_contract + '.sol'):
					with open('attacked_contract_source_code/' + attacked_contract + '.sol', 'a') as f:
						f.write(contract_source_code)
						
			else:	
				# Multiple contracts in a contract address
				# Hard-coded since files have different structures.
				
				if result[0:2] == '{{':
					if not os.path.isdir('attacked_contract_source_code/' + attacked_contract + '/'):
						os.makedirs('attacked_contract_source_code/' + attacked_contract + '/')	
						
					for key in json.loads(response['result'][0]['SourceCode'][1:-1])['sources']:
						file_name = key.split('/')[-1]
						if not os.path.isfile('attacked_contract_source_code/' + attacked_contract + '/' + file_name):
							with open('attacked_contract_source_code/' + attacked_contract + '/' + file_name, 'a') as f:
								f.write(json.loads(response['result'][0]['SourceCode'][1:-1])['sources'][key]['content'])
				
				elif result[0:2] == '{\"':
					if not os.path.isdir('attacked_contract_source_code/' + attacked_contract + '/'):
						os.makedirs('attacked_contract_source_code/' + attacked_contract + '/')	
						
					for key in json.loads(response['result'][0]['SourceCode']):
						file_name = key
						if not os.path.isfile('attacked_contract_source_code/' + attacked_contract + '/' + file_name):
							with open('attacked_contract_source_code/' + attacked_contract + '/' + file_name, 'a') as f:
								f.write(json.loads(response['result'][0]['SourceCode'])[key]['content'])



def main():
	df = pd.read_csv('attacked_functions.csv', skipinitialspace = True)
	df = df[df['Attacked Function'] == 'cast']
	transaction_hashes = df['Transaction'].tolist()
	contracts = get_contracts(transaction_hashes)
	
	with open('cast.csv', 'a') as f:
		f.write('Transaction, Victim Sender, Victim Receiver, Attacked Contract, Attacked Function\n')
		
	if not os.path.isdir('attacked_contract_source_code/'):
		os.makedirs('attacked_contract_source_code/')
	
	for tx in tqdm(contracts, desc='getting attacked functions... '):
		num_entries, targets, attacked_functions = analyze_cast(contracts[tx]['input'][contracts[tx]['input'].find('e0e90acf'):])
		
		for i in range(num_entries):
			with open('cast.csv', 'a') as f:
				f.write(tx + ', ' + contracts[tx]['from'] + ', ' + contracts[tx]['to'] + ', ' + targets[i] + ', '+ attacked_functions[i] + '\n')
			get_source_code(targets[i])
		
		
		



if __name__ == "__main__":
	main()

#with pd.option_context('display.max_rows', None, 'display.max_columns', None):  # more options can be specified also
#	print(df)

# contracts = get_contracts(transaction_hashes)
		
		
		