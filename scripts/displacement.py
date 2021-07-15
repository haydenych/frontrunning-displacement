from http import client
from tqdm import tqdm
from datetime import datetime
from settings import *

import os
import requests
import sha3
import json
import copy
import pymongo
import pandas as pd

def get_transaction_trace(tx):
	data = json.dumps({'jsonrpc':'2.0', 'id': 1, 'method': 'debug_traceTransaction', 'params': [tx, {'tracer': 'callTracer'}]})
	headers = {'Content-Type': 'application/json'}

	connection = client.HTTPConnection('api.archivenode.io', 80)
	connection.request('POST', '/' + ARCHIVENODE_API_KEY + '/erigon', data, headers)
	return json.loads(connection.getresponse().read())
	
def get_contracts(transaction_hashes):
	contracts = {}
	if os.path.isfile('contracts.json'):
		try:
			with open('contracts.json', 'r') as f: 
				contracts = json.loads(f.read())
		except:
			contracts = {}
	
	for tx in tqdm(transaction_hashes, desc='getting contracts... '):
		if tx not in contracts.keys():
			response = get_transaction_trace(tx)
			contracts[tx] = response['result']
	
	with open('contracts.json', 'w') as f:
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
	if type[:5] == 'tuple':
		for _ in range(type.count('[]')):
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


def relay_transactions(_data):
	attacked_contract = ''
	attacked_function = ''
	error = ''
	
	if _data[:8] == 'fd6ac309':		# callContract(address,address,uint256,bytes)
		contract = '0x' + _data[72:136][24:64]
		KECCAK256_hash = _data[328:][:8]
		data = _data[328:]
	elif _data[:8] == 'd5e69ee9':	# approveTokenAndCallContract(address,address,address,uint256,address,bytes)
		contract = '0x' + _data[264:328][24:64]
		KECCAK256_hash = _data[456:][:8]
		data = _data[456:]
	elif _data[:8] == '09d22c8e':	# approveTokenAndCallContract(address,address,address,uint256,bytes)
		contract = '0x' + _data[136:200][24:64]
		KECCAK256_hash = _data[392:][:8]
		data = _data[392:]
	elif _data[:8] == '2df546f4':	# transferToken(address,address,address,uint256,bytes) 
		contract = '0x' + _data[136:200][24:64]
		KECCAK256_hash = _data[456:][:8]
		data = _data[456:]
	elif _data[:8] == '1cff79cd':	# execute(address,bytes)
		contract = '0x' + _data[8:72][24:64]
		KECCAK256_hash = _data[200:][:8]
		data = _data[200:]
	elif _data[:8] == 'f3541901':	# execute(address,bytes,uint256,uint256)
		contract = '0x' + _data[8:72][24:64]
		KECCAK256_hash = _data[328:][:8]
		data = _data[328:]

	response = requests.get("https://api.etherscan.io/api?module=contract&action=getabi&address="+contract+"&apikey="+ETHERSCAN_API_KEY).json()
	attacked_contract = contract 
	
	if response['status'] == '1' and response['message'] == 'OK':
		function_header = _get_attacked_function(KECCAK256_hash, json.loads(response['result']))
		attacked_function = function_header.split('(')[0]
		
		if attacked_function == 'execute': 	# 1cff79cd / f3541901
			return relay_transactions(data)

		elif attacked_function == '':
			attacked_function = 'execute'
			error = '1: Failed to get attacked function (' + KECCAK256_hash + ') from relayed transaction'
			
	else:
		attacked_function = 'execute'
		error = '2: ' + response['result'] + ' (' + contract + ')' # Contract source code not verified, Invalid Address Format
	
	return attacked_contract, attacked_function, error

def _get_attacked_function(KECCAK256_hash, contract_abi):
	for func in contract_abi:
		if func['type'] in ['constructor', 'fallback', 'receive']:
			continue
		
		s = get_function_header(func)
		if sha3.keccak_256(s.encode('utf-8')).hexdigest()[:8] == KECCAK256_hash:
			return s
			
	return ''
	
def get_attacked_function(call_trace):
	response = requests.get("https://api.etherscan.io/api?module=contract&action=getabi&address="+call_trace['to']+"&apikey="+ETHERSCAN_API_KEY).json()
	attacked_contract = call_trace['to']
	attacked_function = ''
	KECCAK256_hash = call_trace['input'][2:10]
	error = ''
	
	if response['status'] == '1' and response['message'] == 'OK':
		if KECCAK256_hash == 'aacaaf88':
			return relay_transactions(call_trace['input'][458:])
		elif KECCAK256_hash == '1cff79cd':
			return relay_transactions(call_trace['input'][2:])
		else:
			function_header = _get_attacked_function(KECCAK256_hash, json.loads(response['result']))
			attacked_function = function_header.split('(')[0]

			if 'calls' in call_trace.keys() and attacked_function == '':
				for call in call_trace['calls']:
					if attacked_function != '':
						break
					
					if call['input'][2:10] != call_trace['input'][2:10]:
						continue
						
					attacked_contract, attacked_function, error = get_attacked_function(call)

	else:
		error = '3: ' + response['result'] + ' (' + attacked_contract + ')'  # Contract source code not verified
	
	if attacked_function == '' and error == '':
		error = '4: Failed to get attacked function (' + KECCAK256_hash + ')' # Contract source code not verified implies failed to get attacked function.
	
	return attacked_contract, attacked_function, error

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
	
	client = pymongo.MongoClient("mongodb://"+MONGO_HOST+":"+str(MONGO_PORT))
	mongo_collection = client['front_running']['displacement']
	
	with open('displacement_results.json', 'r') as f:
		lines = f.readlines()
	
	transaction_hashes = []
	for line in lines:
		transaction_hashes.append(json.loads(line)['victim_transaction']['hash'])
	
	
	#################################### debug ####################################
	if debug:
		transaction_hashes = transaction_hashes[start_tx:end_tx]
	#################################### debug ####################################

	contracts = get_contracts(transaction_hashes)
	
	#################################### debug ####################################
	if debug:
		_contracts = copy.deepcopy(contracts)
		for key in _contracts:
			if key not in transaction_hashes:
				del contracts[key]
	#################################### debug ####################################
	
	if not os.path.isdir('attacked_contract_source_code/'):
		os.makedirs('attacked_contract_source_code/')
	
	for tx in tqdm(contracts, desc='getting attacked functions... '):
		
		if only_error and len(list(mongo_collection.find({'_id': tx}))) > 0:
			if mongo_collection.find({'_id': tx})[0]['Error'] == '':
				continue
		
		attacked_contract = ''
		attacked_function = ''
		contract_source_code = ''
		error = ''
		
		try:
			attacked_contract, attacked_function, error = get_attacked_function(contracts[tx])
			
			record = {}
			record['_id'] = tx
			record['Transaction'] = tx
			record['Victim Sender'] = contracts[tx]['from']
			record['Victim Receiver'] = contracts[tx]['to']
			record['Attacked Contract'] = attacked_contract
			record['Attacked Function'] = attacked_function
			record['Error'] = error
			
			old_record = list(mongo_collection.find({'_id': tx}))
			if len(old_record) == 0:
				with open('log.txt', 'a') as f:
					f.write(datetime.now().strftime("%d/%m/%Y %H:%M:%S") + '\n')
					f.write('New record: ' + json.dumps(record) + '\n\n') 
				mongo_collection.insert_one(record)
			else:
				if record != old_record[0]:
					with open('log.txt', 'a') as f:
						f.write(datetime.now().strftime("%d/%m/%Y %H:%M:%S") + '\n')
						f.write('New record: ' + json.dumps(record) + '\n\nOld record: ' + json.dumps(old_record[0]) + '\n\n\n')
					result = mongo_collection.replace_one(old_record[0], record)
			
			get_source_code(attacked_contract)

		except Exception as e:
			with open('error_log.txt', 'a') as f: 
				f.write('Transaction: ' + tx + ' at index ' + str(transaction_hashes.index(tx)) + ', ' + str(e) + '\n')
	
	df = pd.DataFrame(list(mongo_collection.find()))
	df.to_csv('attacked_functions.csv', sep=',', index=False)
	with open('attacked_functions.csv', 'rt') as f:
		csv = f.read()
	with open('attacked_functions.csv', 'wt') as f:
		f.write(csv.replace(',', ', '))
	print('done')

if __name__ == "__main__":
	main()
	
	