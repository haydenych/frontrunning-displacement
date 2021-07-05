from http import client
from tqdm import tqdm
from settings import *

import os
import requests
import sha3
import json
import copy

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

def relay_transactions(_prev_data, _data, _function_header):
	attacked_contract = ''
	attacked_function = ''
	error = ''

	if _function_header == None:
		if _data[:8] == 'fd6ac309':
			prev_data = _prev_data + _data[:320]
			data = _data[8:]
			relayed_contract = '0x' + data[64:128][24:64]
			relayed_contract_KECCAK256_hash = data[320:][:8]
			relayed_contract_input = data[320:]		
		else:
			prev_data = _prev_data + _data[:448]
			data = _data[8:]
			relayed_contract = '0x' + data[64:128][24:64]
			relayed_contract_KECCAK256_hash = data[448:][:8]
			relayed_contract_input = data[448:]
	else:
		cnt = 0
		data = _data[8:]
		offset = 0
		for param_type in _function_header[_function_header.index('(')+1:-1].split(','):
			curr = data[cnt * 64 + 24 : cnt * 64 + 64]
			if param_type == 'address' and curr not in _prev_data:
				relayed_contract = '0x' + curr
			elif param_type == 'bytes':
				offset += int(curr, 16) * 2 + 64
				
			cnt += 1
		
		prev_data = _prev_data + _data[:8 + offset]
		relayed_contract_KECCAK256_hash = data[offset:][:8]
		relayed_contract_input = data[offset]

		
	response = requests.get("https://api.etherscan.io/api?module=contract&action=getabi&address="+relayed_contract+"&apikey="+ETHERSCAN_API_KEY).json()
	attacked_contract = relayed_contract 
	
	if response['status'] == '1' and response['message'] == 'OK':
		function_header = _get_attacked_function(relayed_contract_KECCAK256_hash, json.loads(response['result']))
		attacked_function = function_header.split('(')[0]
		
		if attacked_function == 'execute':
			return relay_transactions(prev_data, relayed_contract_input, function_header)
		
		if attacked_function == '':
			attacked_function = 'execute'
			error = 'Failed to get attacked function from relayed transaction'
			
	else:
		attacked_function = 'execute'
		error = response['result'] # Contract source code not verified, Invalid Address Format
	
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
	error = ''
	
	if response['status'] == '1' and response['message'] == 'OK':
		function_header = _get_attacked_function(call_trace['input'][2:10], json.loads(response['result']))
		attacked_function = function_header.split('(')[0]
		if 'calls' in call_trace.keys() and attacked_function == '':
			for call in call_trace['calls']:
				if attacked_function != '':
					break
				
				if call['input'][2:10] != call_trace['input'][2:10]:
					continue
					
				attacked_contract, attacked_function, error = get_attacked_function(call)
		
	else:
		error = response['result'] # Contract source code not verified
	
	if attacked_function == '' and error == '':
		error = 'Failed to get attacked function' # Contract source code not verified implies failed to get attacked function.
	
	if attacked_function == 'execute': # aacaaf88
		return relay_transactions(call_trace['input'][:458], call_trace['input'][458:], None)
	else:
		return attacked_contract, attacked_function, error
	
def main():
	with open('displacement_results.json', 'r') as f:
		lines = f.readlines()
	
	transaction_hashes = []
	for line in lines:
		transaction_hashes.append(json.loads(line)['victim_transaction']['hash'])
		
	contracts = get_contracts(transaction_hashes)
	
	with open('attacked_functions.csv', 'a') as f:
		f.write('Transaction, Victim Sender, Victim Receiver, Attacked Contract, Attacked Function, Error\n')
	
	if not os.path.isdir('attacked_contract_source_code/'):
		os.makedirs('attacked_contract_source_code/')
	
	for tx in tqdm(contracts, desc='getting attacked functions... '):
		attacked_contract = ''
		attacked_function = ''
		contract_source_code = ''
		error = ''
		
		try:
			attacked_contract, attacked_function, error = get_attacked_function(contracts[tx])
			
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
				
			with open('attacked_functions.csv', 'a') as f:
				f.write(tx + ', ' + contracts[tx]['from'] + ', ' + contracts[tx]['to'] + ', ' + attacked_contract + ', '+ attacked_function + ', ' + error + '\n')

		except Exception as e:
			with open('error_log.txt', 'a') as f:
				f.write('Transaction: ' + tx + ' at index ' + str(transaction_hashes.index(tx)) + ', ' + str(e) + '\n')
				
	print('done')

if __name__ == "__main__":
	main()