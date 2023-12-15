import requests
import random
import re
import json

class API:
    def __init__(self, key : str, host : str = 'urlscan.io', protocol : str = 'https://', port : int = 443, privacy : str = 'private', verify : bool = False, proxies : dict = None, pagination_limit : int = 5, search_limit : int = 10000, debug : bool = False):
        self.session = requests.Session()
        self.protocol = protocol
        self.host = host
        self.port = port
        self.session.verify = verify
        self.session.proxies = proxies
        self.session.headers = {'Content-Type':'application/json','API-Key':key}
        self.pagination_limit=pagination_limit
        self.search_limit = search_limit
        self.debug = debug
        self.countries = list(filter(lambda code : code.upper(),["de","us","jp","fr","gb","nl","ca","it","es","se","fi","dk","no","is","au","nz","pl","sg","ge","pt","at","ch"]))

    def __results(self, method, path, json_payload):
        try:
            if 'http' in path and '://' in path:
                full_url = path
            else:
                full_url = self.protocol + self.host + ':'+str(self.port) + path.strip()
        except Exception as e:
            print("Error:")
            print(type(e))
            print(str(e))
        finally:
            if self.debug:
                print(f'Attempted {method} to path {path} with data {json_payload}')
        response =  self.session.request(method, full_url, json=json_payload)
        if response.json().get('has_more') and '/search/' in full_url:
            full_results = {'results':[]}
            for iteration in range(0,self.pagination_limit):   
                oldest_item = re.sub(r'[\'\s\[\]]','',str(response.json()['results'][-1]['sort']))
                full_url = re.sub(r'\&search_after=\d+\,[a-f0-9]{8}\-[a-f0-9]{4}\-[a-f0-9]{4}\-[a-f0-9]{4}\-[a-f0-9]{12}','',response.url)
                full_url = full_url+'&search_after='+oldest_item
                method='GET'
                response=self.session.request(method,full_url,json=None)
                if response.status_code==200:
                    full_results['results'] = full_results['results'] + response.json()['results']
                else:
                    print(response.json())
                    break
                if iteration==(self.pagination_limit-1):
                    print('Max pagination hit')
                    if response.json().get('has_more'):
                        print('Change the "urlscan_pagination_limit"s variable to increase the number of iterations to get results')
                        print(f'Current ({self.pagination_limit})')
                        print("There are more results in the URLScan.io portal!")
    
            final_response = response #only hte most recent response attributes
            final_response._content = json.dumps(full_results).encode('utf-8') #change content to aggregated of all responses.json()['results']
            return final_response
        else:
            return response

    def __parse_options(self, options : list):
        parsed_options = []
        for option in options:
            try:
                if '=' in option:
                    cOption = list(filter(option.split('='),None))
                    parsed_options.append((str(cOption[0].replace('--','')).strip().lower(),str(cOption[1]).strip()))
                else:
                    parsed_options.append((cOption[0],None))
            except Exception as e:
                print(f'Option {option} not parsed') 
                pass
        return parsed_options

    def scan(self, data : str, country_code : str = "US", custom_ua : str = None, custom_ref : str = None):
        """{"switches":["-p"],"polling_endpoint":"result","polling_data":"uuid"}"""
        print(f'{self.scan.__name__} called on: {str(data).replace("http","meow")}')
        path = f'/api/v1/scan/'
        method='POST'
        payload={'url':data}
        payload.update({'country':country_code[:2]})
        if custom_ref:
            payload.update({'referer':custom_ref[:1024]})
        if custom_ua:
            payload.update({'customagent':custom_ua[:1024]})
        return self.__results(method, path, json_payload=payload)

    def search(self, data : str):
        """{"switches":[]}"""
        print(f'{self.search.__name__} called on: {data}')
        path = f'/api/v1/search/?q={data}&size={str(self.search_limit)}'
        method = 'GET'
        payload = None
        return self.__results(method, path, json_payload=payload)
    
    def visual_search(self, data : str):
        """{"switches":[]}"""
        print(f'{self.visual_search.__name__} called on {data}')
        path=f'/api/v1/search/?q=visual%3Aminscore-1650%7C{data}&size={str(self.search_limit)}' 
        method = 'GET'
        payload = None
        return self.__results(method, path, json_payload=payload)

    def result(self, data : str):
        """{"switches":[]}"""
        print(f'{self.result.__name__} called on: {data}')
        path = f'/api/v1/result/{data}/'
        method = 'GET'
        payload = None
        return self.__results(method, path, json_payload=payload)
    
    def dom_search(self, data:str):
        print(f'{self.dom_search.__name__} sent with {data}')
        """{"switches":[]}"""
        path=f'/api/v1/pro/result/{data}/similar/'
        method = 'GET'
        payload = None
        return self.__results(method, path, json_payload=payload)
        
    def get_screenshot(self, data : str):
        """{"switches":["-q"],"display":true}"""
        print(f'{self.get_screenshot.__name__} sent with {data}')
        path = f'/screenshots/{data}.png'
        method = 'GET'
        payload = None
        return self.__results(method, path, json_payload=payload)
    
    def get_dom(self, data : str):
        """{"switches":[]}"""
        print(f'{self.get_dom.__name__} called on: {data}')
        path = f'/dom/{data}/'
        method='GET'
        payload=None
        return self.__results(method, path, json_payload=payload)
    
    def get_redirect(self, url):
        """{"switches":[]}"""
        print(f'{self.get_redirect.__name__} called on: {url}')
        method = 'GET'
        payload = None
        return self.__results(method, url, json_payload=payload)