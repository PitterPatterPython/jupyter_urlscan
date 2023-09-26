import requests
import random

class API:
    def __init__(self, key : str, host : str = 'urlscan.io', protocol : str = 'https://', port : int = 443, privacy : str = 'private', verify : bool = False, proxies : dict = None, debug : bool = False):
        self.session = requests.Session()
        self.protocol = protocol
        self.host = host
        self.port = port
        self.session.verify = verify
        self.session.proxies = proxies
        self.session.headers = {'Content-Type':'application/json','API-Key':key}
        self.debug = debug
        self.countries = list(filter(lambda code : code.upper(),["de","us","jp","fr","gb","nl","ca","it","es","se","fi","dk","no","is","au","nz","pl","sg","ge","pt","at","ch"]))

    def __results(self, method, path, json):
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
                print(f'Attempted {method} to path {path} with data {json}')
        return self.session.request(method, full_url, json=json)

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
        """{"switches":["-q","-p"],"polling_endpoint":"result","polling_data":"uuid"}"""
        print(f'{self.scan.__name__} called on: {data}')
        path = f'/api/v1/scan/'
        method='POST'
        payload={'url':data}
        payload.udpate({'country_code':country_code[:2]})
        if custom_ref:
            payload.update({'referer':custom_ref[:1024]})
        if custom_ua:
            payload.update({'user_agent':custom_ua[:1024]})
        return self.__results(method, path, json=payload)

    def search(self, data : str):
        """{"switches":[]}"""
        print(f'{self.search.__name__} called on: {data}')
        path = f'/api/v1/search/?q={data}'
        method = 'GET'
        payload = None
        return self.__results(method, path, json=payload)
    
    def visual_search(self, data : str):
        """{"switches":[]}"""
        print(f'{self.visual_search.__name__} called on {data}')
        path=f'/api/v1/search/?q=visual%3Aminscore-1650%7C{data}' 
        method = 'GET'
        payload = None
        return self.__results(method, path, json=payload)

    def result(self, data : str):
        """{"switches":[]}"""
        print(f'{self.result.__name__} called on: {data}')
        path = f'/api/v1/result/{data}/'
        method = 'GET'
        payload = None
        return self.__results(method, path, json=payload)
    
    def dom_search(self, data:str):
        print(f'{self.dom_search.__name__} sent with {data}')
        """{"switches":[]}"""
        path=f'/api/v1/pro/result/{data}/similar/'
        method = 'GET'
        payload = None
        
    def get_screenshot(self, data : str):
        """{"switches":["-q"],"display":True}"""
        print(f'{self.get_screenshot.__name__} sent with {data}')
        path = f'/screenshots/{data}.png'
        method = 'GET'
        payload = None
        return self.__results(method, path, json=payload)
    
    def get_dom(self, data : str):
        """{"switches":[]}"""
        print(f'{self.get_dom.__name__} called on: {data}')
        path = f'/dom/{data}/'
        method='GET'
        payload=None
        return self.__results(method, path, json=payload)
    
    def get_redirect(self, url):
        """{"switches":[]}"""
        print(f'{self.get_redirect.__name__} called on: {url}')
        method = 'GET'
        payload = None
        return self.__results(method, url, json=payload)