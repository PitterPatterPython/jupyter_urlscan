import requests
class API:
    def __init__(self, key : str, host : str = 'urlscan.io', protocol : str = 'https://', port : int = 443, verify : bool = False, proxies : dict = None, debug : bool = False):
        self.session = requests.Session()
        self.protocol = protocol
        self.host = host
        self.port = port
        self.session.verify = verify
        self.session.proxies = proxies
        self.session.headers = {'Content-Type':'application/json','API-Key':key}
        self.debug = debug

    def __results(self, method, path, json):
        try:
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

    def scan(self, data : str, options : list = []):
        print(f'{self.scan.__name__} called on: {data}')
        #Take data and craft a request path with appropriate data
        path = f'/api/v1/scan/'
        method='POST'
        payload={'url':data}
        
        for opt in self.__parse_options(options):
            if opt[0] in ['specific_ip']:
                payload.update({opt[0]:opt[1]})
            if opt[0] in ['custom_ref']:
                payload.update({'referer':opt[1]})
            if opt[0] in ['custom_ua']:
                payload.update({'user_agent':opt[1]})
            if opt[0] in ['random_ip']:
                payload.update({'country_code':opt[1]})
        
        return self.__results(method, path, json=payload)

    def search(self, data : str):
        print(f'{self.search.__name__} called on: {data}')
        path = f'/api/v1/search/?q={data}'
        method = 'GET'
        payload = None
        #Take data and craft a request path with appropriate data
        return self.__results(method, path, json=payload)

    def result(self, data : str):
        print(f'{self.result.__name__} called on: {data}')
        path = f'/api/v1/result/{data}/'
        method = 'GET'
        payload = None
        return self.__results(method, path, json=payload)
        
    def screenshot(self, data : str):
        print(f'{self.screenshot.__name__} sent with {data}')
        #Take data and craft a request path with appropriate data
        path = f'/screenshots/{data}.png'
        method = 'GET'
        payload = None
        return self.__results(method, path, json=payload)
    
    def dom(self, data : str):
        print(f'{self.dom.__name__} called on: {data}')
        #Take data and craft a request path with appropriate data
        path = f'/dom/{data}/'
        method='GET'
        payload=None
        return self.__results(method, path, json=payload)