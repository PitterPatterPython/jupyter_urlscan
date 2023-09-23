from requests.models import Response
from requests.exceptions import JSONDecodeError

class ResponseParser:
    
    def __can_decode(self, response : Response):
        """
        Parameters
        ----------
        response : Response

        Outputs
        -------
        can_decode : bool 
        """
        try:
            response.json()
        except JSONDecodeError as e:
            return False
        return True
    
    def parse_response(self, response : Response):
        """
        Parameters
        ----------
        endpoint : str - 
        response : Response - 

        Outputs
        -------
        status_code : int
        response.ok : bool
        response : dict
        response_text : str
        response_content : bytes
        """
        if self.__can_decode(response):
            return response.status_code, response.ok, response.json(), response.text, response.content
        else:
            return response.status_code, response.ok, None, response.text,response.content