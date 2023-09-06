#!/usr/bin/python

# Base imports for all integrations, only remove these at your own risk!
import json
import sys
import os
import time
import pandas as pd
from collections import OrderedDict
import re
from integration_core import Integration
import datetime
from IPython.core.magic import (Magics, magics_class, line_magic, cell_magic, line_cell_magic)
from IPython.core.display import HTML
from io import StringIO
from requests import Request, Session

from urlscan_core._version import __desc__
from jupyter_integrations_utility.batchquery import df_expand_col
# Your Specific integration imports go here, make sure they are in requirements!
import jupyter_integrations_utility as jiu
#import IPython.display
from IPython.display import display_html, display, Javascript, FileLink, FileLinks, Image
import ipywidgets as widgets

##custom to urlscan integration
import random
from time import strftime, localtime
import jmespath
from io import BytesIO
import base64

@magics_class
class Urlscan(Integration):
    # Static Variables
    # The name of the integration
    name_str = "urlscan"
    instances = {}
    custom_evars = ["urlscan_conn_default", "urlscan_verify_ssl", "urlscan_rate_limit","urlscan_submission_visiblity"]
    # These are the variables in the opts dict that allowed to be set by the user. These are specific to this custom integration and are joined
    # with the base_allowed_set_opts from the integration base

    # These are the variables in the opts dict that allowed to be set by the user. These are specific to this custom integration and are joined
    # with the base_allowed_set_opts from the integration base
    custom_allowed_set_opts = ["urlscan_conn_default", "urlsacn_verify_ssl","url_rate_limit", "urlscan_submission_visiblity"]

    help_text = ""
    help_dict = {}
    myopts = {}
    myopts['urlscan_conn_default'] = ["default", "Default instance to connect with"]
    myopts['urlscan_verify_ssl'] = [True, "Verify integrity of SSL"]
    myopts['urlscan_rate_limit'] = [True, "Limit rates based on URLScan user configuration"]
    myopts['urlscan_submission_visiblity'] = ["public", "Default visiblity for submissions to URLScan."]
    myopts['urlscan_submission_country'] = ["US","The country from which the scan should be performed"]
    myopts['urlscan_submission_referer'] = [None, "Override the HTTP referer for this scan"]
    myopts['urlscan_submission_useragent'] = [None, "Override useragent for this scan"]

    countries = ["de","us","jp","fr","gb","nl","ca","it","es","se","fi","dk","no","is","au","nz","pl","sg","ge","pt","at","ch"]

    """
    Key:Value pairs here for APIs represent the type? 
    """

    base_url = "https://urlscan.io/api/v1"
    other_base_url = "https://urlscan.io"

    apis = {
            "scan": {'url':base_url,'path': "/scan/", 'method':'POST','parsers':[]},
            "result": {
                'url':base_url,
                'path':"/result/",
                'method':'GET',
                ## column_name & column_value as jmespath valid string
                'parsers':[
                    ("page","page"),
                    ("uuid","task.uuid"),
                    ("report_url","task.reportURL"),
                    ("verdicts","verdicts.overall"),
                    ("cookies","data.cookies[*].[domain,name,value]"),
                    ("embedded_links","data.links"),
                    ("rdns","meta.processors.rdns.data[]"),
                    ("certificates","lists.certificates[].[subjectName,issuer,validTo]"),
                    ("tls_stats","stats.tlsStats"),
                    ("protocol_stats","stats.protocolStats"),
                    ("global_strings","data.globals[?type=='string'].[prop]"),
                    ("global_functions","data.globals[?type=='function'].[prop]"),
                    ("global_objects","data.globals[?type=='object'].[prop]"),
                    ("global_booleans","data.globals[?type=='boolean'].[prop]"),
                    ("domain_stats","stats.domainStats"),
                    ("submitter","submitter")
                ]
            },
            "screenshot": {'url':other_base_url, 'path':'/screenshots/','method':'GET'},
            "dom": {'url':other_base_url, 'path':"/dom/", 'method':'GET'},
            "search": {'url':base_url, 'path':"/search/?q=", 'method':'GET'}
            }



    # Class Init function - Obtain a reference to the get_ipython()
    def __init__(self, shell, debug=False, *args, **kwargs):
        super(Urlscan, self).__init__(shell, debug=debug)
        self.debug = debug
        #Add local variables to opts dict
        for k in self.myopts.keys():
            self.opts[k] = self.myopts[k]

        self.load_env(self.custom_evars)
        self.parse_instances()
#######################################



    def retCustomDesc(self):
        return __desc__


    def customHelp(self, curout):
        n = self.name_str
        mn = self.magic_name
        m = "%" + mn
        mq = "%" + m
        table_header = "| Magic | Description |\n"
        table_header += "| -------- | ----- |\n"
        out = curout

        qexamples = []
        qexamples.append(["myinstance", "scan\nhttps://this.supershady.url/", "Run a urlscan query for iris-enrich"])
        qexamples.append(["","result\na353d4c9-2fa1-4b9b-8919-08ac1db9772a","Provide a UUID to retrieve results from URLScan for the submission associated to it."])
        qexamples.append(["","dom\na353d4c9-2fa1-4b9b-8919-08ac1db9772a","Provide a UUID to retrieve results from URLScan for the submission associated to it."])
        out += self.retQueryHelp(qexamples)

        return out

    #This function stops the integration for prompting you for username
    def req_username(self, instance):
        bAuth=False
        return bAuth

    def customAuth(self, instance):
        result = -1
        inst = None
        if instance not in self.instances.keys():
            result = -3
            print("Instance %s not found in instances - Connection Failed" % instance)
        else:
            inst = self.instances[instance]
        if inst is not None:
            if inst['options'].get('useproxy', 0) == 1:
                myproxies = self.get_proxy_str(instance)
            else:
                myproxies = None

            inst['session']=Session()
            inst['session'].proxies=myproxies

            mypass = ""
            if inst['enc_pass'] is not None:
                mypass = self.ret_dec_pass(inst['enc_pass'])
                inst['session'].headers.update({'API-Key':mypass})
            ssl_verify = self.opts['urlscan_verify_ssl'][0]
            if isinstance(ssl_verify, str) and ssl_verify.strip().lower() in ['true', 'false']:
                if ssl_verify.strip().lower() == 'true':
                    ssl_verify = True
                else:
                    ssl_verify = False
            elif isinstance(ssl_verify, int) and ssl_verify in [0, 1]:
                if ssl_verify == 1:
                    ssl_verify = True
                else:
                    ssl_verify = False

            inst['session'].verify=ssl_verify
            result = 0
        return result

    def parse_query(self, query):
        q_items = query.split("\n")
        end_point = q_items[0].strip()
        if len(q_items) > 1:
            end_point_vars = q_items[1].strip()
        elif len(q_items) > 2:
            end_point_vars = list(map(lambda variable : variable.strip(),q_items))
        else:
            end_point_vars = None
        return end_point, end_point_vars


    def validateQuery(self, query, instance):
        bRun = True
        bReRun = False

        if self.instances[instance]['last_query'] == query:
            # If the validation allows rerun, that we are here:
            bReRun = True
        # Example Validation
        # Warn only - Don't change bRun
        # Basically, we print a warning but don't change the bRun variable and the bReRun doesn't matter

        inst = self.instances[instance]
        ep, ep_vars = self.parse_query(query)

        if ep not in self.apis.keys():
            print(f"Endpoint: {ep} not in available APIs: {self.apis.keys()}")
            bRun = False
            if bReRun:
                print("Submitting due to rerun")
                bRun = True
        return bRun

    def _apiDOMDownload(self, response, uuid):
        if self.debug:
            print('_apiDOMDownload')
            print(response)
            print(uuid)
        status = -1
        if os.access('.', os.W_OK):
            f = open(f"dom_{uuid}.txt","wb")
            try:
                f.write(response.content)
            except Exception as e:
                print(f"An error has occured:\n{str(e)}")
                print(status=-2)
            finally:
                f.flush()
                f.close()
                status = 0
        else:
            print("Please check that you are in a writeable directory before making this request.") 
        return status 

    def _apiDisplayScreenshot(self, response):
        status = 0
        if self.debug:
            print('_apiDisplayScreenshot')
            print(f"Lenght of content to write: {str(len(response.content))}")
            print("Response content first 100 characters")
            print(f"Print {response.content[0:100]}")
        b64_img = base64.b64encode(response.content).decode()
        try:
            output = f"""
                <img
                    src="data:image/png;base64,{b64_img}"
                />
            """
            display(HTML(output))
        except Exception as e:
            print(f"An error with PIL occured: {str(e)}")
            status = -1
        return status

    def _apiResultParser(self, scan_result, parsers):
        if self.debug:
            print('_apiResultParser')
            print(type(scan_result))
            print(parsers)
        parsed = {}
        for expression in parsers:
            parsed.update({expression[0]:[jmespath.search(expression[1],scan_result.json())]})
        return parsed

    def customQuery(self, query, instance, reconnect=True):
        
        ep, ep_data = self.parse_query(query)
        ep_api = self.apis.get(ep, None)

        if self.debug:
            print(f"Query: {query}")
            print(f"Endpoint: {ep}")
            print(f"Endpoint Data: {ep_data}")
            print(f"Endpoint API Transform: {ep_api}")
            print("Session headers")
            print(self.instances[instance]['session'].headers)
        mydf = None
        status = ""
        str_err = ""

        if ep == "help":
            self.call_help(ep_data, instance)
            return mydf, "Success - No Results"

        try:
            api_method = self.apis[ep]['method']
            ##
            ## THis section handles options for your POST request, customizable
            ## to URLScan's specifications
            ##
            if api_method=='POST':
                post_data={"url":ep_data.strip(),"visibility":self.opts['urlscan_submission_visiblity'][0]}
                if self.opts['urlscan_submission_country'][0]:
                    post_data.update({"country":self.opts['urlscan_submission_country'][0]})
                else:
                    post_data.update({"country":random.choice(self.countries)})
                if self.opts['urlscan_submission_useragent'][0]:
                    post_data.update({"customagent":self.opts['urlscan_submission_useragent'][0]})
                if self.opts['urlscan_submission_referer'][0]:
                    post_data.update({"referer":self.opts['urlscan_submission_referer'][0]})
            else:
                post_data=None

            ##
            ##Building the request URL
            ##
            if self.apis[ep.lower()]['method']=='POST':
                api_url=f"{self.apis[ep.lower()]['url']}{self.apis[ep.lower()]['path']}"
            elif self.apis[ep.lower()]['method']=='GET':
                api_url=f"{self.apis[ep.lower()]['url']}{self.apis[ep.lower()]['path']}{ep_data}"
                if ep.lower()=='screenshot':
                    api_url=api_url+'.png'
            else:#people shouldn't be using custom methods / delete, head, PUT
                print("UNPOSSPIBLE -- I don't support this method type for this intergration!")
                print(api_method)
            ##
            ## Send the request then send it! 
            ##

            myres = self.instances[instance]['session'].request(self.apis[ep]['method'],api_url,json=post_data, verify=self.opts['urlscan_verify_ssl'][0])

            ##
            # Begin processing the requests response from the webservice
            ##

            mydf = None
            str_err = "Success - No Results"

            if myres.status_code>=200 and myres.status_code<300:
                if '/result/' in myres.url:
                    mydf = pd.DataFrame(self._apiResultParser(myres,self.apis[ep]['parsers']))
                elif '/screenshot/' in myres.url:
                    mydf = pd.DataFrame()
                    self._apiDisplayScreenshot(myres)
                elif '/dom/' in myres.url:
                    self._apiDOMDownload(myres, ep_data)
                    mydf = pd.DataFrame()
                elif '/search/' in myres.url:
                    mydf = pd.DataFrame(myres.json().get('results'))
                    if myres.json().get('has_more'):
                        print("This search has additional results...")
                        print("Perhaps take your search to the web portal?")
                else:
                    mydf = pd.DataFrame.from_records([(k,v) for k,v in myres.json().items()]).T
                str_err = f"Success {str(myres.status_code)}"

            elif myres.status_code>=300 and myres.status_code<400:
                mydf = pd.DataFrame()
                print(f"Response Code:{str(myres.status_code)}")
                str_err = f"Status {str(myres.status_code)}"
                if myres.status_code==301 or myres.status_code==302:
                    redirect_link = myres.headers.get('Location')

                    ## check if we got a rediriect link , follow it
                    if not redirect_link:
                        print("No redirect link given")
                        str_err = f"Error, 'Location' header not found in list of headers: {myres.headers.keys()}"
                        mydf
                    else: 
                        redir_response = self.instances[instance]['session'].get(redirect_link,verify=self.opts['urlscan_verify_ssl'][0])
                        mydf = pd.DataFrame(_apiResponseParse(redir_response.json()['data']))
                        str_err = f"Success after redirect to {redir_response.url} HTTP {str(myres.status_code)}"
                if self.debug:
                    print(myres.text)
                str_err = f"Error, HTTP code {str(myres.status_code)} Error Text\n{myres.text}"
            elif myres.status_code>=400:
                mydf = pd.DataFrame()
                if 'screenshot' in myres.url and myres.status_code==404: 
                    print("You got a 404:")
                    print("#1 Make sure the UUID you entered for the resource is correct.")
                    print("#2 If not #1, Wait .5 - 2 minutes for the service to make your screenshot ready")
                    str_er = "Error, HTTP {str(myres.status_code)} {myres.text}"
                elif myres.status_code==429:
                    print(f"URLScan returned HTTP {str(myres.status_code)}")
                    print("Too Many requests -- The user has sent too many requests")
                    wait_period = 3600
                    if myres.headers.get('Retry-After'):
                        wait_period = myres.headers.get('Retry-After')
                        print(f"Retry after {str(wait_period)} seconds...")
                elif 'result' in myres.url and myres.status_code==404:
                    print("Wait 2-5 minutes and check back, URLScan still processing")
                    str_err = "Standby"
                else:
                    str_err = f"Error HTTP Code {str(myres.status_code)} {myres.json().get('message')}"
            else:
                print(f"URLScan returned  HTTP {str(myres.status_code)}\n")
                print(f"{str(myres.text)}\n")
                str_err = "Error"
                mydf = pd.DataFrame()
            ##
            # Rate limit parsing (specific to URLScan)
            ##
            if 'X-Rate-Limit-Limit' in myres.headers.keys() and float(int(myres.headers.get('X-Rate-Limit-Remaining'))/int(myres.headers.get('X-Rate-Limit-Limit')))<0.11:
                print("!"*22) 
                print("! RATE LIMIT WARNING !")
                print("!"*22) 
                print(f"Rate Limiting:{myres.headers.get('X-Rate-Limit-Remaining')}")
                print(f"You have {myres.headers.get('X-Rate-Limit-Limit')} requests to your limit.")
                print(f"Rate Limit resets on {str(myres.headers.get('X-Rate-Limit-Reset'))}")
                print(f"Rate Limit resets in {str(myres.headers.get('X-Rate-Limit-Reset-After'))} seconds")
                print("If this request was a 'private' submission, you can switch to use 'unlisted' to work around this quota.")

        except Exception as e:
            mydf = pd.DataFrame()
            str_err = str(e)
            print(str_err)

        if str_err.find("Success") >= 0:
            pass
        else:
            status = "Failure - query_error: " + str_err
        return mydf, status


    def parse_help_text(self):

        help_lines = self.help_text.split("\n")
        bmethods = False
        methods_dict = {}
        method = ""
        method_name = ""
        method_text = []
        inmethod = False
        for l in help_lines:
            if l.find(" |  -------------------------") == 0:
                if inmethod:
                    methods_dict[method_name] = {"title": method, "help": method_text}
                    method = ""
                    method_name = ""
                    method_text = []
                    inmethod = False
                bmethods = False
            if bmethods:
                if l.strip() == "|":
                    continue
                f_l = l.replace(" |  ", "")
                if f_l[0] != ' ':
                    inmethod = True
                    if inmethod:
                        if method_name.strip() != "":
                            if method_name == "__init__":
                                method_name = "API"
                            methods_dict[method_name] = {"title": method, "help": method_text}
                            method = ""
                            method_name = ""
                            method_text = []
                    method = f_l
                    method_name = method.split("(")[0]
                else:
                    if inmethod:
                        method_text.append(f_l)
            if l.find("|  Methods defined here:") >= 0:
                bmethods = True
        self.help_dict = methods_dict

    # This is the magic name.
    @line_cell_magic
    def urlscan(self, line, cell=None):
        if cell is None:
            line = line.replace("\r", "")
            line_handled = self.handleLine(line)
            if self.debug:
                print("line: %s" % line)
                print("cell: %s" % cell)
            if not line_handled: # We based on this we can do custom things for integrations. 
                if line.lower() == "testintwin":
                    print("You've found the custom testint winning line magic!")
                else:
                    print("I am sorry, I don't know what you want to do with your line magic, try just %" + self.name_str + " for help options")
        else: # This is run is the cell is not none, thus it's a cell to process  - For us, that means a query
            self.handleCell(cell, line)

##############################
