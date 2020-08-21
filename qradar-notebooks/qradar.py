#
# Copyright (C) 2020 IBM. All Rights Reserved.
#
# See LICENSE file in the root directory
# of this source tree for licensing information.
#

import time
from datetime import datetime

import pandas as pd
import requests
import urllib3

urllib3.disable_warnings()


class AQL:
    proxy_model = """select if username is not null then username else if ASSETUSER(sourceip) is not null then str(ASSETUSER(sourceip)) else str(sourceip) as user,
endtime/3600000 as timeslice,
sum(if eventdirection = 'L2L' then long(eventcount) else 0) as general_events_L2L,
sum(if eventdirection = 'R2L' then long(eventcount) else 0) as general_events_R2L,
sum(if eventdirection = 'L2R' then long(eventcount) else 0) as general_events_L2R,
sum(if eventdirection = 'R2R' then long(eventcount) else 0) as general_events_R2R,
UNIQUECOUNT(qid) as general_unique_qid,
sum(eventcount) as general_sum_eventcount,
count(*) as general_count_rows,
UNIQUECOUNT(logsourceid) as general_unique_logsource,
/* Network addresses */
UNIQUECOUNT(if eventdirection = 'L2L' or eventdirection = 'L2R' then str(sourceip) else '0')-1 as network_unique_local_src_ip,
UNIQUECOUNT(if eventdirection = 'R2L' or eventdirection = 'R2R' then str(sourceip) else '0')-1 as network_unique_remote_src_ip,
UNIQUECOUNT(if eventdirection = 'L2L' or eventdirection = 'R2L' then str(destinationip) else '0')-1 as network_unique_local_dst_ip,
UNIQUECOUNT(if eventdirection = 'L2R' or eventdirection = 'R2R' then str(destinationip) else '0')-1 as network_unique_remote_dst_ip,
UNIQUECOUNT(if eventdirection = 'L2L' or eventdirection = 'L2R' then str(sourceport) else '0')-1 as network_unique_local_src_port,
UNIQUECOUNT(if eventdirection = 'R2L' or eventdirection = 'R2R' then str(sourceport) else '0')-1 as network_unique_remote_src_port,
UNIQUECOUNT(if eventdirection = 'L2L' or eventdirection = 'R2L' then str(destinationport) else '0')-1 as network_unique_local_dst_port,
UNIQUECOUNT(if eventdirection = 'L2R' or eventdirection = 'R2R' then str(destinationport) else '0')-1 as network_unique_remote_dst_port,
UNIQUECOUNT(NETWORKNAME(sourceip)) as network_unique_src_network,
UNIQUECOUNT(NETWORKNAME(destinationip)) as network_unique_dst_network,
UNIQUECOUNT(sourcegeographiclocation) as network_unique_src_country,
UNIQUECOUNT(destinationgeographiclocation) as network_unique_dst_country,
/* Time */
AVG((endtime/60000) % 60) as time_avg_minute_of_hour,
STDEV((endtime/60000) % 60) as time_stdev_minute_of_hour,
MIN((endtime/60000) % 60) as time_first_seen_minute,
MAX((endtime/60000) % 60) as time_last_seen_minute,
(MAX(endtime) - MIN(endtime))/60000 as time_active_minutes,
AVG((endtime/1000) % 60) as time_avg_second_of_minute,
STDEV((endtime/1000) % 60) as time_stdev_second_of_minute,
SUM(if (endtime/60000) % 60 = 0 then long(eventcount) else 0) as time_events_first_minute,
SUM(if (endtime/1000) % 60 = 0 then long(eventcount) else 0) as time_events_first_second,
AVG(endtime-devicetime)/1000 as time_avg_difference_seconds,
MAX(endtime-devicetime)/1000 as time_max_difference_seconds,
/* Proxy Specific */
UNIQUECOUNT(URL) as proxy_unique_URL,
MAX(STRLEN(URL)) as proxy_max_len_URL,
AVG(STRLEN(URL)) as proxy_avg_len_URL,
STDEV(STRLEN(URL)) as proxy_stddev_len_URL,
UNIQUECOUNT(DOMAINNAME(domainid)) as proxy_unique_domain,
UNIQUECOUNT(if DOMAINNAME(domainid) matches '\b((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(\.|$)){4}\b' then DOMAINNAME(domainid) else '0')-1 as proxy_unique_domain_ipformat,
UNIQUECOUNT(if DOMAINNAME(domainid) matches '.*[0-9].*' then DOMAINNAME(domainid) else '0')-1 as proxy_unique_domain_contains_numbers,
MAX(STRLEN(DOMAINNAME(domainid))) as proxy_max_len_domain,
AVG(STRLEN(DOMAINNAME(domainid))) as proxy_avg_len_domain,
STDEV(STRLEN(DOMAINNAME(domainid))) as proxy_stddev_len_domain,
sum(BytesSent)/1000000 as proxy_sum_mb_sent,
sum(BytesReceived)/1000000 as proxy_sum_mb_recieved,
max(BytesSent)/1000000 as proxy_max_mb_sent,
max(BytesReceived)/1000000 as proxy_max_mb_recieved,
avg(BytesSent)/1000000 as proxy_avg_mb_sent,
avg(BytesReceived)/1000000 as proxy_avg_mb_recieved
from events
where URL is not null
group by user, timeslice
having general_count_rows > 1 and general_events_R2R != general_sum_eventcount
order by general_sum_eventcount desc"""


class QRadar(object):
    '''
    The QRadar() class searches QRadar and returns results as a list or Pandas.DataFrame.
    This makes it easier to search QRadar and use results with standard data analysis techniques.
    '''

    def __init__(self,
                 console=None,
                 username=None, password=None,
                 token=None,
                 proxy=None,
                 timeout=10,
                 debug=False,
                 cleanup_results=True):
        '''
        Create the QRadar object to run searches with settings
        Can be used to run multiple searches and return a list of results or DF

        :param console: IP or hostname of console, for example "1.2.3.4" or "qradar.company.com"
        :param username: QRadar username, if using basic auth
        :param password: QRadar password, if using basic auth
        :param token: SEC token (authorized service), can be used instead of basic auth
        :param proxy: proxy if needed. Example: "proxy.us.company.com:8080"
        :param timeout: Timeout to cancel search in minutes
        :param debug: Print logs
        :param cleanup_results: Delete search cursor on QRadar after loading results
        '''

        self.console = console
        self.proxy = {'https': proxy} if proxy else None
        self.timeout = timeout  # timeout for searches in minutes
        self.debug = debug
        self.cleanup_results = cleanup_results

        # Headers
        self.headers = {'Accept': 'application/json'}
        if username and password:
            self.headers['username'] = username
            self.headers['password'] = password
        elif token:
            self.headers['SEC'] = token
        else:
            raise Exception("No credentials supplied")

    def _log(self, message):
        if self.debug:
            print(message)

    def _get_headers(self) -> dict:
        return self.headers.copy()

    def search(self, aql, start_time=None, end_time=None, limit=None, priority=None) -> list:
        '''
        Search QRadar synchronously and return the results as a list
        Can take a long time to run if the search has a large time-frame

        aql: A string containing the QRadar search in AQL form
        start_time: optional, datetime() object for search start time.  Can also be part of search string
        end_time: optional,  datetime() object for search start time.  Can also be part of search string
        limit: optional, limit search to this many result rows.  Can also be part of search string
        priority: optional, priority to run search as: LOW/NORMAL/HIGH.  Can also be part of search string
        :return: search results, list of dicts where dict is each row key/values
        :rtype: list
        '''

        # Build query with optional parameters for time, priority etc
        query = aql
        if limit:
            query += f'\n LIMIT {limit}'
        if start_time:
            start_epoch = start_time.timestamp() * 1000
            end_epoch = int(end_time.timestamp() * 1000 if end_time else datetime.now().timestamp() * 1000)
            query += f'\n START {start_epoch} STOP {end_epoch}'
        if priority and priority in ['LOW', 'NORMAL', 'HIGH']:
            query += f'\n PARAMETERS PRIORITY=\'{priority}\''

        # Start search
        self._log(f'Search query: {query}')
        search_id = self._start_search(query)
        self._log(f'Search ID: {search_id}')

        # Check search status until done
        search_start = time.time()
        timeout = search_start + self.timeout * 60
        while time.time() < timeout:
            status = self._get_status(search_id)
            self._log(f'Search running for {time.time() - search_start:.2f} sec')
            if ('CANCELED' == status) or ('ERROR' == status):
                raise Exception(f'Search did not finish, state is: {status}')
            elif status == 'COMPLETED':
                break
            time.sleep(5)  # wait 5 seconds to check again
        else:
            self._delete(search_id)
            raise Exception(f'Search did not finish within {self.timeout} minutes')

        # Load results list
        results = self._get_results(search_id)

        if self.cleanup_results:
            self._delete(search_id)

        return results

    def search_df(self, aql, start_time=None, end_time=None, limit=None, priority=None) -> pd.DataFrame:
        '''
        aql: A string containing the QRadar search in AQL form
        start_time: optional, datetime() object for search start time.  Can also be part of search string
        end_time: optional,  datetime() object for search start time.  Can also be part of search string
        limit: optional, limit search to this many result rows.  Can also be part of search string
        priority: optional, priority to run search as: LOW/NORMAL/HIGH.  Can also be part of search string
        :return: DataFrame of results
        :rtype: pandas.DataFrame
        '''
        results = self.search(aql, start_time=start_time, end_time=end_time, limit=limit, priority=priority)
        df = pd.DataFrame(results)
        return df

    def _start_search(self, query) -> str:
        # start search
        headers = self._get_headers()
        headers['Content-Type'] = 'application/x-www-form-urlencoded'
        url = f'https://{self.console}/api/ariel/searches'
        resp = requests.post(url, headers=headers, verify=False, data={'query_expression': query}, proxies=self.proxy)
        if resp.status_code != 201:
            self._log(resp.content)
            raise Exception('Cannot start search')
        return resp.json().get('search_id')

    def _get_status(self, search_id) -> str:
        url = f'https://{self.console}/api/ariel/searches/{search_id}'
        resp = requests.get(url, headers=self._get_headers(), verify=False, proxies=self.proxy)
        resp_json = resp.json()
        status = resp_json.get('status')
        self._log(f"Search {status} and {resp_json.get('progress')}% complete")
        return status

    def _get_results(self, search_id, attempt=0) -> list:
        """
        :param search_id:
        :param attempt:
        :return: List of results
        :rtype: list []
        """
        url = f'https://{self.console}/api/ariel/searches/{search_id}/results'
        resp = requests.get(url, headers=self._get_headers(), verify=False, proxies=self.proxy)

        # retry loading results, sometimes fails
        if resp.status_code != 200:
            self._log(resp.content)
            if attempt <= 10:
                time.sleep(5)
                return self._get_results(search_id, attempt=attempt + 1)
            else:
                raise Exception("Could not load search results")

        # loads first (and only) value from json blob to get the data
        # dict can be like {flows: []} or {events: []} or {cursor: []}
        return list(resp.json().values())[0]

    def _delete(self, search_id):
        url = f'https://{self.console}/api/ariel/searches/{search_id}'
        requests.delete(url, headers=self._get_headers(), verify=False, proxies=self.proxy)
        self._log(f'Deleted search cursor {search_id}')
