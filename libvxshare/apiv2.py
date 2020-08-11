"""
VirusShare API v2
=================

Support for version 2 of the VirusShare API.

This API is fully documented here: https://virusshare.com/apiv2_reference

An exception is raised in the case the status code is not 200 (Success) or 204 (Rate limited).

Please add try/except clauses around calls to this library to properly handle errors in requesting data.
This was not implemented within the library to allow greater flexibility in how you would like to handle errors.

"""
from time import sleep
import datetime

import requests


class VirusShare:
    """Class containing methods to support querying the VirusShare API including rate limiting operations."""
    def __init__(self, api_key=None, requests_per_minute=4):
        """Initialize class

        :param requests_per_minute: Integer representing the number of requests per minute allowed by your API
        """
        self.api_key = api_key
        self.uri = "https://virusshare.com/apiv2"
        self.requests_per_minute = requests_per_minute
        self.rate_limit_buffer = 0.01

        self._last_request = None
        self._rate_limit = float(60.0 / requests_per_minute) + self.rate_limit_buffer

    def _sleep(self):
        """Provide rate limiting based on API requests per minute.

        This executes immediately before each request to the API

        :return: None
        """
        if self._last_request is None:
            self._last_request = datetime.datetime.now()
            return

        elapsed_time = (datetime.datetime.now() - self._last_request).total_seconds()
        # If less than the rate limit has passed, sleep for the remainder
        if elapsed_time < self._rate_limit:
            sleep(self._rate_limit - elapsed_time)

    def _request(self, endpoint, hash_value):
        """Execute the API request and return the result.

        Incorporates the rate limiter.

        :param endpoint (str): A valid API endpoint. One of file, quick, download, source

        :return: Response from GET request.
        """
        if not self.api_key:
            raise ValueError("Required API key not provided")
        self._sleep()
        resp = requests.get("{}/{}".format(self.uri, endpoint), params={
            "apikey": self.api_key,
            "hash": hash_value
        })
        # If successful, return the results
        if resp.status_code == 200:
            return resp
        # If rate limited, sleep then try again
        if resp.status_code == 204:
            self._sleep()
            return self._request(endpoint, hash_value)

        # Otherwise raise the HTTP error
        resp.raise_for_status()

    @staticmethod
    def _add_metadata(response_data):
        """Add interpretation of the `response` value.

        0 - Indicates the file is not found
        1 - Indicates the file is found and detected
        2 - Indicated the file is found and benign

        :param response_data: Dictionary containing at least the 'response' key
        :return:
        """
        response_data['_exists'] = True if response_data.get('response', 0) in (1, 2) else False
        response_data['_detected'] = True if response_data.get('response', 0) == 1 else False
        return response_data

    def file_exists(self, hash_value):
        """Quickly confirm whether the file exists in the data set or not.

        This leverages the `/quick` endpoint, and will return a 0 if the file is not found,
        a 1 if the file is found and has a detection, and 2 if the file is found and benign.

        :param hash_value: A string hash value. May be one of md5, sha1, sha224, sha256, sha384, or sha512.
        :return: Dictionary containing response from VirusShare, plus metadata fields about whether the file exists
            or was detected.
        """
        response = self._request('quick', hash_value)
        resp_data = response.json()
        resp_data = self._add_metadata(resp_data)
        return resp_data

    def file_report(self, hash_value):
        """Gather a report about a file in the dataset.

        It is highly recommended to use self.file_exists to confirm the file is found
        within the dataset before requesting a report.

        This leverages the `/file` endpoint, which returns a JSON document with key-value mappings of
        the metadata associated with this entry. An example response is shown in the main documentation
        here: https://virusshare.com/apiv2_reference.

        :param hash_value: A string hash value. May be one of md5, sha1, sha224, sha256, sha384, or sha512.
        :return: Dictionary containing response from VirusShare, plus metadata fields about the request
        """
        response = self._request('file', hash_value)
        resp_data = response.json()
        resp_data = self._add_metadata(resp_data)
        return resp_data

    def file_source(self, hash_value, convert_timestamps=False):
        """Gather information about where the sample was sourced from.

        It is highly recommended to use self.file_exists to confirm the file is found
        within the dataset before requesting a report.

        This leverages the `/source` endpoint, which returns a JSON document with key-value mappings of
        the metadata associated with this entry. The main data point of interest is located in the
        `urllist` field. An example response is shown in the main documentation
        here: https://virusshare.com/apiv2_reference.

        :param hash_value: A string hash value. Must by SHA256
        :param convert_timestamps: Whether or not to convert timestamps to datetime objects. Will add `datetime` field.
        :return: Dictionary containing response from VirusShare, plus metadata fields about the request
        """
        if len(hash_value) != 64:
            raise ValueError("Please provide a SHA256 value")
        response = self._request('source', hash_value)
        resp_data = response.json()
        if convert_timestamps and isinstance(resp_data.get('urllist'), list) and len(resp_data.get('urllist')) > 0:
            new_url_list = []
            for entry in resp_data.get('urllist', []):
                new_url_list.append({
                    "url": entry.get("url"),
                    "timestamp": entry.get("timestamp"),
                    "datetime": datetime.datetime.utcfromtimestamp(entry.get("timestamp"))
                })
            resp_data['urllist'] = new_url_list
        return resp_data

    def file_download(self, hash_value):
        """Download a sample by hash value.

        It is highly recommended to use self.file_exists to confirm the file is found
        within the dataset before requesting a report.

        This leverages the `/download` endpoint, which returns a byte stream containing a password
        protected zip file archive.

        :param hash_value: A string hash value. May be one of md5, sha1, sha224, sha256, sha384, or sha512.
        :return: Byte content of the zip file containing the sample.
        """
        response = self._request('download', hash_value)
        return response.content
