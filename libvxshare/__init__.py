"""
Overview
=========

VirusShare.com API wrapper

LibVXShare includes a simple Python interface that wraps the already simple VirusShare API, namely adding support for
automated rate limiting and conversion of types in to Python data types. More helpers coming soon! Open a ticket
on GitHub with any requests.

Official API documentation here: https://virusshare.com/apiv2_reference

This library provides a generic interface for querying and accessing information from VirusShare's API. This can
allow for ease of integration in to existing Python frameworks, scripts, and other utilities. That said, it will
raise an exception for HTTP response codes other than 200 (success) and 204 (rate limiting). Please leverage
try/except around the library to handle exceptions as required by your implementation.

Notes
^^^^^

This implementation will not rate limit across threads or processes, only within the same thread. This is because the
API is limited on requests per minute and does not provide a counter of remaining requests.

"""
__name__ = "libvxshare"
__desc__ = "Unofficial VirusShare API Wrapper"
__version__ = "1.0.0"
__author__ = "Chapin Bryce"
__email__ = 'python@chapinb.com'
__license__ = "MIT"
__date__ = "20200810"
