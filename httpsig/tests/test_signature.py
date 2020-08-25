#!/usr/bin/env python
import sys
import os

import unittest

import httpsig.sign as sign
from httpsig.utils import parse_authorization_header


sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

sign.DEFAULT_SIGN_ALGORITHM = "rsa-sha256"


class TestSign(unittest.TestCase):
    test_method = 'POST'
    test_path = '/foo?param=value&pet=dog'
    header_host = 'example.com'
    header_date = 'Thu, 05 Jan 2014 21:31:40 GMT'
    header_content_type = 'application/json'
    header_digest = 'SHA-256=X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE='
    header_content_length = '18'

    def setUp(self):
        self.key_path = os.path.join(
            os.path.dirname(__file__), 'rsa_private.pem')
        with open(self.key_path, 'rb') as f:
            self.key = f.read()

        self.other_key_path = os.path.join(
            os.path.dirname(__file__), 'rsa_private_2.pem')
        with open(self.other_key_path, 'rb') as f:
            self.other_key = f.read()

    def test_default(self):
        hs = sign.HeaderSigner(key_id='Test', secret=self.key)
        unsigned = {
            'Date': self.header_date
        }
        signed = hs.sign(unsigned)
        self.assertIn('Date', signed)
        self.assertEqual(unsigned['Date'], signed['Date'])
        self.assertIn('Authorization', signed)
        auth = parse_authorization_header(signed['authorization'])
        params = auth[1]
        self.assertIn('keyId', params)
        self.assertIn('algorithm', params)
        self.assertIn('signature', params)
        self.assertEqual(params['keyId'], 'Test')
        self.assertEqual(params['algorithm'], 'rsa-sha256')
        self.assertEqual(params['signature'], 'jKyvPcxB4JbmYY4mByyBY7cZfNl4OW9HpFQlG7N4YcJPteKTu4MWCLyk+gIr0wDgqtLWf9NLpMAMimdfsH7FSWGfbMFSrsVTHNTk0rK3usrfFnti1dxsM4jl0kYJCKTGI/UWkqiaxwNiKqGcdlEDrTcUhhsFsOIo8VhddmZTZ8w=')  # noqa: E501

    def test_other_default(self):
        hs = sign.HeaderSigner(key_id='Test', secret=self.other_key)
        unsigned = {
            'Date': self.header_date
        }
        signed = hs.sign(unsigned)
        self.assertIn('Date', signed)
        self.assertEqual(unsigned['Date'], signed['Date'])
        self.assertIn('Authorization', signed)
        auth = parse_authorization_header(signed['authorization'])
        params = auth[1]
        self.assertIn('keyId', params)
        self.assertIn('algorithm', params)
        self.assertIn('signature', params)
        self.assertEqual(params['keyId'], 'Test')
        self.assertEqual(params['algorithm'], 'rsa-sha256')
        self.assertEqual(params['signature'],
                         'GY3Yyuj92xScIb2QbDUWxIW/fg7ZP8rxURltbpouTGxTo+ZRDHO9BbfN6YQeP1Z0VJBEA0dgynuzQs2bVBJavTcoEgvttzznAIj9ypfI6n35Uzeid+9gepa0pfBom6qnoNbblMNsHt7hXBfrpe5EwfEKmpqZgivjJZ53p9gD1NAhlioty/m1MFu1J5wEjpgX466R2PmR10yl22rMcv3mbEPV5ijqLTViDW18DchLyHR+fItzRtor2yLv7QgBSw+gVJu0dVeKeL9kwPxsaurzODgYsFsjZOJvuP9nKPJOdH3PI6eDhpfwjmwhjbSTte3bjkbw0w5tlWuA8m5l1gzyBQ==')

    def test_basic(self):
        hs = sign.HeaderSigner(key_id='Test', secret=self.key, headers=[
            '(request-target)',
            'host',
            'date',
        ])
        unsigned = {
            'Host': self.header_host,
            'Date': self.header_date,
        }
        signed = hs.sign(
            unsigned, method=self.test_method, path=self.test_path)

        self.assertIn('Date', signed)
        self.assertEqual(unsigned['Date'], signed['Date'])
        self.assertIn('Authorization', signed)
        auth = parse_authorization_header(signed['authorization'])
        params = auth[1]
        self.assertIn('keyId', params)
        self.assertIn('algorithm', params)
        self.assertIn('signature', params)
        self.assertEqual(params['keyId'], 'Test')
        self.assertEqual(params['algorithm'], 'rsa-sha256')
        self.assertEqual(
            params['headers'], '(request-target) host date')
        self.assertEqual(params['signature'], 'HUxc9BS3P/kPhSmJo+0pQ4IsCo007vkv6bUm4Qehrx+B1Eo4Mq5/6KylET72ZpMUS80XvjlOPjKzxfeTQj4DiKbAzwJAb4HX3qX6obQTa00/qPDXlMepD2JtTw33yNnm/0xV7fQuvILN/ys+378Ysi082+4xBQFwvhNvSoVsGv4=')  # noqa: E501

    def test_all(self):
        hs = sign.HeaderSigner(key_id='Test', secret=self.key, headers=[
            '(request-target)',
            'host',
            'date',
            'content-type',
            'digest',
            'content-length'
        ])
        unsigned = {
            'Host': self.header_host,
            'Date': self.header_date,
            'Content-Type': self.header_content_type,
            'Digest': self.header_digest,
            'Content-Length': self.header_content_length,
        }
        signed = hs.sign(
            unsigned, method=self.test_method, path=self.test_path)

        self.assertIn('Date', signed)
        self.assertEqual(unsigned['Date'], signed['Date'])
        self.assertIn('Authorization', signed)
        auth = parse_authorization_header(signed['authorization'])
        params = auth[1]
        self.assertIn('keyId', params)
        self.assertIn('algorithm', params)
        self.assertIn('signature', params)
        self.assertEqual(params['keyId'], 'Test')
        self.assertEqual(params['algorithm'], 'rsa-sha256')
        self.assertEqual(
            params['headers'],
            '(request-target) host date content-type digest content-length')
        self.assertEqual(params['signature'], 'Ef7MlxLXoBovhil3AlyjtBwAL9g4TN3tibLj7uuNB3CROat/9KaeQ4hW2NiJ+pZ6HQEOx9vYZAyi+7cmIkmJszJCut5kQLAwuX+Ms/mUFvpKlSo9StS2bMXDBNjOh4Auj774GFj4gwjS+3NhFeoqyr/MuN6HsEnkvn6zdgfE2i0=')  # noqa: E501
