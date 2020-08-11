import datetime
import unittest
from unittest.mock import patch, Mock

from requests import HTTPError

from libvxshare.apiv2 import VirusShare


class TestAPIv2(unittest.TestCase):
    def setUp(self):
        self.sample_data = {}
        self.requests_get_path = 'libvxshare.apiv2.requests.get'

    def mock_json(self):
        return self.sample_data

    def test_file_exists(self):
        self.sample_data = {"response": 1}
        vxs = VirusShare(api_key='not_an_api_key')
        with patch(self.requests_get_path) as mock_get:
            mock_get.return_value.status_code = 200
            mock_get.return_value.json = self.mock_json
            actual = vxs.file_exists("15d5c88dd0f15eb4426e191b91f2cefe")
        expected = self.sample_data.copy()
        expected.update(dict(_detected=True, _exists=True))
        self.assertDictEqual(expected, actual)

    def test_file_report(self):
        self.sample_data = {
            "filetype": "Zip archive data, at least v2.0 to extract",
            "sha1": "778d0b014c58e8130804c56e9579a97eb77eee79",
            "ssdeep": "393216:Fap6O7g0jcBlDxonTFwEf0Hez/3+xpT4WWFobJ2p1ok:RKg0jcBlDxohzMHQupWFobY",
            "size": 16617145,
            "exif": {
                "FileSize": "16 MB",
                "FileType": "ZIP",
                "FileTypeExtension": "zip",
                "MIMEType": "application/zip",
                "ZipBitFlag": "0x0808",
                "ZipCRC": "0xc8373873",
                "ZipCompressedSize": 76009,
                "ZipCompression": "Deflated",
                "ZipFileName": "META-INF/MANIFEST.MF",
                "ZipModifyDate": "2018:11:05 16:54:10",
                "ZipRequiredVersion": 20,
                "ZipUncompressedSize": 226704
            },
            "sha512": "4c810dab39f0b8298ec383b1632aba77eb5c509e4ff28f7f7c09dd2dff69ada5be2a48afc80bec00064c6a215ce"
                      "52ec2f08a80b342dd7cd18fc6997a0555fd2a",
            "extension": "apk",
            "md5": "15d5c88dd0f15eb4426e191b91f2cefe",
            "added_timestamp": "2020-07-09T17:41:32+00:00",
            "trid": {
                "0": "Android Package (43.2%)",
                "1": "OpenOffice Extension (24.1%)",
                "2": "Java Archive (15.1%)",
                "3": "(.SH3D) Sweet Home 3D design (generic) (11.7%)",
                "4": "ZIP compressed archive (4.4%)"
            },
            "mimetype": "application/zip",
            "sha256": "036eef46db1f85a5c499d363e0f4d3b40051c9ef81ccd3f2173008c0c5dea4f4",
            "sha384": "e252519be8909e2b390fedd83f5b7d1317a19409b6ff329d54db329025636b6c8a9fedf391"
                      "512811268bfc389c40f509",
            "sha224": "d848a0d6f4971c09295b9275fbd4814933b297dbc7768d662035998a",
            "response": 1
        }
        vxs = VirusShare(api_key='not_an_api_key')
        with patch(self.requests_get_path) as mock_get:
            mock_get.return_value.status_code = 200
            mock_get.return_value.json = self.mock_json
            actual = vxs.file_report("15d5c88dd0f15eb4426e191b91f2cefe")
        expected = self.sample_data.copy()
        expected.update(dict(_detected=True, _exists=True))
        self.assertDictEqual(expected, actual)

    def test_file_source_convert(self):
        self.sample_data = {
            "sha256": "a1ac533baaf7de1dae53cf5b465aeca28a7f20bdfc79e5a0a39437dd728c231f",
            "size": 293376,
            "urllist": [
                {
                    "url": "http://totes-leg.it/bin/Data/Managed/Mono.Security.dll",
                    "timestamp": 1591933584
                },
                {
                    "url": "http://totes-leg.it/railmaker.apk:assets/bin/Data/Managed/Mono.Security.dll",
                    "timestamp": 1591976721
                }
            ]
        }
        vxs = VirusShare(api_key="not_an_api_key")
        with patch(self.requests_get_path) as mock_get:
            mock_get.return_value.status_code = 200
            mock_get.return_value.json = self.mock_json
            actual = vxs.file_source(
                hash_value="a1ac533baaf7de1dae53cf5b465aeca28a7f20bdfc79e5a0a39437dd728c231f",
                convert_timestamps=True
            )
        expected = self.sample_data.copy()
        expected.update(
            dict(urllist=[
                    {
                        "url": "http://totes-leg.it/bin/Data/Managed/Mono.Security.dll",
                        "timestamp": 1591933584,
                        "datetime": datetime.datetime(2020, 6, 12, 3, 46, 24)
                    },
                    {
                        "url": "http://totes-leg.it/railmaker.apk:assets/bin/Data/Managed/Mono.Security.dll",
                        "timestamp": 1591976721,
                        "datetime": datetime.datetime(2020, 6, 12, 15, 45, 21)
                    }
                 ]
            )
        )
        self.assertDictEqual(expected, actual)

    def test_file_source(self):
        self.sample_data = {
            "sha256": "a1ac533baaf7de1dae53cf5b465aeca28a7f20bdfc79e5a0a39437dd728c231f",
            "size": 293376,
            "urllist": [
                {
                    "url": "http://totes-leg.it/bin/Data/Managed/Mono.Security.dll",
                    "timestamp": 1591933584
                },
                {
                    "url": "http://totes-leg.it/railmaker.apk:assets/bin/Data/Managed/Mono.Security.dll",
                    "timestamp": 1591976721
                }
            ]
        }
        vxs = VirusShare(api_key="not_an_api_key")
        with patch(self.requests_get_path) as mock_get:
            mock_get.return_value.status_code = 200
            mock_get.return_value.json = self.mock_json
            actual = vxs.file_source(
                hash_value="a1ac533baaf7de1dae53cf5b465aeca28a7f20bdfc79e5a0a39437dd728c231f",
                convert_timestamps=False
            )
        expected = self.sample_data.copy()
        self.assertDictEqual(expected, actual)

    def test_source_md5(self):
        vxs = VirusShare()
        self.assertRaises(ValueError, vxs.file_source, "2c599b6155feb202941edf9bbf2d580d")

    def test_no_api_key(self):
        vxs = VirusShare()
        self.assertRaises(ValueError, vxs.file_exists, "2c599b6155feb202941edf9bbf2d580d")

    def test_raise_500(self):
        vxs = VirusShare(api_key="not_an_api_key")
        self.assertRaises(HTTPError, vxs.file_exists, "2c599b6155feb202941edf9bbf2d580d")

    def test_file_download(self):
        self.sample_data = b'PK\x03\x04\x14\x00\t\x00\x08'
        vxs = VirusShare(api_key='not_an_api_key')
        with patch(self.requests_get_path) as mock_get:
            mock_get.return_value.status_code = 200
            mock_get.return_value.content = self.sample_data
            actual = vxs.file_download("2c599b6155feb202941edf9bbf2d580d")
        expected = self.sample_data
        self.assertEqual(expected, actual)

    def test_rate_limit(self):
        vxs = VirusShare(api_key='not_an_api_key', requests_per_minute=30)
        with patch(self.requests_get_path) as mock_get:
            mock_get.side_effect = [
                Mock(status_code=204),
                Mock(status_code=200, content=self.sample_data)
            ]
            start = datetime.datetime.now()
            actual = vxs.file_download("2c599b6155feb202941edf9bbf2d580d")
        expected = self.sample_data
        self.assertGreaterEqual((datetime.datetime.now() - start).total_seconds(), 2)
        self.assertEqual(expected, actual)


if __name__ == '__main__':
    unittest.main()
