# Presented here is a DER-encoded x509 RSA certificate. Find the modulus of the certificate, giving your answer as a decimal.

# command: openssl x509 -inform der -in 2048b-rsa-example-cert.der -text -noout

# output:

# Certificate:
#     Data:
#         Version: 1 (0x0)
#         Serial Number: 3580 (0xdfc)
#         Signature Algorithm: sha1WithRSAEncryption
#         Issuer: C=JP, ST=Tokyo, L=Chuo-ku, O=Frank4DD, OU=WebCert Support, CN=Frank4DD Web CA, emailAddress=support@frank4dd.com
#         Validity
#             Not Before: Aug 22 05:27:41 2012 GMT
#             Not After : Aug 21 05:27:41 2017 GMT
#         Subject: C=JP, ST=Tokyo, O=Frank4DD, CN=www.example.com
#         Subject Public Key Info:
#             Public Key Algorithm: rsaEncryption
#                 Public-Key: (2048 bit)
#                 Modulus:
#                     00:b4:cf:d1:5e:33:29:ec:0b:cf:ae:76:f5:fe:2d:
#                     c8:99:c6:78:79:b9:18:f8:0b:d4:ba:b4:d7:9e:02:
#                     52:06:09:f4:18:93:4c:d4:70:d1:42:a0:29:13:92:
#                     73:50:77:f6:04:89:ac:03:2c:d6:f1:06:ab:ad:6c:
#                     c0:d9:d5:a6:ab:ca:cd:5a:d2:56:26:51:e5:4b:08:
#                     8a:af:cc:19:0f:25:34:90:b0:2a:29:41:0f:55:f1:
#                     6b:93:db:9d:b3:cc:dc:ec:eb:c7:55:18:d7:42:25:
#                     de:49:35:14:32:92:9c:1e:c6:69:e3:3c:fb:f4:9a:
#                     f8:fb:8b:c5:e0:1b:7e:fd:4f:25:ba:3f:e5:96:57:
#                     9a:24:79:49:17:27:d7:89:4b:6a:2e:0d:87:51:d9:
#                     23:3d:06:85:56:f8:58:31:0e:ee:81:99:78:68:cd:
#                     6e:44:7e:c9:da:8c:5a:7b:1c:bf:24:40:29:48:d1:
#                     03:9c:ef:dc:ae:2a:5d:f8:f7:6a:c7:e9:bc:c5:b0:
#                     59:f6:95:fc:16:cb:d8:9c:ed:c3:fc:12:90:93:78:
#                     5a:75:b4:56:83:fa:fc:41:84:f6:64:79:34:35:1c:
#                     ac:7a:85:0e:73:78:72:01:e7:24:89:25:9e:da:7f:
#                     65:bc:af:87:93:19:8c:db:75:15:b6:e0:30:c7:08:
#                     f8:59
#                 Exponent: 65537 (0x10001)
#     Signature Algorithm: sha1WithRSAEncryption
#     Signature Value:
#         40:cb:fe:04:5b:c6:74:c5:73:91:06:90:df:ff:b6:9e:85:73:
#         fe:e0:0a:6f:3a:44:2f:cc:53:73:16:32:3f:79:64:39:e8:78:
#         16:8c:62:49:6a:b2:e6:91:85:00:b7:4f:38:da:03:b9:81:69:
#         2e:18:c9:49:96:84:c2:eb:e3:23:f4:eb:ac:68:4b:57:5a:51:
#         1b:d7:eb:c0:31:6c:86:a0:f6:55:a8:f8:10:d0:42:06:1e:94:
#         a5:e0:68:a7:9f:b6:f3:9c:d0:e1:22:3b:ab:85:3d:a1:27:9b:
#         50:32:62:b8:ec:7a:fa:d6:7d:2b:29:e6:ad:b2:69:4d:28:b4:
#         f8:0a

hex_n = '00:b4:cf:d1:5e:33:29:ec:0b:cf:ae:76:f5:fe:2d:c8:99:c6:78:79:b9:18:f8:0b:d4:ba:b4:d7:9e:02:52:06:09:f4:18:93:4c:d4:70:d1:42:a0:29:13:92:73:50:77:f6:04:89:ac:03:2c:d6:f1:06:ab:ad:6c:c0:d9:d5:a6:ab:ca:cd:5a:d2:56:26:51:e5:4b:08:8a:af:cc:19:0f:25:34:90:b0:2a:29:41:0f:55:f1:6b:93:db:9d:b3:cc:dc:ec:eb:c7:55:18:d7:42:25:de:49:35:14:32:92:9c:1e:c6:69:e3:3c:fb:f4:9a:f8:fb:8b:c5:e0:1b:7e:fd:4f:25:ba:3f:e5:96:57:9a:24:79:49:17:27:d7:89:4b:6a:2e:0d:87:51:d9:23:3d:06:85:56:f8:58:31:0e:ee:81:99:78:68:cd:6e:44:7e:c9:da:8c:5a:7b:1c:bf:24:40:29:48:d1:03:9c:ef:dc:ae:2a:5d:f8:f7:6a:c7:e9:bc:c5:b0:59:f6:95:fc:16:cb:d8:9c:ed:c3:fc:12:90:93:78:5a:75:b4:56:83:fa:fc:41:84:f6:64:79:34:35:1c:ac:7a:85:0e:73:78:72:01:e7:24:89:25:9e:da:7f:65:bc:af:87:93:19:8c:db:75:15:b6:e0:30:c7:08:f8:59'.replace(':', '')
int_n = int(hex_n, 16)
print(int_n)