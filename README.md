## Validate Certificate Pinning

Work in progress, at the moment:

- Allow to changing the URL
- Allow to selecting a public key with files in Bundle
- Validate the public key in the selected file
- Validate certificate pinning for:
	- Alamofire default pin
	- Alamofire with custom policy manager
	- NSURLSession challenge
	- Alamofire + NSURLSession
- Retrieve and save in Bundle the public key from the server

### Todos

- Helper to convert certificate files in Bundle into array bytes 

Based on the example: [https://infinum.co/the-capsized-eight/266](https://infinum.co/the-capsized-eight/266)


### Tested method to retrieve manually the public key.

- Export Firefox, working
- Export Safari, not tested
- Openssl, Not working

	```openssl s_client -showcerts -connect httpbin.org:443  -servername httpbin.org < /dev/null | openssl x509 -outform DER > httpbinorg.cer```
