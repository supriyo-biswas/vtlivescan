# vtlivescan

A VirusTotal-powered Python daemon that watches files in a directory for malware.

For privacy reasons and to save bandwidth, the files themselves are never uploaded. Instead, the hashes are checked.

# Installation

* Clone and download this repository:

```bash
git clone https://github.com/supriyo-biswas/vtlivescan
```

* Install the requests and the inotify library:

```bash
pip3 install git+https://github.com/supriyo-biswas/PyInotify@patch-1 requests
```

* Install notify-send. On Ubuntu/Debian, you need to run:

```bash
apt install notify-send
```

* Create `/.vtlivescan/config.json` and add in the Virustotal API key and the paths to monitor. VirusTotal API keys are available for free with an account on virustotal.com (though it has a rate limit of 4 requests/second). Do not use comments in the file; JSON does not support them.

```js
{
	// Your VirusTotal API key.
	"vt_api_key": "...",
	// Optional, defaults to ~/Downloads.
	// It's preferable not to use directories with many (nested) subdirectories.
	"paths": [
		"~/Documents",
		"/media/sdb1/Downloads"
	],
	// Optional, has sensible defaults
	"extensions": [
		"exe", "doc", "pdf"
	]
}
```

* Configure your desktop environment to run the application when it starts up. For example, you can do this through "Session and Startup" on XFCE.

# Screenshot

![](https://github.com/supriyo-biswas/vtlivescan/raw/master/misc/screenshot.png)

# License

See [LICENSE.md]
