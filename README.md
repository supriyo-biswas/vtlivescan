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
sudo apt install notify-send
```

* Create `~/.vtlivescan/config.json` and add in your VirusTotal API key like so.

```js
{
	"vt_api_key": "<YOUR VIRUSTOTAL API KEY GOES HERE>",
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
