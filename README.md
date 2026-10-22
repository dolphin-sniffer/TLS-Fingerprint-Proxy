# TLS

By using this script as a local proxy (http://localhost:9000), you can send requests to servers protected by Cloudflare while avoiding being blocked due to fingerprinting.
But what it doesn't do is pass its challenges like the turnstile one.

# How do I use it?

**STRUCTURE:**

For the proxy, you will need to define one in your code, and for the ID, you will need to generate a numeric value.

import random
ID = random.randint(1111111111, 9999999999)
print(ID)

Then, in the URL field, you should enter http://localhost:9000/, and in the headers, enter the following:

x-tp-url: https://ejemplo.com
x-tp-session: <ID>
x-tp-proxie: <PROXY>

You can also use these, which are **optional**.
And these would be the main ones because it also has other names but they are for the same thing.
**1 -**
In this case, you'd have to use the one you have if you want it to be used as a backup in case the others can't connect or can't attend for some reason.
But remember to use a format that's supported, which is almost all of them.
http://user:pass@host:port
user:pass@host:port
user:pass:host:port
host:port:user:pass
x-tp-proxy-fallback: ...
**2 -**
There's also this option, which is enabled by default.
What this does is ensure that if you use multiple proxies simultaneously, it uses only one for a session and its requests to prevent different proxies from being used in the same session, as that could cause problems.
x-tp-sticky-session: true/false
**3 -**
There's also this option, which is enabled by default.
This allows you to track autoredirects, up to fifteen if they occur.
This displays the final URL in the headers, in case you want to review it. However, if you don't want to because it modifies the response, you can disable it.
x-tp-redirects: true/false
**4 -**
There's also this option, which is enabled by default.
To ensure the request retains your user agent, but if you don't want that, you can disable it to use other alternatives that are incorporated into the code.
x-tp-useragent: true/false
**5 -**
Forces a specific TLS fingerprint. If omitted, the proxy defaults to "auto".
(deducing the impersonate from the User-Agent).
x-tp-profile: 
Supported values:
- auto, random, randombrowser, randommobile
- specific profiles: chrome131, chrome124, firefox133, safari180, edge101, ...

# ❗DISCLAIMER

This program was developed solely for educational and learning purposes to conduct authorized testing. As the creator, I do not condone, support, or encourage any malicious or illegal use of this software. The user assumes all responsibility and risk for their actions. The author shall not be held liable for any damages or consequences resulting from the misuse of this tool.

# 🎁 DONATIONS
USDT (BEP20): **0xce76Df18Fb390e0C649c41aa48ae39F84BB8556d**

BTC: **bc1qy9qn3hxye4qr39cr322ggspp5qdma0mj6246xd**

LTC: **ltc1quq3vhqrl5qeap0zg743rght9pa4wzdqdrvrran**
