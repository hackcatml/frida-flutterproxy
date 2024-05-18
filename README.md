# frida-flutterproxy
A Frida script for intercepting traffic on Android Flutter applications (aarch64 only)<br>
Tested on a few android flutter apps (e.g., naver Knowledge iN, 삼쩜삼, BMW, Nubank,  Universal Studios hollywood, Demaecan)

# Usage
```
1. Set up burp invisible proxy on the host machine<br>
```
![image](https://github.com/hackcatml/frida-flutterproxy/assets/75507443/26692c67-4273-4e1b-814e-3af7c445caa3)

```
2. Specifiy burp ip and port on the script<br>
At the very end of the script.js, specifiy BURP_PROXY_IP and BURP_PROXY_PORT
```
![image](https://github.com/hackcatml/frida-flutterproxy/assets/75507443/bc17b35b-a644-4b53-9dc7-8b76984585d2)

```
3. Attach
frida -Uf <package name> -l script.js
```
![Screen Recording 2024-05-18 at 9 51 25 PM](https://github.com/hackcatml/frida-flutterproxy/assets/75507443/16f82ac8-2431-41b4-92c3-be2af0302f1f)


# Credits
[reflutter](https://github.com/Impact-I/reFlutter)<br>
[NVISO blog post](https://blog.nviso.eu/2020/05/20/intercepting-flutter-traffic-on-android-x64/)
